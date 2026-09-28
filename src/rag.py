"""
rag.py
Retrieval-Augmented Generation over TRACE threat briefs.

Retrieval modes (auto-selected):
  1. Semantic  – sentence-transformers (offline) or watsonx embeddings (if credentials set)
  2. TF-IDF    – offline fallback, always available

Usage:
  python rag.py --build            # index all briefs in briefs/
  python rag.py --query "What escalation steps apply to incitement?"
  python rag.py --eval             # run 10-question retrieval test set
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

log = logging.getLogger("rag")

# ---------------------------------------------------------------------------
# Corpus paths
# ---------------------------------------------------------------------------

BRIEFS_DIR = Path("briefs")
INDEX_PATH = Path("briefs/index.json")

# ---------------------------------------------------------------------------
# Text normalisation
# ---------------------------------------------------------------------------

_STOP = {
    "a", "an", "the", "and", "or", "of", "in", "to", "is", "are", "was",
    "for", "this", "that", "with", "on", "at", "by", "from", "be", "it",
    "as", "not", "no", "its", "all", "any", "can", "will",
}


def _tokenise(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [t for t in tokens if t not in _STOP and len(t) > 1]


# ---------------------------------------------------------------------------
# TF-IDF index
# ---------------------------------------------------------------------------

class TFIDFIndex:
    """Minimal TF-IDF index over brief documents."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []          # {id, text, meta}
        self.tf: list[dict[str, float]] = []          # per-doc term frequencies
        self.df: dict[str, int] = defaultdict(int)    # document frequency
        self.idf: dict[str, float] = {}

    def add(self, doc_id: str, text: str, meta: dict[str, Any] | None = None) -> None:
        tokens = _tokenise(text)
        counts: dict[str, int] = defaultdict(int)
        for t in tokens:
            counts[t] += 1
        n = max(len(tokens), 1)
        tf = {t: c / n for t, c in counts.items()}
        for t in tf:
            self.df[t] += 1
        self.docs.append({"id": doc_id, "text": text, "meta": meta or {}})
        self.tf.append(tf)

    def build(self) -> None:
        """Compute IDF weights."""
        N = len(self.docs)
        self.idf = {
            t: math.log((N + 1) / (df + 1)) + 1.0
            for t, df in self.df.items()
        }

    def _vec(self, tf: dict[str, float]) -> dict[str, float]:
        return {t: tf[t] * self.idf.get(t, 1.0) for t in tf}

    def _cosine(self, q: dict[str, float], d: dict[str, float]) -> float:
        keys = set(q) & set(d)
        dot = sum(q[k] * d[k] for k in keys)
        nq = math.sqrt(sum(v * v for v in q.values()))
        nd = math.sqrt(sum(v * v for v in d.values()))
        return dot / (nq * nd) if nq * nd > 0 else 0.0

    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        tokens = _tokenise(query)
        counts: dict[str, int] = defaultdict(int)
        for t in tokens:
            counts[t] += 1
        n = max(len(tokens), 1)
        q_tf = {t: c / n for t, c in counts.items()}
        q_vec = self._vec(q_tf)

        scores = []
        for i, (doc, tf) in enumerate(zip(self.docs, self.tf)):
            d_vec = self._vec(tf)
            score = self._cosine(q_vec, d_vec)
            scores.append((score, i))

        scores.sort(reverse=True)
        return [
            {"score": round(s, 4), **self.docs[i]}
            for s, i in scores[:top_k]
            if s > 0
        ]

    def to_dict(self) -> dict[str, Any]:
        return {"docs": self.docs, "tf": self.tf, "df": dict(self.df), "idf": self.idf}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TFIDFIndex":
        idx = cls()
        idx.docs = data["docs"]
        idx.tf = data["tf"]
        idx.df = defaultdict(int, data["df"])
        idx.idf = data["idf"]
        return idx


# ---------------------------------------------------------------------------
# Optional: sentence-transformers semantic index
# ---------------------------------------------------------------------------

class SemanticIndex:
    """
    Sentence-transformers based dense retrieval.
    Falls back gracefully if the library is not installed.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self.model: Any = None
        self.embeddings: list[Any] = []
        self.docs: list[dict[str, Any]] = []
        self._load_model()

    def _load_model(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self.model = SentenceTransformer(self.model_name)
            log.info("Loaded sentence-transformers model: %s", self.model_name)
        except ImportError:
            log.warning("sentence-transformers not installed; semantic index unavailable")
            self.model = None

    @property
    def available(self) -> bool:
        return self.model is not None

    def add(self, doc_id: str, text: str, meta: dict[str, Any] | None = None) -> None:
        self.docs.append({"id": doc_id, "text": text, "meta": meta or {}})

    def build(self) -> None:
        if not self.model:
            return
        import numpy as np  # type: ignore
        texts = [d["text"] for d in self.docs]
        self.embeddings = self.model.encode(texts, normalize_embeddings=True)

    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        if not self.model or len(self.embeddings) == 0:
            return []
        import numpy as np  # type: ignore
        q_emb = self.model.encode([query], normalize_embeddings=True)[0]
        scores = [float(np.dot(q_emb, e)) for e in self.embeddings]
        ranked = sorted(enumerate(scores), key=lambda x: -x[1])
        return [
            {"score": round(scores[i], 4), **self.docs[i]}
            for i, _ in ranked[:top_k]
            if scores[i] > 0
        ]


# ---------------------------------------------------------------------------
# Optional: watsonx embeddings
# ---------------------------------------------------------------------------

def _watsonx_embed(texts: list[str]) -> list[list[float]] | None:
    """
    Embed texts via watsonx.ai if credentials are set.
    Returns None if unavailable.

    NOTE: Endpoint/model verified against IBM Cloud docs as of 2024.
    Model used: ibm/slate-125m-english-rtrvr (retrieval-optimised).
    Untested against live API in this environment.
    """
    api_key = os.getenv("WATSONX_API_KEY")
    project_id = os.getenv("WATSONX_PROJECT_ID")
    if not api_key or not project_id:
        return None
    try:
        import requests  # type: ignore

        region = os.getenv("WATSONX_REGION", "us-south")
        model_id = os.getenv("WATSONX_EMBED_MODEL", "ibm/slate-125m-english-rtrvr")

        iam_resp = requests.post(
            "https://iam.cloud.ibm.com/identity/token",
            data={"apikey": api_key, "grant_type": "urn:ibm:params:oauth:grant-type:apikey"},
            timeout=10,
        )
        iam_resp.raise_for_status()
        token = iam_resp.json()["access_token"]

        resp = requests.post(
            f"https://{region}.ml.cloud.ibm.com/ml/v1/text/embeddings?version=2023-10-25",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"model_id": model_id, "inputs": texts, "project_id": project_id},
            timeout=30,
        )
        resp.raise_for_status()
        results = resp.json()["results"]
        return [r["embedding"] for r in results]
    except Exception as exc:
        log.warning("watsonx embed failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# RAG manager
# ---------------------------------------------------------------------------

class RAGIndex:
    """
    Unified RAG interface. Uses semantic retrieval when available, else TF-IDF.
    """

    def __init__(self) -> None:
        self.tfidf = TFIDFIndex()
        self.semantic = SemanticIndex()
        self._built = False

    def add_brief(self, alert: dict[str, Any]) -> None:
        """Index a single alert brief."""
        brief_id = alert.get("brief_id", "unknown")
        text_parts = [
            f"Cluster: {alert.get('cluster', '')}",
            f"Level: {alert.get('level', '')}",
            f"ThreatType: {alert.get('threat_type', '')}",
            f"Harm: {alert.get('harm_score', 0)}",
            f"Coord: {alert.get('coordination_score', 0)}",
            "Phrases: " + " | ".join(alert.get("matched_phrases", [])),
            "BNS: " + " | ".join(alert.get("bns_provisions", [])),
            "Escalation: " + " | ".join(alert.get("escalation_steps", [])),
        ]
        text = "\n".join(text_parts)
        meta = {
            "brief_id": brief_id,
            "level": alert.get("level", ""),
            "threat_type": alert.get("threat_type", ""),
            "cluster": alert.get("cluster", ""),
        }
        self.tfidf.add(brief_id, text, meta)
        self.semantic.add(brief_id, text, meta)

    def build(self) -> None:
        self.tfidf.build()
        self.semantic.build()
        self._built = True

    def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Search briefs; prefer semantic results if available."""
        if self.semantic.available and self._built:
            results = self.semantic.search(query, top_k)
            if results:
                for r in results:
                    r["retrieval_mode"] = "semantic"
                return results
        results = self.tfidf.search(query, top_k)
        for r in results:
            r["retrieval_mode"] = "tfidf"
        return results

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.tfidf.to_dict(), fh, ensure_ascii=False, indent=2)
        log.info("TF-IDF index saved to %s", path)

    def load(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.tfidf = TFIDFIndex.from_dict(data)
        self._built = True

    def answer_with_watsonx(self, query: str, context_docs: list[dict[str, Any]]) -> str:
        """
        Generate an answer using watsonx.ai if credentials set.
        Returns empty string if unavailable (UI should show retrieved docs only).

        NOTE: Untested against live watsonx API in this environment.
        """
        api_key = os.getenv("WATSONX_API_KEY")
        project_id = os.getenv("WATSONX_PROJECT_ID")
        if not api_key or not project_id:
            return ""
        try:
            import requests  # type: ignore

            region = os.getenv("WATSONX_REGION", "us-south")
            model_id = os.getenv("WATSONX_MODEL", "ibm/granite-13b-instruct-v2")

            context = "\n\n".join(d.get("text", "") for d in context_docs[:2])
            prompt = (
                "You are a law-enforcement threat analyst. Using the context below, "
                "answer the question concisely and factually.\n\n"
                f"Context:\n{context[:1500]}\n\nQuestion: {query}\nAnswer:"
            )

            iam_resp = requests.post(
                "https://iam.cloud.ibm.com/identity/token",
                data={"apikey": api_key, "grant_type": "urn:ibm:params:oauth:grant-type:apikey"},
                timeout=10,
            )
            iam_resp.raise_for_status()
            token = iam_resp.json()["access_token"]

            wx_resp = requests.post(
                f"https://{region}.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={
                    "model_id": model_id,
                    "input": prompt,
                    "parameters": {"max_new_tokens": 256, "temperature": 0},
                    "project_id": project_id,
                },
                timeout=20,
            )
            wx_resp.raise_for_status()
            return wx_resp.json()["results"][0]["generated_text"].strip()
        except Exception as exc:
            log.warning("watsonx answer failed: %s", exc)
            return ""


# ---------------------------------------------------------------------------
# 10-question retrieval test set
# ---------------------------------------------------------------------------

RETRIEVAL_TEST_SET = [
    {"question": "What escalation steps apply to HIGH incitement alerts?",
     "expected_cluster_contains": "chowkalert"},
    {"question": "Which BNS provisions cover targeted harassment?",
     "expected_cluster_contains": "silenceher"},
    {"question": "What are the signs of organised misinformation in VaccineLie?",
     "expected_cluster_contains": "vaccinelie"},
    {"question": "How is coordination scored for bot activity?",
     "expected_cluster_contains": "botsunite"},
    {"question": "Why is MarketSquareNews rated LOW?",
     "expected_cluster_contains": "marketsquarenews"},
    {"question": "What to do for a lone high-harm post with no coordination?",
     "expected_cluster_contains": "no_hashtag"},
    {"question": "What Hinglish phrases indicate incitement?",
     "expected_cluster_contains": "sazishhai"},
    {"question": "Which IPC legacy sections map to criminal conspiracy?",
     "expected_cluster_contains": None},   # any result acceptable
    {"question": "What is the burst ratio signal?",
     "expected_cluster_contains": None},
    {"question": "How are evidence hashes chained in TRACE?",
     "expected_cluster_contains": None},
]


def run_retrieval_eval(index: RAGIndex) -> None:
    """Evaluate 10-question retrieval test set and print hit rate."""
    hits = 0
    print("\nRetrieval evaluation (10 questions):")
    print(f"{'Q#':<4} {'Hit':>4}  Question")
    print("-" * 70)
    for i, item in enumerate(RETRIEVAL_TEST_SET, 1):
        results = index.search(item["question"], top_k=3)
        expected = item["expected_cluster_contains"]
        if expected is None:
            hit = len(results) > 0
        else:
            hit = any(
                expected in (r.get("meta", {}).get("cluster", "") or r.get("id", "")).lower()
                for r in results
            )
        hits += int(hit)
        mark = "✓" if hit else "✗"
        print(f"  Q{i:<3} {mark:>4}  {item['question'][:60]}")
    print(f"\nHit rate: {hits}/{len(RETRIEVAL_TEST_SET)} = {hits/len(RETRIEVAL_TEST_SET):.0%}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_index_from_analyze() -> RAGIndex:
    """Build index by running the demo analysis."""
    import sys
    sys.path.insert(0, ".")
    from trace_engine import analyze, _demo_posts  # type: ignore

    posts = _demo_posts()
    result = analyze(posts)
    idx = RAGIndex()
    for alert in result["alerts"]:
        idx.add_brief(alert)
    idx.build()
    return idx


def _cli() -> None:
    parser = argparse.ArgumentParser(description="TRACE RAG interface")
    parser.add_argument("--build", action="store_true", help="Build index from demo briefs")
    parser.add_argument("--query", type=str, help="Query the index")
    parser.add_argument("--eval", action="store_true", help="Run 10-question retrieval evaluation")
    args = parser.parse_args()

    if args.build or args.eval or args.query:
        idx = _build_index_from_analyze()
        if args.build:
            idx.save(INDEX_PATH)
            print(f"Index saved to {INDEX_PATH}")
        if args.query:
            results = idx.search(args.query)
            print(json.dumps(results, indent=2, ensure_ascii=False))
        if args.eval:
            run_retrieval_eval(idx)
    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
