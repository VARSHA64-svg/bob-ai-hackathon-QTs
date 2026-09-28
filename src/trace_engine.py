"""
TRACE – Threat Reconnaissance and Coordination Evidence engine
FastAPI service: /health, /analyze, /demo
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from itertools import combinations
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("trace")

# ---------------------------------------------------------------------------
# Lexicon
# ---------------------------------------------------------------------------

HARM_PHRASES: dict[str, float] = {
    # English – incitement
    "kill them": 1.0,
    "burn them": 0.9,
    "burn their": 0.9,
    "attack them": 0.9,
    "attack the": 0.7,
    "destroy their": 0.8,
    "wipe out": 0.85,
    "blood will flow": 1.0,
    "take up arms": 1.0,
    "rise and fight": 0.9,
    "take revenge": 0.8,
    "no mercy": 0.75,
    "traitors must die": 1.0,
    "hang them": 0.9,
    "lynch mob": 1.0,
    "mob justice": 0.8,
    "finish them": 0.85,
    "eliminate them": 0.85,
    "die traitor": 1.0,
    "cleanse": 0.7,
    "purge": 0.75,
    "take them down": 0.45,
    "shut them down": 0.42,
    "bring them down": 0.43,
    "resist the regime": 0.45,
    "topple the system": 0.48,
    # English – harassment
    "rape threat": 1.0,
    "doxx": 0.85,
    "dox her": 0.85,
    "stalking": 0.7,
    "bomb threat": 1.0,
    "your address is": 0.9,
    "find you": 0.75,
    "coming for you": 0.8,
    "watch your back": 0.75,
    "you will regret": 0.7,
    "harass": 0.7,
    # English – misinfo
    "fake election": 0.7,
    "stolen votes": 0.75,
    "government is hiding": 0.65,
    "deep state": 0.6,
    "crisis actor": 0.75,
    "false flag": 0.7,
    "fabricated evidence": 0.75,
    "rigged election": 0.75,
    "they are poisoning": 0.8,
    "microchip": 0.65,
    "poison the water": 0.8,
    "media lies": 0.6,
    "mainstream media lying": 0.65,
    "plandemic": 0.7,
    "scamdemic": 0.7,
    # Hinglish / romanised Hindi – incitement
    "maar do": 1.0,          # kill them
    "jala do": 0.95,         # burn them
    "jalao": 0.9,            # burn (imperative)
    "danga karo": 0.95,      # do riot
    "danga": 0.75,           # riot
    "badla lo": 0.85,        # take revenge
    "kaat do": 0.95,         # cut/kill
    "khatam karo": 0.9,      # finish/eliminate
    "tod do": 0.75,          # break/destroy
    "bhago mat": 0.6,        # don't flee (rally to fight)
    "ladai karo": 0.8,       # go fight
    "sangharsh": 0.65,       # struggle/conflict
    "jihad": 0.85,
    "kafir ko": 0.9,         # to the infidel
    "nikalo unhe": 0.85,     # drive them out
    "ghar jalao": 0.95,      # burn homes
    "desh chhodo": 0.7,      # leave the country
    "inko bhagao": 0.8,      # chase them away
    "inhe rokna hoga": 0.65, # we must stop them
    "gaddaron ko": 0.9,      # to the traitors
    "maut": 0.8,             # death (in threatening context)
    "khoon bahega": 1.0,     # blood will flow
    "khoon ka badla": 1.0,   # avenge blood
    "laal kar do": 0.85,     # colour red (bloodshed)
    "inke ghar jalao": 0.95,
    # Hinglish – harassment
    "teri maa ki": 0.85,     # abusive maternal slur
    "gali do": 0.7,          # abuse/insult
    "teri behen": 0.85,
    "dhoka diya": 0.65,      # betrayed
    # Hinglish – misinfo
    "ye sab jhooth hai": 0.65,   # it's all a lie
    "sarkar chhupa rahi": 0.7,   # government is hiding
    "media bikau hai": 0.7,      # media is sold/corrupt
    "fake khabar": 0.65,         # fake news
    "andar ki baat": 0.6,        # inside information (rumour)
    "sazish hai": 0.75,          # there is a conspiracy
    "natak kar rahe": 0.65,      # they are acting / false flag
    "danga failana": 0.85,       # spreading riots
}

REPORTING_PHRASES: list[tuple[str, float]] = [
    # Phrases that indicate reporting / condemning (reduce harm)
    ("police say", -0.35),
    ("police said", -0.35),
    ("police report", -0.35),
    ("according to police", -0.4),
    ("authorities say", -0.35),
    ("officials say", -0.35),
    ("reported that", -0.3),
    ("media reported", -0.3),
    ("news reports", -0.3),
    ("breaking news", -0.25),
    ("we condemn", -0.5),
    ("i condemn", -0.5),
    ("strongly condemn", -0.55),
    ("condemnable", -0.45),
    ("denounce", -0.4),
    ("denouncing", -0.4),
    ("call for peace", -0.5),
    ("pray for peace", -0.45),
    ("appeal for calm", -0.5),
    ("seeking justice through", -0.3),
    ("peacefully protest", -0.35),
    ("rumours of", -0.35),
    ("rumor of", -0.35),
    ("unverified reports", -0.4),
    ("alleged", -0.25),
    ("allegedly", -0.25),
    ("quoted as saying", -0.3),
    ("quoting", -0.25),
    ("do not spread", -0.4),
    ("misinformation is spreading", -0.4),
    ("fact check", -0.35),
    ("debunked", -0.45),
    ("this is false", -0.45),
    ("was satirical", -0.4),
    ("satire", -0.3),
    ("not true", -0.3),
]

# ---------------------------------------------------------------------------
# BNS / IPC mapping (static, curated)
# ---------------------------------------------------------------------------

BNS_TABLE: dict[str, dict[str, Any]] = {
    "incitement": {
        "bns_sections": ["BNS §196 (Promoting enmity)", "BNS §197 (Imputations to national integration)",
                         "BNS §351 (Criminal intimidation)"],
        "ipc_legacy": ["IPC §153A", "IPC §153B", "IPC §503"],
        "description": "Promoting enmity between groups or inciting violence",
    },
    "targeted_harassment": {
        "bns_sections": ["BNS §351 (Criminal intimidation)", "BNS §79 (Stalking)",
                         "BNS §308 (Extortion)"],
        "ipc_legacy": ["IPC §503", "IPC §354D", "IPC §383"],
        "description": "Targeted threats, intimidation or stalking of individuals",
    },
    "organized_misinformation": {
        "bns_sections": ["BNS §353 (Statements conducing to public mischief)",
                         "BNS §197 (Imputations to national integration)"],
        "ipc_legacy": ["IPC §505", "IPC §153B"],
        "description": "Coordinated spread of false information to incite or mislead",
    },
    "coordinated_inauthentic": {
        "bns_sections": ["BNS §61 (Criminal conspiracy)", "BNS §353 (Statements conducing to public mischief)"],
        "ipc_legacy": ["IPC §120B", "IPC §505"],
        "description": "Coordinated inauthentic behaviour without specific threat type",
    },
}

# ---------------------------------------------------------------------------
# Union-Find for hashtag clustering
# ---------------------------------------------------------------------------

class UnionFind:
    """Weighted quick-union with path compression."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


# ---------------------------------------------------------------------------
# Evidence hash chain
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_evidence_chain(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a SHA-256 chained evidence ledger."""
    chain: list[dict[str, Any]] = []
    prev_hash = "0" * 64
    for item in items:
        content = json.dumps(item, sort_keys=True, ensure_ascii=False)
        current_hash = _sha256(prev_hash + content)
        chain.append({
            "id": item.get("id", str(uuid.uuid4())),
            "content_hash": _sha256(content),
            "chain_hash": current_hash,
            "prev_hash": prev_hash,
            "timestamp": item.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })
        prev_hash = current_hash
    return chain


def verify_chain(chain: list[dict[str, Any]], items: list[dict[str, Any]]) -> bool:
    """Verify integrity of a hash chain against original items."""
    if len(chain) != len(items):
        return False
    prev_hash = "0" * 64
    for link, item in zip(chain, items):
        content = json.dumps(item, sort_keys=True, ensure_ascii=False)
        expected_content_hash = _sha256(content)
        expected_chain_hash = _sha256(prev_hash + content)
        if (link["content_hash"] != expected_content_hash
                or link["chain_hash"] != expected_chain_hash
                or link["prev_hash"] != prev_hash):
            return False
        prev_hash = link["chain_hash"]
    return True


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

def _normalise(text: str) -> str:
    """Lower-case and strip extra whitespace."""
    return re.sub(r"\s+", " ", text.lower().strip())


def _extract_hashtags(text: str) -> list[str]:
    return [h.lower() for h in re.findall(r"#(\w+)", text)]


def _shingle(text: str, k: int = 4) -> set[str]:
    """k-gram character shingles for near-duplicate detection."""
    t = _normalise(text)
    return {t[i:i + k] for i in range(len(t) - k + 1)} if len(t) >= k else {t}


def jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity between two shingle sets."""
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_harm(text: str) -> tuple[float, list[str]]:
    """
    Score harm [0,1] for a single text.

    Returns (score, matched_phrases).
    Applies reporting-context reduction transparently.
    """
    t = _normalise(text)
    base = 0.0
    matched: list[str] = []

    for phrase, weight in HARM_PHRASES.items():
        if phrase in t:
            base = max(base, weight)
            matched.append(f"HARM:{phrase}({weight:.2f})")

    # Reporting / condemning reduction
    reduction = 0.0
    for phrase, delta in REPORTING_PHRASES:
        if phrase in t:
            reduction += abs(delta)
            matched.append(f"REPORT:{phrase}({delta:.2f})")

    score = max(0.0, min(1.0, base - reduction))
    return score, matched


def _near_dup_ratio(texts: list[str], threshold: float = 0.7) -> float:
    """Fraction of post pairs with Jaccard similarity >= threshold."""
    if len(texts) < 2:
        return 0.0
    shingles = [_shingle(t) for t in texts]
    pairs = list(combinations(range(len(shingles)), 2))
    if not pairs:
        return 0.0
    dup_count = sum(1 for i, j in pairs if jaccard(shingles[i], shingles[j]) >= threshold)
    return dup_count / len(pairs)


def _burst_ratio(timestamps: list[str], window_minutes: int = 10) -> float:
    """Fraction of posts that fall within a 10-minute burst window."""
    if len(timestamps) < 2:
        return 0.0
    epochs: list[float] = []
    for ts in timestamps:
        try:
            epochs.append(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    if len(epochs) < 2:
        return 0.0
    epochs.sort()
    window = window_minutes * 60
    best = 1
    left = 0
    for right in range(1, len(epochs)):
        while epochs[right] - epochs[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best / len(epochs)


def score_coordination(posts: list[dict[str, Any]]) -> tuple[float, dict[str, float]]:
    """
    Score coordination [0,1] for a cluster of posts.

    Returns (score, signal_dict).
    Signals: near_dup, burst_ratio, new_account_ratio, repeat_author_ratio.
    """
    texts = [p.get("text", "") for p in posts]
    timestamps = [p.get("timestamp", "") for p in posts]
    authors = [p.get("author", "") for p in posts]
    account_ages = [p.get("account_age_days", 365) for p in posts]

    near_dup = _near_dup_ratio(texts)
    burst = _burst_ratio(timestamps)
    new_account = (sum(1 for d in account_ages if d < 30) / len(posts)) if posts else 0.0
    repeat_author = (len(authors) - len(set(authors))) / len(authors) if authors else 0.0

    score = min(1.0, 0.35 * near_dup + 0.30 * burst + 0.20 * new_account + 0.15 * repeat_author)
    signals = {
        "near_dup": round(near_dup, 3),
        "burst_ratio": round(burst, 3),
        "new_account_ratio": round(new_account, 3),
        "repeat_author_ratio": round(repeat_author, 3),
    }
    return round(score, 3), signals


# ---------------------------------------------------------------------------
# Alert level
# ---------------------------------------------------------------------------

def level_for(harm: float, coord: float) -> str:
    """Two-key alert rule (harm × coordination)."""
    if harm >= 0.6 and coord >= 0.5:
        return "HIGH - ACT NOW"
    if harm >= 0.6 or (harm >= 0.4 and coord >= 0.5):
        return "MEDIUM - NEEDS REVIEW"
    return "LOW - MONITOR"


# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------

def classify_threat(posts: list[dict[str, Any]], matched_phrases: list[str]) -> str:
    """Heuristic threat-type classifier."""
    all_text = " ".join(_normalise(p.get("text", "")) for p in posts)
    phrase_labels = " ".join(matched_phrases).lower()

    harassment_kw = ["doxx", "dox", "stalk", "coming for you", "your address", "watch your back",
                     "rape threat", "bomb threat", "harass", "teri maa", "teri behen"]
    misinfo_kw = ["fake", "rigged", "stolen votes", "false flag", "crisis actor", "government hiding",
                  "media lies", "media bikau", "sarkar chhupa", "sazish", "deep state", "fabricated",
                  "fake khabar", "jhooth"]
    incitement_kw = ["kill", "burn", "attack", "blood", "arms", "revenge", "lynch", "mob",
                     "maar do", "jala do", "danga", "badla", "kaat do", "khatam", "khoon",
                     "ghar jalao", "nikalo", "inko bhagao"]

    def _hits(kws: list[str]) -> int:
        return sum(1 for k in kws if k in all_text or k in phrase_labels)

    scores_map = {
        "incitement": _hits(incitement_kw),
        "targeted_harassment": _hits(harassment_kw),
        "organized_misinformation": _hits(misinfo_kw),
    }
    best = max(scores_map, key=lambda k: scores_map[k])
    return best if scores_map[best] > 0 else "coordinated_inauthentic"


# ---------------------------------------------------------------------------
# Escalation steps
# ---------------------------------------------------------------------------

ESCALATION_STEPS: dict[str, list[str]] = {
    "HIGH - ACT NOW": [
        "Immediately escalate to the Cyber Crime Cell (nodal officer) within 1 hour.",
        "Preserve evidence: export full post metadata, screenshots and this brief.",
        "Request platform takedown under IT Act §69A / BNS provisions listed below.",
        "Notify district SP / DCP for potential law-and-order deployment.",
        "Open an FIR referencing the evidence IDs and hash chain in this brief.",
        "Consider Section 144 CrPC / BNSS preventive measures if incitement is local.",
    ],
    "MEDIUM - NEEDS REVIEW": [
        "Assign to a senior analyst for manual review within 4 hours.",
        "Cross-check author accounts for prior flagging in internal systems.",
        "Issue a platform notice requesting content review under IT Rules 2021.",
        "Brief the district intelligence officer; no public statement yet.",
        "Re-score after 24 hours if activity continues.",
    ],
    "LOW - MONITOR": [
        "Log in the threat register and schedule a 48-hour re-check.",
        "No immediate action required; continue passive monitoring.",
        "Flag authors for watchlist if account age < 30 days.",
    ],
}


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def flatten_posts(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten top-level posts and their nested comments into a single list."""
    flat: list[dict[str, Any]] = []
    for post in raw:
        p = {k: v for k, v in post.items() if k != "comments"}
        p.setdefault("id", str(uuid.uuid4()))
        flat.append(p)
        for comment in post.get("comments", []):
            c = dict(comment)
            c.setdefault("id", str(uuid.uuid4()))
            c["parent_post_id"] = post.get("id", "")
            flat.append(c)
    return flat


def cluster_by_hashtags(posts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Group posts into clusters by co-occurring hashtags (union-find).
    Posts with no hashtags form a single 'no_hashtag' cluster.
    """
    uf = UnionFind()
    post_tags: list[list[str]] = []
    for post in posts:
        tags = _extract_hashtags(post.get("text", ""))
        post_tags.append(tags)
        for i in range(1, len(tags)):
            uf.union(tags[0], tags[i])

    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for post, tags in zip(posts, post_tags):
        if tags:
            root = uf.find(tags[0])
            clusters[root].append(post)
        else:
            clusters["no_hashtag"].append(post)
    return dict(clusters)


def _watsonx_refine(text: str, harm_score: float) -> float:
    """
    Optionally refine harm score via watsonx.ai.
    Returns original score if credentials absent or call fails.

    NOTE: This integration is tested only with synthetic prompts.
    Verify endpoint / model against IBM Cloud docs before production use.
    """
    api_key = os.getenv("WATSONX_API_KEY")
    project_id = os.getenv("WATSONX_PROJECT_ID")
    if not api_key or not project_id:
        return harm_score

    try:
        import requests  # type: ignore

        region = os.getenv("WATSONX_REGION", "us-south")
        model_id = os.getenv("WATSONX_MODEL", "ibm/granite-13b-instruct-v2")

        # Get IAM token
        iam_resp = requests.post(
            "https://iam.cloud.ibm.com/identity/token",
            data={"apikey": api_key, "grant_type": "urn:ibm:params:oauth:grant-type:apikey"},
            timeout=10,
        )
        iam_resp.raise_for_status()
        token = iam_resp.json()["access_token"]

        prompt = (
            "You are a content moderation system. Given the text below, output ONLY a "
            "harm severity score between 0.0 (no harm) and 1.0 (extreme harm). "
            "Output only the number, nothing else.\n\n"
            f"Text: {text[:500]}\nScore:"
        )

        wx_resp = requests.post(
            f"https://{region}.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "model_id": model_id,
                "input": prompt,
                "parameters": {"max_new_tokens": 8, "temperature": 0},
                "project_id": project_id,
            },
            timeout=15,
        )
        wx_resp.raise_for_status()
        raw = wx_resp.json()["results"][0]["generated_text"].strip()
        refined = float(re.search(r"[\d.]+", raw).group())  # type: ignore[union-attr]
        return max(0.0, min(1.0, refined))
    except Exception as exc:
        log.warning("watsonx refinement failed: %s", exc)
        return harm_score


def analyze(raw_posts: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Full TRACE analysis pipeline.

    Parameters
    ----------
    raw_posts:
        List of post dicts (may include nested 'comments').

    Returns
    -------
    dict with keys: alerts, evidence_chain, metadata
    """
    posts = flatten_posts(raw_posts)
    clusters = cluster_by_hashtags(posts)

    alerts: list[dict[str, Any]] = []
    all_evidence_items: list[dict[str, Any]] = []

    for cluster_key, cluster_posts in clusters.items():
        if not cluster_posts:
            continue

        # Per-post harm scoring
        post_harms: list[tuple[float, list[str]]] = []
        for p in cluster_posts:
            h, m = score_harm(p.get("text", ""))
            h = _watsonx_refine(p.get("text", ""), h)
            post_harms.append((h, m))

        harm_score = max((h for h, _ in post_harms), default=0.0)
        all_matched = [phrase for _, ms in post_harms for phrase in ms]

        coord_score, coord_signals = score_coordination(cluster_posts)
        level = level_for(harm_score, coord_score)
        threat_type = classify_threat(cluster_posts, all_matched)

        bns_info = BNS_TABLE.get(threat_type, BNS_TABLE["coordinated_inauthentic"])
        escalation = ESCALATION_STEPS[level]

        # Build evidence items for this cluster
        evidence_items = [
            {
                "id": p.get("id", str(uuid.uuid4())),
                "author": p.get("author", "unknown"),
                "text": p.get("text", "")[:200],
                "timestamp": p.get("timestamp", ""),
                "hashtags": _extract_hashtags(p.get("text", "")),
            }
            for p in cluster_posts
        ]
        chain = build_evidence_chain(evidence_items)
        all_evidence_items.extend(evidence_items)

        alert: dict[str, Any] = {
            "cluster": cluster_key,
            "level": level,
            "threat_type": threat_type,
            "harm_score": round(harm_score, 3),
            "coordination_score": round(coord_score, 3),
            "coordination_signals": coord_signals,
            "post_count": len(cluster_posts),
            "matched_phrases": sorted(set(all_matched)),
            "bns_provisions": bns_info["bns_sections"],
            "ipc_legacy": bns_info["ipc_legacy"],
            "provision_note": (
                "Provisions potentially attracted, subject to legal review. "
                "This tool does not determine guilt."
            ),
            "escalation_steps": escalation,
            "evidence_chain": chain,
            "brief_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        alerts.append(alert)

    alerts.sort(key=lambda a: (
        {"HIGH - ACT NOW": 0, "MEDIUM - NEEDS REVIEW": 1, "LOW - MONITOR": 2}[a["level"]],
        -a["harm_score"],
    ))

    return {
        "alerts": alerts,
        "metadata": {
            "total_posts_analyzed": len(posts),
            "total_clusters": len(clusters),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "engine_version": "1.0.0",
        },
    }


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="TRACE Engine", version="1.0.0")


class AnalyzeRequest(BaseModel):
    posts: list[dict[str, Any]]


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check."""
    return {"status": "ok", "service": "TRACE", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> JSONResponse:
    """Analyze a batch of social-media posts."""
    if not req.posts:
        raise HTTPException(status_code=400, detail="posts list is empty")
    result = analyze(req.posts)
    return JSONResponse(content=result)


@app.get("/demo")
def demo_endpoint() -> JSONResponse:
    """Run analysis on built-in demo data."""
    demo_posts = _demo_posts()
    result = analyze(demo_posts)
    return JSONResponse(content=result)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_endpoint() -> HTMLResponse:
    """Live TRACE dashboard – fetches /demo data and renders it."""
    return HTMLResponse(content=_DASHBOARD_HTML)


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>TRACE – Threat Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 28px;display:flex;align-items:center;gap:14px}
header h1{font-size:20px;font-weight:700;letter-spacing:.5px;color:#f0f6fc}
header .badge{font-size:11px;font-weight:600;padding:3px 8px;border-radius:20px;background:#21262d;border:1px solid #30363d;color:#8b949e}
.engine-ok{color:#3fb950;font-size:12px;display:flex;align-items:center;gap:5px;margin-left:auto}
.dot{width:8px;height:8px;border-radius:50%;background:#3fb950;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
main{padding:24px 28px;max-width:1280px;margin:0 auto}
/* stat cards */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 20px}
.card .label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.card .value{font-size:30px;font-weight:700;color:#f0f6fc}
.card .sub{font-size:12px;color:#8b949e;margin-top:4px}
/* level colours */
.HIGH{color:#f85149}.MEDIUM{color:#d29922}.LOW{color:#3fb950}
/* alert blocks */
.section-title{font-size:13px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.6px;margin-bottom:14px;border-bottom:1px solid #21262d;padding-bottom:8px}
.alerts{display:flex;flex-direction:column;gap:16px;margin-bottom:32px}
.alert-card{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}
.alert-header{padding:14px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #21262d}
.level-badge{font-size:11px;font-weight:700;padding:4px 10px;border-radius:20px}
.level-HIGH{background:#3d1a1a;color:#f85149;border:1px solid #5c2020}
.level-MEDIUM{background:#2d2008;color:#d29922;border:1px solid #4a3408}
.level-LOW{background:#0d2b12;color:#3fb950;border:1px solid #1a4a22}
.cluster-name{font-size:14px;font-weight:600;color:#f0f6fc;text-transform:uppercase;letter-spacing:.4px}
.alert-body{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;padding:0}
.ab-section{padding:16px 20px;border-right:1px solid #21262d}
.ab-section:last-child{border-right:none}
.ab-title{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
/* score bars */
.score-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.score-label{font-size:12px;color:#8b949e;width:130px;flex-shrink:0}
.bar-track{flex:1;height:6px;background:#21262d;border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;transition:width .6s ease}
.score-val{font-size:12px;color:#8b949e;width:32px;text-align:right;flex-shrink:0}
/* phrases */
.phrases{display:flex;flex-wrap:wrap;gap:6px}
.phrase{font-size:11px;padding:3px 8px;border-radius:12px;font-family:monospace}
.phrase-harm{background:#3d1a1a;color:#f85149;border:1px solid #5c2020}
.phrase-report{background:#0d2b12;color:#3fb950;border:1px solid #1a4a22}
/* escalation */
.steps{list-style:none;display:flex;flex-direction:column;gap:6px}
.steps li{font-size:12px;color:#c9d1d9;display:flex;gap:8px;line-height:1.5}
.steps li::before{content:counter(step);counter-increment:step;background:#21262d;color:#8b949e;border-radius:50%;width:18px;height:18px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.steps{counter-reset:step}
/* evidence chain */
.chain-table{width:100%;border-collapse:collapse;font-size:11px;font-family:monospace}
.chain-table th{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left;font-weight:600;letter-spacing:.4px}
.chain-table td{padding:6px 10px;border-top:1px solid #21262d;color:#c9d1d9;word-break:break-all}
.chain-table tr:hover td{background:#1c2128}
/* provisions */
.prov-list{display:flex;flex-direction:column;gap:5px}
.prov{font-size:12px;padding:5px 10px;background:#21262d;border-radius:6px;color:#c9d1d9}
/* refresh btn */
.refresh-btn{margin-left:auto;background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:7px 16px;border-radius:6px;font-size:13px;cursor:pointer;transition:background .2s}
.refresh-btn:hover{background:#30363d}
.ts{font-size:11px;color:#8b949e;margin-bottom:20px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px}
/* SVG chart */
.chart-wrap{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 20px}
</style>
</head>
<body>
<header>
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <circle cx="14" cy="14" r="13" stroke="#3b82d4" stroke-width="2"/>
    <circle cx="14" cy="14" r="7" stroke="#f85149" stroke-width="2"/>
    <circle cx="14" cy="14" r="2" fill="#f85149"/>
    <line x1="14" y1="1" x2="14" y2="5" stroke="#3b82d4" stroke-width="2"/>
    <line x1="14" y1="23" x2="14" y2="27" stroke="#3b82d4" stroke-width="2"/>
    <line x1="1" y1="14" x2="5" y2="14" stroke="#3b82d4" stroke-width="2"/>
    <line x1="23" y1="14" x2="27" y2="14" stroke="#3b82d4" stroke-width="2"/>
  </svg>
  <h1>TRACE Engine</h1>
  <span class="badge">v1.0.0</span>
  <span class="badge">Threat Intelligence</span>
  <div class="engine-ok"><span class="dot"></span>Live</div>
  <button class="refresh-btn" onclick="loadData()">&#8635; Refresh</button>
</header>

<main>
  <p class="ts" id="ts">Loading…</p>

  <!-- Stat cards -->
  <div class="stats" id="stats"></div>

  <!-- Harm vs Coord chart -->
  <div class="grid2" id="chartRow"></div>

  <!-- Alert cards -->
  <div class="section-title">Cluster Alerts</div>
  <div class="alerts" id="alerts"></div>

  <!-- Evidence chain -->
  <div class="section-title">Evidence Chain (all clusters)</div>
  <div class="chart-wrap" style="overflow-x:auto" id="chainWrap"></div>
</main>

<script>
function levelKey(l){return l.split(' ')[0]}

function barColor(v){
  if(v>=0.8) return '#f85149';
  if(v>=0.5) return '#d29922';
  return '#3fb950';
}

function scoreRow(label,val){
  const pct=Math.round(val*100);
  return `<div class="score-row">
    <span class="score-label">${label}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${barColor(val)}"></div></div>
    <span class="score-val">${pct}%</span>
  </div>`;
}

function phraseTag(p){
  const isHarm=p.startsWith('HARM');
  return `<span class="phrase ${isHarm?'phrase-harm':'phrase-report'}">${p}</span>`;
}

function renderStats(data){
  const alerts=data.alerts;
  const high=alerts.filter(a=>a.level.startsWith('HIGH')).length;
  const med=alerts.filter(a=>a.level.startsWith('MEDIUM')).length;
  const low=alerts.filter(a=>a.level.startsWith('LOW')).length;
  const maxHarm=Math.max(...alerts.map(a=>a.harm_score));
  return `
    <div class="card"><div class="label">Posts Analysed</div><div class="value">${data.metadata.total_posts_analyzed}</div><div class="sub">across ${data.metadata.total_clusters} clusters</div></div>
    <div class="card"><div class="label">HIGH Alerts</div><div class="value HIGH">${high}</div><div class="sub">Immediate action</div></div>
    <div class="card"><div class="label">MEDIUM Alerts</div><div class="value MEDIUM">${med}</div><div class="sub">Needs review</div></div>
    <div class="card"><div class="label">LOW Alerts</div><div class="value LOW">${low}</div><div class="sub">Monitor</div></div>
    <div class="card"><div class="label">Peak Harm Score</div><div class="value" style="color:${barColor(maxHarm)}">${(maxHarm*100).toFixed(0)}%</div><div class="sub">Worst cluster</div></div>
  `;
}

function renderChart(data){
  const alerts=data.alerts;
  const W=460,H=220,PL=50,PR=20,PT=20,PB=40;
  const iW=W-PL-PR, iH=H-PT-PB;
  let bars='', xLabels='', yLines='';
  const bW=Math.min(40, iW/alerts.length*0.5);
  const gap=iW/alerts.length;
  [0,0.25,0.5,0.75,1.0].forEach(v=>{
    const y=PT+iH*(1-v);
    yLines+=`<line x1="${PL}" x2="${W-PR}" y1="${y}" y2="${y}" stroke="#21262d" stroke-width="1"/>`;
    yLines+=`<text x="${PL-6}" y="${y+4}" text-anchor="end" fill="#8b949e" font-size="10">${(v*100).toFixed(0)}</text>`;
  });
  alerts.forEach((a,i)=>{
    const cx=PL+gap*i+gap/2;
    const hH=iH*a.harm_score;
    const cH=iH*a.coordination_score;
    bars+=`<rect x="${cx-bW-2}" y="${PT+iH-hH}" width="${bW}" height="${hH}" fill="${barColor(a.harm_score)}" rx="2" opacity=".85">
      <title>${a.cluster}: Harm ${(a.harm_score*100).toFixed(0)}%</title></rect>`;
    bars+=`<rect x="${cx+2}" y="${PT+iH-cH}" width="${bW}" height="${cH}" fill="#3b82d4" rx="2" opacity=".75">
      <title>${a.cluster}: Coord ${(a.coordination_score*100).toFixed(0)}%</title></rect>`;
    const short=a.cluster.length>12?a.cluster.slice(0,12)+'…':a.cluster;
    xLabels+=`<text x="${cx}" y="${H-8}" text-anchor="middle" fill="#8b949e" font-size="9">${short}</text>`;
  });
  const svg=`<svg width="100%" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">${yLines}${bars}${xLabels}
    <text x="${W/2}" y="12" text-anchor="middle" fill="#8b949e" font-size="11" font-weight="600">Harm vs Coordination Scores (%)</text>
    <rect x="${W-PR-120}" y="5" width="10" height="10" fill="#f85149" rx="2"/>
    <text x="${W-PR-108}" y="14" fill="#8b949e" font-size="10">Harm</text>
    <rect x="${W-PR-70}" y="5" width="10" height="10" fill="#3b82d4" rx="2"/>
    <text x="${W-PR-58}" y="14" fill="#8b949e" font-size="10">Coordination</text>
  </svg>`;

  // Coord signal breakdown radar-like bar chart
  const sig=alerts[0]?.coordination_signals||{};
  const sigKeys=Object.keys(sig);
  const SW=460,SH=220;
  const sbW=Math.min(60, (SW-80)/sigKeys.length*0.6);
  const sgap=(SW-80)/sigKeys.length;
  let sbars='',sxl='',syLines='';
  [0,0.25,0.5,0.75,1.0].forEach(v=>{
    const y=PT+iH*(1-v);
    syLines+=`<line x1="50" x2="${SW-20}" y1="${y}" y2="${y}" stroke="#21262d" stroke-width="1"/>`;
    syLines+=`<text x="44" y="${y+4}" text-anchor="end" fill="#8b949e" font-size="10">${(v*100).toFixed(0)}</text>`;
  });
  sigKeys.forEach((k,i)=>{
    const v=sig[k];
    const cx=50+sgap*i+sgap/2;
    const bh=iH*v;
    sbars+=`<rect x="${cx-sbW/2}" y="${PT+iH-bh}" width="${sbW}" height="${bh}" fill="#7c5cd8" rx="2" opacity=".85">
      <title>${k}: ${(v*100).toFixed(0)}%</title></rect>`;
    const lbl=k.replace(/_/g,' ');
    sxl+=`<text x="${cx}" y="${SH-8}" text-anchor="middle" fill="#8b949e" font-size="9">${lbl}</text>`;
  });
  const svg2=`<svg width="100%" viewBox="0 0 ${SW} ${SH}" xmlns="http://www.w3.org/2000/svg">${syLines}${sbars}${sxl}
    <text x="${SW/2}" y="12" text-anchor="middle" fill="#8b949e" font-size="11" font-weight="600">Coordination Signals – #ChowkAlert (%)</text>
  </svg>`;

  return `<div class="chart-wrap">${svg}</div><div class="chart-wrap">${svg2}</div>`;
}

function renderAlerts(data){
  return data.alerts.map(a=>{
    const lk=levelKey(a.level);
    const phrases=a.matched_phrases.map(phraseTag).join('');
    const steps=a.escalation_steps.map(s=>`<li>${s}</li>`).join('');
    const provs=a.bns_provisions.map(p=>`<div class="prov">${p}</div>`).join('');
    const sigs=a.coordination_signals;
    return `
    <div class="alert-card">
      <div class="alert-header">
        <span class="level-badge level-${lk}">${a.level}</span>
        <span class="cluster-name">#${a.cluster}</span>
        <span style="font-size:12px;color:#8b949e;margin-left:8px">${a.post_count} posts &nbsp;·&nbsp; ${a.threat_type}</span>
        <span style="font-size:11px;color:#8b949e;margin-left:auto">Brief: ${a.brief_id.slice(0,8)}…</span>
      </div>
      <div class="alert-body">
        <div class="ab-section">
          <div class="ab-title">Scores</div>
          ${scoreRow('Harm Score', a.harm_score)}
          ${scoreRow('Coordination', a.coordination_score)}
          ${scoreRow('Near-Dup Ratio', sigs.near_dup)}
          ${scoreRow('Burst Ratio', sigs.burst_ratio)}
          ${scoreRow('New Account Ratio', sigs.new_account_ratio)}
          ${scoreRow('Repeat Author', sigs.repeat_author_ratio)}
        </div>
        <div class="ab-section">
          <div class="ab-title">Matched Phrases</div>
          <div class="phrases">${phrases||'<span style="color:#8b949e;font-size:12px">None</span>'}</div>
          <div style="margin-top:14px"><div class="ab-title">BNS Provisions</div><div class="prov-list">${provs}</div></div>
        </div>
        <div class="ab-section">
          <div class="ab-title">Escalation Steps</div>
          <ol class="steps">${steps}</ol>
        </div>
      </div>
    </div>`;
  }).join('');
}

function renderChain(data){
  const rows=data.alerts.flatMap(a=>
    a.evidence_chain.map(e=>`<tr>
      <td>${e.id}</td>
      <td>${e.timestamp||'—'}</td>
      <td style="color:#f0f6fc">${e.content_hash.slice(0,20)}…</td>
      <td style="color:#8b949e">${e.prev_hash.slice(0,20)}…</td>
      <td style="color:#3fb950">${e.chain_hash.slice(0,20)}…</td>
    </tr>`)
  ).join('');
  return `<table class="chain-table">
    <thead><tr><th>Post ID</th><th>Timestamp</th><th>Content Hash</th><th>Prev Hash</th><th>Chain Hash</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function loadData(){
  try{
    const r=await fetch('/demo');
    const data=await r.json();
    document.getElementById('ts').textContent='Last refreshed: '+new Date(data.metadata.analysis_timestamp).toLocaleString()+' · Engine v'+data.metadata.engine_version;
    document.getElementById('stats').innerHTML=renderStats(data);
    document.getElementById('chartRow').innerHTML=renderChart(data);
    document.getElementById('alerts').innerHTML=renderAlerts(data);
    document.getElementById('chainWrap').innerHTML=renderChain(data);
  }catch(e){
    document.getElementById('ts').textContent='Error loading data: '+e.message;
  }
}
loadData();
</script>
</body>
</html>"""




# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

def _demo_posts() -> list[dict[str, Any]]:
    """Small self-contained demo dataset."""
    return [
        {
            "id": "d001", "author": "user_alpha", "account_age_days": 5,
            "timestamp": "2024-06-15T08:01:00Z",
            "text": "Chowk Alert! Nikalo unhe, ghar jalao! #ChowkAlert #ActionNow",
            "comments": [
                {"id": "d001c1", "author": "user_beta", "account_age_days": 3,
                 "timestamp": "2024-06-15T08:03:00Z",
                 "text": "Haan! Maar do inhe! Khoon bahega! #ChowkAlert"},
            ],
        },
        {
            "id": "d002", "author": "user_gamma", "account_age_days": 7,
            "timestamp": "2024-06-15T08:05:00Z",
            "text": "Nikalo unhe ghar jalao danga karo! #ChowkAlert #ActionNow",
        },
        {
            "id": "d003", "author": "reporter_01", "account_age_days": 900,
            "timestamp": "2024-06-15T09:00:00Z",
            "text": "Police say: rumours of attack reported near Market Square. "
                    "We condemn any violence. #MarketSquareNews",
        },
        {
            "id": "d004", "author": "journalist_02", "account_age_days": 1200,
            "timestamp": "2024-06-15T09:10:00Z",
            "text": "Breaking news: authorities say situation is under control. "
                    "Condemnable acts must be stopped. #MarketSquareNews",
        },
    ]


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(description="TRACE engine CLI")
    parser.add_argument("--demo", action="store_true", help="Run built-in demo and print results")
    parser.add_argument("--input", type=str, help="Path to JSON file of posts")
    args = parser.parse_args()

    if args.demo:
        result = analyze(_demo_posts())
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.input:
        with open(args.input, encoding="utf-8") as fh:
            raw = json.load(fh)
        result = analyze(raw)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("Starting TRACE API server on http://0.0.0.0:8000")
        uvicorn.run("trace_engine:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    _cli()
