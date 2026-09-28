# Solution Overview

## What We Built

**TRACE** (Threat Reconnaissance and Coordination Evidence Engine) is a threat detection system that analyses social media posts to identify dangerous coordinated activity — incitement to violence, targeted harassment, and organised misinformation — before it escalates into real-world harm.

It does two things that no existing lightweight tool does together: it scores **how harmful** a post's language is, and it scores **how coordinated** the accounts posting it are. Combining both signals gives analysts a reliable, explainable alert — not just a flagged keyword. It also handles **Hinglish** (Hindi-English code-switching), maps findings to **Indian legal provisions (BNS/IPC)**, and produces a **SHA-256 tamper-evident evidence chain** suitable for law enforcement use.

---

## How It Works

1. **Ingest** — A JSON array of social media posts (with author, timestamp, text, account age) is fed in via the dashboard, API, or CLI.
2. **Flatten** — Nested comments are extracted alongside top-level posts into a single flat list for uniform processing.
3. **Cluster** — Posts are grouped by shared hashtags. Posts with no hashtag form a `no_hashtag` cluster. Each cluster is analysed independently.
4. **Harm Score** — Every post is scanned against a weighted Hinglish + English lexicon of violent, harassing, and misinformation phrases. IBM watsonx.ai optionally refines borderline scores using `granite-13b-instruct-v2`.
5. **Coordination Score** — Each cluster is checked for three coordination signals: near-duplicate text (Jaccard/k-shingle similarity), burst timing (many posts within 10 minutes), and new account ratio (accounts < 30 days old).
6. **Alert Level** — Harm and coordination scores are combined into one of three levels: `HIGH - ACT NOW`, `MEDIUM - NEEDS REVIEW`, or `LOW - MONITOR`.
7. **Evidence Chain** — Each post in the cluster is SHA-256 hashed and linked into a tamper-evident chain — verifiable proof that content was not altered after capture.
8. **Legal Mapping** — The detected threat type is automatically mapped to applicable **BNS sections and legacy IPC provisions** with escalation steps.
9. **RAG Q&A** — Alert briefs are indexed (TF-IDF or semantic embeddings) so analysts can ask natural-language questions like *"What escalation steps apply to this cluster?"* and get grounded answers via watsonx.ai.
10. **Display** — The Streamlit dashboard renders alerts, a network graph of account relationships, a timeline of post bursts, and the full evidence chain with integrity verification.

---

## Architecture Diagram

```
[User / Browser]
      │
      ├──── Streamlit :8501 ──► dashboard.py
      │                              │
      └──── REST :8000  ──► FastAPI (trace_engine.py)
                                     │
                          ┌──────────▼──────────┐
                          │   TRACE analyze()    │
                          │  flatten → cluster   │
                          │  harm + coord score  │
                          │  alert + chain       │
                          └──────────┬──────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                 ▼
             Lexicon scorer    watsonx.ai         RAG Index
             (rule-based)    (optional LLM)   (TF-IDF / semantic)
```

> See [`architecture.md`](architecture.md) for the full detailed diagram.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Dual-axis scoring (harm × coordination)** | A single harmful post and a coordinated bot campaign require different responses; combining both axes avoids both false positives and missed threats |
| **Hinglish lexicon built-in** | English-only NLP misses direct incitement phrases like *"maar do"* or *"ghar jalao"*; a curated bilingual lexicon ensures coverage without requiring a fine-tuned model |
| **Synthetic dataset, not real scraped data** | Avoids legal/ethical issues with real user data; enables reproducible, seeded evaluation across multiple random configurations |
| **SHA-256 evidence chain** | Screenshots are tamper-prone; a cryptographic chain of custody makes evidence defensible for law enforcement and FIR filing |
| **watsonx.ai as optional, not required** | Keeps the tool fully deployable offline in low-connectivity or air-gapped law enforcement environments; AI enhances but does not gate functionality |
| **FastAPI + Streamlit dual interface** | Streamlit serves human analysts; FastAPI enables integration into existing OSINT pipelines or SIEM systems programmatically |
| **TF-IDF with semantic fallback in RAG** | Guarantees RAG works in any environment (no GPU, no internet); semantic retrieval via `sentence-transformers` upgrades quality when available |

---

## IBM Technologies Used

- **IBM watsonx.ai — `ibm/granite-13b-instruct-v2`:** Used in [`rag.py`](rag.py:296) to generate natural-language answers to analyst queries over retrieved threat brief context. The model receives a structured prompt containing the top-2 retrieved alert briefs and the analyst's question, returning a concise factual answer.

- **IBM watsonx.ai — `ibm/slate-125m-english-rtrvr`:** Used in [`rag.py`](rag.py:188) to generate dense vector embeddings of alert briefs for semantic retrieval. When credentials are available, this replaces TF-IDF cosine similarity with embedding-based nearest-neighbour search for more accurate Q&A retrieval.

- **IBM watsonx.ai — harm score refinement:** Used in [`trace_engine.py`](trace_engine.py:506) via `_watsonx_refine()` to re-score borderline posts (harm score 0.3–0.7) using the Granite LLM, reducing false positives on ambiguous Hinglish phrasing that the lexicon alone may mis-score.
