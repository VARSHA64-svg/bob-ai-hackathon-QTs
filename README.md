# 🚀 [1]TRACE [Threat Reconnaissance and Coordination Evidence Engine]

> ⚠️ **Replace everything in `[ ]` brackets with your actual content before submission.**

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | [QTs] |
| **Track** | [Open] |
| **Team Lead** | [S. Sai Varsha] — [varsha641980@gmail.com] |
| **Members** | [Srishti Prasad] |

---

## 🎯 Problem Statement

> Social Media Threat Intelligence Engine

[Real Case: The 2022 Nupur Sharma controversy and 2020 Delhi riots — coordinated hashtag campaigns directly preceded communal violence in multiple cities. Police had no real-time tool to detect coordinated inauthentic behavior or emerging offline threats from online content patterns.
Build a Bob-powered OSINT tool that ingests a batch of mock social media posts, detects coordinated inauthentic behavior signals, classifies threat type (incitement / targeted harassment / organized misinformation), maps to IPC/BNS provisions, and generates a time-stamped threat brief with recommended escalation steps for law enforcement.]

---

## 💡 Solution

> In 2–3 sentences: What did you build? How does it solve the problem above?

[**TRACE (Threat Reconnaissance and Coordination Evidence Engine)** is a social media threat detection system built on fully synthetic data. We generated labelled datasets across 7 threat scenarios — incitement, harassment, misinformation, and coordinated inauthentic behaviour — using [`make_dataset.py`](make_dataset.py). The core engine in [`trace_engine.py`](trace_engine.py) clusters posts by hashtag, then scores each cluster on **harm** and **coordination** to produce `HIGH`, `MEDIUM`, or `LOW` alerts. A Streamlit dashboard in [`dashboard.py`](dashboard.py) visualises results interactively. Finally, [`evaluate.py`](evaluate.py) benchmarks engine accuracy across 5 random seeds using precision, recall, and false alarm metrics against ground truth labels.

---

## ✨ Key Features

- **Feature 1:** [Brief description — e.g., "Real-time anomaly detection using watsonx.ai"]
- **Feature 2:** [Brief description]
- **Feature 3:** [Brief description]
- **Feature 4:** [Optional]
- **Feature 5:** [Optional]

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.14 |
| **Web UI** | Streamlit |
| **API Server** | FastAPI |
| **AI / LLM** | IBM watsonx (optional refinement) |
| **RAG** | [`rag.py`](rag.py) — custom Retrieval-Augmented Generation |
| **Data** | JSON (synthetic, no external DB) |
| **Hashing / Integrity** | SHA-256 (evidence chain) |
| **Testing** | pytest |
| **Similarity** | Jaccard / k-shingle (near-dup detection) |
| **Config** | `.streamlit/config.toml` |
| **Dependency Mgmt** | `pip` + [`requirements.txt`](requirements.txt) |

**No external database. No real social media API. Fully self-contained Python stack.**

---

## 📁 Repository Structure

```
```
TRACE/
│
├── trace_engine.py        # Core engine — harm scoring, coordination, clustering, alerts
├── dashboard.py           # Streamlit UI — alerts, network graph, timeline, RAG tab
├── make_dataset.py        # Synthetic dataset generator (7 scenarios + background noise)
├── evaluate.py            # Evaluation harness — precision, recall, false alarms across seeds
├── rag.py                 # RAG (Retrieval-Augmented Generation) Q&A module
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
├── BOB_LOG.md             # Bob assistant activity log
│
├── data/                  # Generated datasets (one folder per seed)
│   ├── seed_42/
│   │   ├── posts.json         # Synthetic input posts
│   │   └── ground_truth.json  # Expected threat labels
│   ├── seed_99/
│   ├── seed_7/
│   ├── seed_2024/
│   └── seed_1337/
│
├── tests/
│   ├── test_engine.py     # Unit tests for the TRACE engine
│   └── __init__.py
│
└── .streamlit/
    └── config.toml        # Streamlit theme/config
```

**6 core files, 5 seeded datasets, 1 test suite.**
```

---

## ⚡ How to Run

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

---

### 2. Generate the Dataset
```bash
# Default seed (42)
python make_dataset.py

# Custom seed
python make_dataset.py --seed 99
```

---

### 3. Run the Streamlit Dashboard
```bash
streamlit run dashboard.py
```
Then open **http://localhost:8501** in your browser.
- Choose **Built-in demo** → click **Run demo analysis**
- Or **Upload JSON** → select any `data/seed_42/posts.json`
- Or **Paste JSON** → paste a raw post array

---

### 4. Run the Evaluation
```bash
# All 5 seeds (42, 99, 7, 2024, 1337)
python evaluate.py

# Custom seeds
python evaluate.py --seeds 42 99
```

---

### 5. Run the FastAPI Server
```bash
uvicorn trace_engine:app --reload
```
Then hit:
- `GET  /health` — health check
- `POST /analyze` — send `{ "posts": [...] }`
- `GET  /demo` — run built-in demo

---

### 6. Run Tests
```bash
pytest tests/
```

---

> **No API keys required** for basic use. IBM watsonx is optional — the engine falls back to rule-based scoring if not configured.
---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

---

## ⚠️ Known Limitations

> Be honest — judges appreciate transparency over overclaiming.

- [Limitation 1: e.g., "Authentication is mocked — not production-ready"]
- [Limitation 2: e.g., "Only tested on Chrome"]
- [Limitation 3: e.g., "Feature X is scaffolded but not fully implemented"]

---

## 🏅 What We're Most Proud Of

[Tell the judges what part of your submission is strongest and worth paying close attention to.]

---
