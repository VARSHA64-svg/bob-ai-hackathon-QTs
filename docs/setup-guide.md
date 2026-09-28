# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

---

## Prerequisites

Before you begin, ensure you have the following:

- [ ] **Python 3.11+** — [Download](https://www.python.org/downloads/)
- [ ] **pip** (bundled with Python 3.11+)
- [ ] *(Optional)* An **IBM Cloud account** with watsonx.ai access — only needed for LLM-powered harm refinement and RAG answer generation. The engine runs fully offline without it.

---

## Environment Variables

No `.env` file is required for basic use. For watsonx.ai integration, set the following environment variables:

| Variable | Description | Required |
|---|---|---|
| `WATSONX_API_KEY` | Your IBM watsonx.ai API key | No (optional) |
| `WATSONX_PROJECT_ID` | Your watsonx.ai project ID | No (optional) |
| `WATSONX_REGION` | IBM Cloud region (default: `us-south`) | No (optional) |
| `WATSONX_MODEL` | LLM model ID (default: `ibm/granite-13b-instruct-v2`) | No (optional) |
| `WATSONX_EMBED_MODEL` | Embedding model ID (default: `ibm/slate-125m-english-rtrvr`) | No (optional) |

Set them in your shell:

```bash
# Linux / macOS
export WATSONX_API_KEY=your_key_here
export WATSONX_PROJECT_ID=your_project_id_here

# Windows PowerShell
$env:WATSONX_API_KEY="your_key_here"
$env:WATSONX_PROJECT_ID="your_project_id_here"
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/trace.git
cd trace

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Enable semantic RAG — uncomment in requirements.txt first
pip install sentence-transformers numpy
```

---

## Running the Application

### Streamlit Dashboard
```bash
streamlit run dashboard.py
```
Available at: **http://localhost:8501**

### FastAPI Server
```bash
uvicorn trace_engine:app --reload
```
Available at: **http://localhost:8000**

API endpoints:
| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/analyze` | POST | Analyse a JSON array of posts |
| `/demo` | GET | Run built-in demo analysis |

---

## Generating the Dataset

```bash
# Default seed (42) → writes to data/seed_42/
python make_dataset.py

# Custom seed
python make_dataset.py --seed 99

# Custom output directory
python make_dataset.py --seed 7 --out-dir data/seed_7
```

---

## Running Evaluation

```bash
# Evaluate across all 5 seeds (42, 99, 7, 2024, 1337)
python evaluate.py

# Evaluate on specific seeds
python evaluate.py --seeds 42 99
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Quick Demo

**Option 1 — Dashboard (recommended):**
```bash
streamlit run dashboard.py
# → Click "Built-in demo" → "Run demo analysis"
```

**Option 2 — API:**
```bash
uvicorn trace_engine:app --reload
# In another terminal:
curl http://localhost:8000/demo
```

**Option 3 — CLI:**
```bash
python trace_engine.py
```

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError: fastapi` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: streamlit` | Run `pip install streamlit>=1.35.0` |
| `ModuleNotFoundError: sentence_transformers` | Uncomment and install optional deps: `pip install sentence-transformers numpy` |
| watsonx.ai `401 Unauthorized` | Check `WATSONX_API_KEY` and `WATSONX_PROJECT_ID` are set correctly |
| watsonx.ai `404` on embeddings | Check `WATSONX_REGION` matches your IBM Cloud region |
| Dashboard shows no alerts | Ensure you clicked **"Run demo analysis"** or uploaded a valid `posts.json` |
| `data/` folder missing | Run `python make_dataset.py` to generate it |
| Port 8501 already in use | Run `streamlit run dashboard.py --server.port 8502` |
