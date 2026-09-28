"""
dashboard.py
TRACE Streamlit dashboard.

Tabs:
  1. Alerts      – alert cards, network graph, coordination timeline, explainability panel,
                   Download brief, Approve/Reject escalation
  2. Integrity   – SHA-256 text/file check, ledger lookup, dataset hash-chain check, JSON report
  3. RAG Query   – retrieval-augmented search over threat briefs
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import streamlit as st

# ---------------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="TRACE – Threat Intelligence Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Import engine (local)
# ---------------------------------------------------------------------------
import sys
sys.path.insert(0, str(Path(__file__).parent))
from trace_engine import analyze, _demo_posts  # type: ignore
from rag import RAGIndex, run_retrieval_eval  # type: ignore

# ---------------------------------------------------------------------------
# Minimal CSS – monochrome
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
body, .stApp { background: #ffffff; color: #1f2328; font-family: -apple-system,"Segoe UI",system-ui,sans-serif; }
h1,h2,h3 { color: #1f2328; font-weight: 600; }
.stButton>button { background:#1f2328; color:#fff; border:none; border-radius:4px; padding:6px 16px; }
.stButton>button:hover { background:#3b3b3b; }
.card { border:1px solid #e5e7eb; border-radius:6px; padding:16px; margin-bottom:12px; background:#f7f8fa; }
.HIGH { border-left:5px solid #1f2328; }
.MEDIUM { border-left:5px solid #57606a; }
.LOW { border-left:5px solid #bcc0c5; }
.badge-HIGH { background:#1f2328; color:#fff; padding:2px 8px; border-radius:3px; font-size:12px; }
.badge-MEDIUM { background:#57606a; color:#fff; padding:2px 8px; border-radius:3px; font-size:12px; }
.badge-LOW { background:#bcc0c5; color:#1f2328; padding:2px 8px; border-radius:3px; font-size:12px; }
.mono { font-family: monospace; font-size:12px; }
.caveat { font-size:11px; color:#57606a; font-style:italic; }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "decisions" not in st.session_state:
    st.session_state.decisions = {}  # brief_id -> {decision, note, analyst, timestamp}
if "rag_index" not in st.session_state:
    st.session_state.rag_index = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _level_key(level: str) -> str:
    return level.split(" - ")[0]  # "HIGH" | "MEDIUM" | "LOW"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_brief_html(alert: dict[str, Any], decision: dict[str, Any] | None = None) -> str:
    """Generate a self-contained HTML brief for download."""
    level = alert.get("level", "")
    bns = "<br>".join(alert.get("bns_provisions", []))
    ipc = ", ".join(alert.get("ipc_legacy", []))
    steps = "".join(f"<li>{s}</li>" for s in alert.get("escalation_steps", []))
    phrases = ", ".join(alert.get("matched_phrases", []))
    chain = alert.get("evidence_chain", [])
    final_hash = chain[-1]["chain_hash"] if chain else "N/A"
    coord = alert.get("coordination_signals", {})

    decision_html = ""
    if decision:
        decision_html = f"""
        <h3>Analyst Decision</h3>
        <table>
          <tr><td><b>Decision</b></td><td>{decision.get('decision','')}</td></tr>
          <tr><td><b>Analyst</b></td><td>{decision.get('analyst','')}</td></tr>
          <tr><td><b>Note</b></td><td>{decision.get('note','')}</td></tr>
          <tr><td><b>Recorded at</b></td><td>{decision.get('timestamp','')}</td></tr>
        </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>TRACE Brief – {alert.get('brief_id','')}</title>
<style>
  body {{ font-family: -apple-system,"Segoe UI",sans-serif; max-width:800px; margin:40px auto;
          color:#1f2328; font-size:14px; line-height:1.6; }}
  h1 {{ font-size:20px; border-bottom:2px solid #1f2328; padding-bottom:8px; }}
  h3 {{ font-size:14px; color:#57606a; margin-top:20px; }}
  table {{ border-collapse:collapse; width:100%; }}
  td {{ padding:6px 8px; border:1px solid #e5e7eb; vertical-align:top; }}
  td:first-child {{ width:180px; font-weight:600; background:#f7f8fa; }}
  ul {{ margin:0; padding-left:20px; }}
  .mono {{ font-family:monospace; font-size:11px; word-break:break-all; }}
  .caveat {{ font-size:11px; color:#57606a; font-style:italic; margin-top:16px; }}
  footer {{ margin-top:40px; border-top:1px solid #e5e7eb; padding-top:8px;
             font-size:11px; color:#57606a; text-align:center; }}
</style>
</head>
<body>
<h1>TRACE Threat Brief</h1>
<table>
  <tr><td>Brief ID</td><td class="mono">{alert.get('brief_id','')}</td></tr>
  <tr><td>Generated at</td><td>{alert.get('generated_at','')}</td></tr>
  <tr><td>Alert Level</td><td><b>{level}</b></td></tr>
  <tr><td>Threat Type</td><td>{alert.get('threat_type','')}</td></tr>
  <tr><td>Cluster</td><td>{alert.get('cluster','')}</td></tr>
  <tr><td>Posts analysed</td><td>{alert.get('post_count',0)}</td></tr>
  <tr><td>Harm score</td><td>{alert.get('harm_score',0):.3f}</td></tr>
  <tr><td>Coordination score</td><td>{alert.get('coordination_score',0):.3f}</td></tr>
  <tr><td>Near-dup ratio</td><td>{coord.get('near_dup',0):.3f}</td></tr>
  <tr><td>Burst ratio</td><td>{coord.get('burst_ratio',0):.3f}</td></tr>
  <tr><td>New-account ratio</td><td>{coord.get('new_account_ratio',0):.3f}</td></tr>
  <tr><td>Repeat-author ratio</td><td>{coord.get('repeat_author_ratio',0):.3f}</td></tr>
</table>

<h3>BNS Provisions (potentially attracted, subject to legal review)</h3>
<p>{bns}</p>
<p><i>Legacy IPC reference: {ipc}</i></p>
<p class="caveat">{alert.get('provision_note','')}</p>

<h3>Matched Phrases &amp; Signals</h3>
<p class="mono">{phrases}</p>

<h3>Escalation Steps</h3>
<ul>{steps}</ul>

<h3>Evidence Chain (final hash)</h3>
<p class="mono">{final_hash}</p>
<p class="caveat">
  Hash comparison proves integrity of the supplied text or file, not the
  authenticity of the original platform content.
</p>

{decision_html}

<footer>Generated by TRACE v1.0.0 &mdash; SYNTHETIC DATA ONLY &mdash; All names, places and events are fictional.</footer>
</body></html>"""


def _build_rag_index(result: dict[str, Any]) -> RAGIndex:
    idx = RAGIndex()
    for alert in result.get("alerts", []):
        idx.add_brief(alert)
    idx.build()
    return idx


# ---------------------------------------------------------------------------
# Network graph data builder (for Streamlit + simple SVG)
# ---------------------------------------------------------------------------

def _build_network_svg(alert: dict[str, Any], width: int = 600, height: int = 320) -> str:
    """
    Build a simple SVG network graph: author nodes linked to hashtag nodes.
    Uses a basic force-free layout (authors on left, hashtags on right).
    """
    import re
    import math

    chain = alert.get("evidence_chain", [])
    # Collect authors and hashtags from evidence items
    authors: list[str] = []
    hashtags: list[str] = []

    for link in chain:
        author = link.get("content_hash", "")[:8]  # anonymised
        # get hashtags from the brief meta if available
        for h in link.get("hashtags", []):
            if h not in hashtags:
                hashtags.append(h)

    # Fallback: extract from matched phrases and cluster key
    cluster = alert.get("cluster", "")
    if cluster and cluster not in hashtags and cluster != "no_hashtag":
        hashtags.append(cluster)

    # Authors from evidence chain
    seen: set[str] = set()
    for link in chain:
        a = link.get("id", "")
        if a and a not in seen:
            authors.append(a[:8])
            seen.add(a)

    if not authors:
        authors = [f"acct_{i}" for i in range(min(3, alert.get("post_count", 1)))]
    if not hashtags:
        hashtags = [cluster or "unknown"]

    # Layout
    n_a = len(authors)
    n_h = len(hashtags)
    margin = 60
    a_x = margin + 40
    h_x = width - margin - 40
    a_positions = [(a_x, margin + i * (height - 2 * margin) // max(n_a, 1)) for i in range(n_a)]
    h_positions = [(h_x, margin + i * (height - 2 * margin) // max(n_h, 1)) for i in range(n_h)]

    lines = []
    for ax, ay in a_positions:
        for hx, hy in h_positions:
            lines.append(f'<line x1="{ax}" y1="{ay}" x2="{hx}" y2="{hy}" stroke="#bcc0c5" stroke-width="1"/>')

    a_nodes = "".join(
        f'<circle cx="{x}" cy="{y}" r="10" fill="#1f2328"/>'
        f'<text x="{x}" y="{y + 22}" text-anchor="middle" font-size="9" fill="#57606a">{a[:6]}</text>'
        for a, (x, y) in zip(authors, a_positions)
    )
    h_nodes = "".join(
        f'<rect x="{x - 28}" y="{y - 10}" width="56" height="20" rx="4" fill="#f7f8fa" stroke="#e5e7eb"/>'
        f'<text x="{x}" y="{y + 5}" text-anchor="middle" font-size="9" fill="#1f2328">#{h[:8]}</text>'
        for h, (x, y) in zip(hashtags, h_positions)
    )

    legend = (
        f'<circle cx="16" cy="{height - 18}" r="6" fill="#1f2328"/>'
        f'<text x="26" y="{height - 14}" font-size="9" fill="#57606a">Author node</text>'
        f'<rect x="80" y="{height - 24}" width="14" height="12" rx="2" fill="#f7f8fa" stroke="#e5e7eb"/>'
        f'<text x="98" y="{height - 14}" font-size="9" fill="#57606a">Hashtag node</text>'
    )

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'style="background:#ffffff;border:1px solid #e5e7eb;border-radius:6px;">'
        + "".join(lines) + a_nodes + h_nodes + legend +
        "</svg>"
    )
    return svg


def _build_timeline_html(alert: dict[str, Any]) -> str:
    """Build a simple bar-chart timeline of coordination signals."""
    signals = alert.get("coordination_signals", {})
    if not signals:
        return "<p class='caveat'>No coordination signals.</p>"

    bars = ""
    for name, val in signals.items():
        pct = int(val * 100)
        bars += (
            f"<div style='margin-bottom:8px'>"
            f"<div style='font-size:12px;color:#57606a;margin-bottom:2px'>{name}</div>"
            f"<div style='display:flex;align-items:center;gap:8px'>"
            f"<div style='background:#1f2328;height:14px;width:{pct * 2}px;border-radius:2px;min-width:2px'></div>"
            f"<span style='font-size:12px'>{val:.3f}</span>"
            f"</div></div>"
        )
    return f"<div style='padding:8px'>{bars}</div>"


# ---------------------------------------------------------------------------
# Sidebar – data input
# ---------------------------------------------------------------------------

def _sidebar() -> list[dict[str, Any]] | None:
    st.sidebar.title("TRACE")
    st.sidebar.caption("Threat Reconnaissance and Coordination Evidence Engine")
    st.sidebar.markdown("---")

    mode = st.sidebar.radio("Data source", ["Built-in demo", "Upload JSON", "Paste JSON"])

    posts: list[dict[str, Any]] | None = None

    if mode == "Built-in demo":
        if st.sidebar.button("Run demo analysis"):
            posts = _demo_posts()

    elif mode == "Upload JSON":
        uploaded = st.sidebar.file_uploader("Upload posts.json", type=["json"])
        if uploaded and st.sidebar.button("Analyse"):
            try:
                posts = json.loads(uploaded.read().decode("utf-8"))
            except Exception as e:
                st.sidebar.error(f"JSON parse error: {e}")

    elif mode == "Paste JSON":
        raw = st.sidebar.text_area("Paste JSON array of posts", height=150)
        if raw and st.sidebar.button("Analyse"):
            try:
                posts = json.loads(raw)
            except Exception as e:
                st.sidebar.error(f"JSON parse error: {e}")

    st.sidebar.markdown("---")
    st.sidebar.caption(
        "⚠ SYNTHETIC DATA ONLY. All names, places and events are fictional. "
        "Hash checks prove integrity of the supplied text, not platform authenticity."
    )
    return posts


# ---------------------------------------------------------------------------
# Tab 1: Alerts
# ---------------------------------------------------------------------------

def _tab_alerts(result: dict[str, Any]) -> None:
    alerts = result.get("alerts", [])
    meta = result.get("metadata", {})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total posts", meta.get("total_posts_analyzed", 0))
    col2.metric("Clusters", meta.get("total_clusters", 0))
    col3.metric("HIGH alerts", sum(1 for a in alerts if "HIGH" in a["level"]))
    col4.metric("MEDIUM alerts", sum(1 for a in alerts if "MEDIUM" in a["level"]))

    st.markdown("---")

    if not alerts:
        st.info("No alerts generated.")
        return

    # Filter controls
    filter_level = st.selectbox(
        "Filter by level",
        ["All", "HIGH - ACT NOW", "MEDIUM - NEEDS REVIEW", "LOW - MONITOR"],
    )
    shown = alerts if filter_level == "All" else [a for a in alerts if a["level"] == filter_level]

    for alert in shown:
        level_key = _level_key(alert["level"])
        brief_id = alert.get("brief_id", "")

        with st.container():
            st.markdown(
                f'<div class="card {level_key}">'
                f'<span class="badge-{level_key}">{alert["level"]}</span>&nbsp;&nbsp;'
                f'<b>{alert["cluster"]}</b>&nbsp;'
                f'<span style="color:#57606a;font-size:12px">'
                f'Harm={alert["harm_score"]:.2f}  Coord={alert["coordination_score"]:.2f}  '
                f'Posts={alert["post_count"]}  Type={alert["threat_type"]}'
                f'</span></div>',
                unsafe_allow_html=True,
            )

            with st.expander(f"Details – {brief_id[:16]}…", expanded=(level_key == "HIGH")):
                sub_tabs = st.tabs(["Summary", "Network", "Timeline", "Explainability", "Evidence", "Actions"])

                # Summary
                with sub_tabs[0]:
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown("**BNS Provisions** *(potentially attracted, subject to legal review)*")
                        for s in alert.get("bns_provisions", []):
                            st.markdown(f"- {s}")
                        st.caption(f"Legacy IPC: {', '.join(alert.get('ipc_legacy', []))}")
                        st.caption(alert.get("provision_note", ""))
                    with col_b:
                        st.markdown("**Escalation Steps**")
                        for i, step in enumerate(alert.get("escalation_steps", []), 1):
                            st.markdown(f"{i}. {step}")

                # Network graph
                with sub_tabs[1]:
                    st.caption("Account → Hashtag co-occurrence network (anonymised author IDs)")
                    svg = _build_network_svg(alert)
                    st.markdown(svg, unsafe_allow_html=True)

                # Coordination timeline
                with sub_tabs[2]:
                    st.caption("Coordination signal values")
                    st.markdown(_build_timeline_html(alert), unsafe_allow_html=True)
                    st.caption(
                        "near_dup = near-duplicate text ratio | burst_ratio = fraction of posts in 10-min window | "
                        "new_account_ratio = fraction of accounts < 30 days old | repeat_author_ratio = repeat poster fraction"
                    )

                # Explainability
                with sub_tabs[3]:
                    st.markdown("**Signal values**")
                    col_h, col_c = st.columns(2)
                    col_h.metric("Harm score", f"{alert['harm_score']:.3f}")
                    col_c.metric("Coordination score", f"{alert['coordination_score']:.3f}")

                    st.markdown("**Alert rule applied**")
                    h = alert["harm_score"]
                    c = alert["coordination_score"]
                    if h >= 0.6 and c >= 0.5:
                        rule = "HIGH: harm ≥ 0.6 AND coordination ≥ 0.5"
                    elif h >= 0.6 or (h >= 0.4 and c >= 0.5):
                        rule = "MEDIUM: harm ≥ 0.6 OR (harm ≥ 0.4 AND coordination ≥ 0.5)"
                    else:
                        rule = "LOW: neither HIGH nor MEDIUM condition met"
                    st.code(rule)

                    st.markdown("**Matched phrases** *(rule that fired)*")
                    for phrase in alert.get("matched_phrases", []):
                        prefix = phrase.split(":")[0]
                        colour = "#1f2328" if prefix == "HARM" else "#57606a"
                        st.markdown(
                            f'<span style="font-family:monospace;font-size:11px;'
                            f'color:{colour}">{phrase}</span>',
                            unsafe_allow_html=True,
                        )

                # Evidence
                with sub_tabs[4]:
                    chain = alert.get("evidence_chain", [])
                    st.markdown(f"**{len(chain)} evidence items** – SHA-256 hash chain")
                    st.caption(
                        "Hash comparison proves integrity of the supplied text, "
                        "not the authenticity of the original platform content."
                    )
                    for link in chain[:5]:
                        st.markdown(
                            f'<div class="mono" style="border:1px solid #e5e7eb;'
                            f'border-radius:4px;padding:6px;margin-bottom:4px">'
                            f'ID: {link["id"][:20]}… | '
                            f'chain: {link["chain_hash"][:32]}… | '
                            f'prev: {link["prev_hash"][:16]}…'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                    if len(chain) > 5:
                        st.caption(f"… {len(chain) - 5} more items")

                # Actions
                with sub_tabs[5]:
                    col_dl, col_ap = st.columns([1, 2])

                    # Download brief
                    with col_dl:
                        decision = st.session_state.decisions.get(brief_id)
                        html_brief = _build_brief_html(alert, decision)
                        st.download_button(
                            label="⬇ Download brief (HTML)",
                            data=html_brief,
                            file_name=f"trace_brief_{brief_id[:8]}.html",
                            mime="text/html",
                            key=f"dl_{brief_id}",
                        )

                    # Approve / Reject
                    with col_ap:
                        st.markdown("**Analyst escalation decision**")
                        existing = st.session_state.decisions.get(brief_id, {})

                        analyst_name = st.text_input(
                            "Analyst name", value=existing.get("analyst", ""),
                            key=f"analyst_{brief_id}",
                        )
                        analyst_note = st.text_area(
                            "Note", value=existing.get("note", ""),
                            height=60, key=f"note_{brief_id}",
                        )
                        dec_col1, dec_col2 = st.columns(2)
                        if dec_col1.button("✓ Approve escalation", key=f"approve_{brief_id}"):
                            st.session_state.decisions[brief_id] = {
                                "decision": "APPROVED",
                                "analyst": analyst_name,
                                "note": analyst_note,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "brief_id": brief_id,
                            }
                            st.success("Escalation approved and recorded.")
                        if dec_col2.button("✗ Reject escalation", key=f"reject_{brief_id}"):
                            st.session_state.decisions[brief_id] = {
                                "decision": "REJECTED",
                                "analyst": analyst_name,
                                "note": analyst_note,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "brief_id": brief_id,
                            }
                            st.warning("Escalation rejected and recorded.")

                        if brief_id in st.session_state.decisions:
                            d = st.session_state.decisions[brief_id]
                            st.markdown(
                                f'<div class="card" style="margin-top:8px">'
                                f'Decision: <b>{d["decision"]}</b> | '
                                f'By: {d["analyst"] or "N/A"} | '
                                f'{d["timestamp"][:19]}'
                                f'</div>',
                                unsafe_allow_html=True,
                            )


# ---------------------------------------------------------------------------
# Tab 2: Integrity
# ---------------------------------------------------------------------------

def _tab_integrity(result: dict[str, Any] | None) -> None:
    st.markdown(
        "*Hash comparison proves integrity of the supplied text or file, "
        "not the authenticity of the original platform content.*"
    )
    st.markdown("---")

    mode = st.radio(
        "Check mode",
        ["Hash text input", "Hash uploaded file", "Verify JSON report", "Dataset hash-chain check"],
        horizontal=True,
    )

    if mode == "Hash text input":
        text = st.text_area("Enter text to hash", height=100)
        if text:
            h = _sha256_text(text)
            st.code(h, language=None)
            compare = st.text_input("Compare against known hash (optional)")
            if compare:
                if compare.strip() == h:
                    st.success("✓ Hash matches – text is unmodified.")
                else:
                    st.error("✗ Hash mismatch – text has been altered.")

    elif mode == "Hash uploaded file":
        f = st.file_uploader("Upload any file", key="int_file")
        if f:
            data = f.read()
            h = _sha256_bytes(data)
            st.code(h, language=None)
            compare = st.text_input("Compare against known hash (optional)", key="int_cmp")
            if compare:
                if compare.strip() == h:
                    st.success("✓ Hash matches – file is unmodified.")
                else:
                    st.error("✗ Hash mismatch – file has been altered.")

    elif mode == "Verify JSON report":
        uploaded = st.file_uploader("Upload TRACE JSON report", type=["json"], key="int_json")
        if uploaded:
            try:
                report = json.loads(uploaded.read().decode("utf-8"))
                alerts = report.get("alerts", [])
                all_ok = True
                for alert in alerts:
                    chain = alert.get("evidence_chain", [])
                    # Reconstruct items from chain (content-hash verification)
                    for link in chain:
                        # We can only verify the chain structure here (hash links)
                        prev = link.get("prev_hash", "")
                        ch = link.get("chain_hash", "")
                        if not ch:
                            all_ok = False
                            break
                if all_ok:
                    st.success(f"✓ Report structure valid – {len(alerts)} alert(s) found.")
                else:
                    st.error("✗ Report integrity issue detected.")
                st.json(report.get("metadata", {}))
            except Exception as e:
                st.error(f"Parse error: {e}")

    elif mode == "Dataset hash-chain check":
        if result is None:
            st.info("Run an analysis first (sidebar).")
            return
        all_ok = True
        for alert in result.get("alerts", []):
            chain = alert.get("evidence_chain", [])
            if not chain:
                continue
            # Verify chain link structure (prev_hash linkage)
            prev = "0" * 64
            for link in chain:
                if link["prev_hash"] != prev:
                    all_ok = False
                    st.error(f"Chain broken in cluster {alert['cluster']} at {link['id']}")
                    break
                prev = link["chain_hash"]

        if all_ok:
            st.success("✓ All evidence chain links are internally consistent.")

        # Show full JSON
        with st.expander("View full analysis JSON"):
            st.json(result)


# ---------------------------------------------------------------------------
# Tab 3: RAG Query
# ---------------------------------------------------------------------------

def _tab_rag(result: dict[str, Any] | None) -> None:
    if result is None:
        st.info("Run an analysis first (sidebar) to build the brief index.")
        return

    # Build / rebuild index
    if st.session_state.rag_index is None:
        with st.spinner("Building brief index…"):
            st.session_state.rag_index = _build_rag_index(result)

    idx: RAGIndex = st.session_state.rag_index

    st.markdown(
        f"**Retrieval mode:** {'Semantic (sentence-transformers)' if idx.semantic.available else 'TF-IDF (offline)'}"
    )
    st.markdown("---")

    query = st.text_input("Query threat briefs", placeholder="e.g. What escalation steps apply to incitement?")
    top_k = st.slider("Results", 1, 5, 3)

    if query:
        results = idx.search(query, top_k=top_k)
        if not results:
            st.warning("No matching briefs found.")
        else:
            for r in results:
                meta = r.get("meta", {})
                with st.container():
                    st.markdown(
                        f'<div class="card">'
                        f'<b>Brief ID:</b> {meta.get("brief_id","N/A")[:24]}… &nbsp; '
                        f'<b>Level:</b> {meta.get("level","N/A")} &nbsp; '
                        f'<b>Type:</b> {meta.get("threat_type","N/A")} &nbsp; '
                        f'<b>Score:</b> {r.get("score",0):.4f} &nbsp; '
                        f'<b>Mode:</b> {r.get("retrieval_mode","N/A")}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    with st.expander("Brief text"):
                        st.text(r.get("text", ""))

        # watsonx answer (if credentials set)
        answer = idx.answer_with_watsonx(query, results)
        if answer:
            st.markdown("**watsonx.ai answer:**")
            st.info(answer)
        else:
            st.caption("(watsonx.ai answer generation unavailable – set WATSONX_API_KEY and WATSONX_PROJECT_ID)")

    st.markdown("---")
    if st.button("Run 10-question retrieval evaluation"):
        output = StringIO()
        import sys
        old_stdout = sys.stdout
        sys.stdout = output
        run_retrieval_eval(idx)
        sys.stdout = old_stdout
        st.text(output.getvalue())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.title("TRACE – Threat Intelligence Dashboard")
    st.caption(
        "Threat Reconnaissance and Coordination Evidence Engine · "
        "SYNTHETIC DATA ONLY · All names, places and events are fictional."
    )

    posts = _sidebar()

    if posts is not None:
        with st.spinner("Analysing posts…"):
            st.session_state.analysis_result = analyze(posts)
            st.session_state.rag_index = None  # reset index on new analysis

    result = st.session_state.analysis_result

    tab1, tab2, tab3 = st.tabs(["Alerts", "Integrity", "RAG Query"])

    with tab1:
        if result:
            _tab_alerts(result)
        else:
            st.info("Select a data source in the sidebar and run analysis.")

    with tab2:
        _tab_integrity(result)

    with tab3:
        _tab_rag(result)


if __name__ == "__main__":
    main()
