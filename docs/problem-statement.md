# Problem Statement

## Background

Social media platforms have become primary vectors for coordinating real-world violence, spreading targeted harassment, and amplifying dangerous misinformation — particularly in multilingual, high-density regions like South Asia. Threats are increasingly expressed in **Hinglish** (Hindi-English code-switching), making them invisible to English-only moderation tools. Law enforcement and platform trust-and-safety teams must monitor vast volumes of posts in near-real-time to detect coordinated harmful activity before it escalates offline.

---

## The Problem

Analysts and law enforcement officers have no unified tool to **simultaneously detect both the harmfulness and the coordination** of social media activity. Identifying a single violent post is tractable — but identifying that 40 accounts, created within the last week, posted near-identical incitement content within an 8-minute window, referencing the same hashtag, while using Hinglish phrasing to evade keyword filters — requires cross-signal reasoning that no lightweight, deployable tool currently provides.

---

## Who is Affected

- **Law enforcement cyber cells** monitoring social media for pre-riot incitement and mob coordination.
- **Platform trust-and-safety analysts** triaging thousands of flagged posts daily with limited multilingual support.
- **Journalists and civil society researchers** tracking coordinated inauthentic behaviour (bot networks, astroturfing campaigns).
- **Government CERT / public safety teams** needing rapid, legally-grounded escalation guidance when threats emerge.

---

## Why It Matters

| Impact | Detail |
|---|---|
| **Safety risk** | Undetected coordinated incitement has directly preceded real-world mob violence and riots |
| **Speed gap** | Manual review of a 50-post hashtag cluster takes 30–60 minutes; automated triage can reduce this to seconds |
| **Language gap** | English-only NLP misses Hinglish phrases like *"maar do"*, *"ghar jalao"*, *"danga karo"* — direct incitement to violence |
| **Legal gap** | Analysts lack on-the-spot mapping of flagged content to applicable legal provisions (BNS / IPC), delaying FIR filing |
| **Evidence gap** | Screenshot-based evidence is tamper-prone; there is no integrity-verified chain of custody for digital posts |

---

## Why Existing Solutions Fall Short

| Existing Approach | Limitation |
|---|---|
| **Platform content moderation** | Reactive, not proactive; English-centric; does not surface coordination signals across accounts |
| **Manual OSINT analysis** (Maltego, SpiderFoot) | Requires expert operators; time-intensive; no automated harm + coordination scoring |
| **Generic NLP classifiers** | Trained on English corpora; fail on Hinglish code-switching; no coordination layer |
| **Social listening tools** (Brandwatch, Meltwater) | Built for marketing analytics, not threat detection; no legal provision mapping |
| **Screenshot evidence** | No cryptographic integrity; inadmissible or challengeable; no audit trail |

**TRACE** addresses all five gaps in a single, deployable, open-source pipeline — combining multilingual harm scoring, coordination detection, SHA-256 evidence chaining, BNS/IPC legal mapping, and RAG-powered analyst Q&A in one tool.
