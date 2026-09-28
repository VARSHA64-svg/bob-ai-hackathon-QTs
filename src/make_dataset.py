"""
make_dataset.py
Generates a synthetic labelled dataset for TRACE evaluation.

Scenarios (7):
  S1  Hinglish incitement campaign (#ChowkAlert) – HIGH
  S2  Targeted harassment campaign (#SilenceHer) – HIGH
  S3  Organised misinfo campaign (#VaccineLie) – HIGH
  S4  Coordinated-only (low-harm, high-coordination) (#BotsUnite) – MEDIUM
  S5  Reporting / journalism cluster (#MarketSquareNews) – LOW
  S6  Single high-harm post (no coordination) – MEDIUM
  S7  Misinfo with some Hinglish phrases (#SazishHai) – HIGH
  BG  Background noise (no threat) – LOW

Usage:
  python make_dataset.py              # seed=42, writes data/
  python make_dataset.py --seed 99    # alternate seed
"""
from __future__ import annotations

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(base: datetime, offset_minutes: float) -> str:
    return (base + timedelta(minutes=offset_minutes)).isoformat()


def _post(
    pid: str,
    author: str,
    age_days: int,
    ts: str,
    text: str,
    comments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    p: dict[str, Any] = {
        "id": pid,
        "author": author,
        "account_age_days": age_days,
        "timestamp": ts,
        "text": text,
    }
    if comments:
        p["comments"] = comments
    return p


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def _scenario_s1(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S1 – Hinglish incitement (#ChowkAlert). Expected: HIGH."""
    posts = []
    incite_texts = [
        "Chowk mein ikattho! Nikalo unhe, ghar jalao! #ChowkAlert #ActionNow",
        "Aaj raat sab milte hain – khatam karo unhe! #ChowkAlert",
        "Maar do inhe, khoon bahega toh theek hai! #ChowkAlert #ActionNow",
        "Danga karo, bhago mat! Badla lo! #ChowkAlert",
        "Inko bhagao ghar se, laal kar do sadak! #ChowkAlert #ActionNow",
        "Inke ghar jalao! #ChowkAlert",
        "Gaddaron ko maut chahiye! #ChowkAlert #ActionNow",
        "Jala do unka daftar! Sangharsh karo! #ChowkAlert",
    ]
    for i, txt in enumerate(incite_texts):
        age = rng.randint(2, 15)
        offset = rng.uniform(0, 8)
        pid = f"s1_{i:03d}"
        author = f"acct_{rng.randint(1000, 1099)}"
        coms = []
        if i % 3 == 0:
            coms = [
                {
                    "id": f"{pid}_c1",
                    "author": f"acct_{rng.randint(1100, 1199)}",
                    "account_age_days": rng.randint(1, 10),
                    "timestamp": _ts(base, offset + 0.5),
                    "text": f"Bilkul sahi! Badla lo! #ChowkAlert",
                }
            ]
        posts.append(_post(pid, author, age, _ts(base, offset), txt, coms))

    label = {"scenario": "S1", "cluster_key": "chowkalert", "expected_level": "HIGH - ACT NOW",
              "expected_threat_type": "incitement"}
    return posts, label


def _scenario_s2(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S2 – Targeted harassment (#SilenceHer). Expected: HIGH."""
    target = "journalist_priya_fictitious"
    posts = []
    harass_texts = [
        f"@{target} your address is public now. Watch your back. #SilenceHer",
        f"Coming for you @{target}. No mercy. #SilenceHer",
        f"Dox her – find every detail about @{target} #SilenceHer",
        f"Bomb threat sent to @{target}'s office. #SilenceHer",
        f"We know where you live @{target}. You will regret this. #SilenceHer",
        f"Rape threat: @{target} deserves what's coming. #SilenceHer",
        f"Stalking starts today @{target} #SilenceHer",
    ]
    for i, txt in enumerate(harass_texts):
        age = rng.randint(1, 20)
        offset = rng.uniform(0, 6)
        pid = f"s2_{i:03d}"
        author = f"anon_{rng.randint(2000, 2099)}"
        posts.append(_post(pid, author, age, _ts(base, offset), txt))

    label = {"scenario": "S2", "cluster_key": "silenceher", "expected_level": "HIGH - ACT NOW",
              "expected_threat_type": "targeted_harassment"}
    return posts, label


def _scenario_s3(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S3 – Organised misinfo (#VaccineLie). Expected: HIGH.

    Uses near-duplicate templates + burst + new accounts to push coordination ≥ 0.5.
    """
    posts = []
    # Near-duplicate template: same structure, slight wording variation
    misinfo_template = (
        "They are poisoning the water supply – government is hiding the truth! "
        "Fabricated evidence exposed. Media lies! #VaccineLie"
    )
    misinfo_variants = [
        "They are poisoning the water supply – government is hiding the truth! "
        "Fabricated evidence everywhere. Media lies! #VaccineLie",
        "They are poisoning the water supply – the government is hiding deaths! "
        "Fabricated evidence exposed – media lies #VaccineLie",
        "They are poisoning the water supply – government hiding truth! "
        "Fake khabar spread by officials. #VaccineLie",
        "They are poisoning the water supply – government is hiding this! "
        "Crisis actor caught. Media lies confirmed. #VaccineLie",
        "They are poisoning the water supply – rigged election cover-up! "
        "Fabricated report exposed. Media lies! #VaccineLie",
        "They are poisoning the water supply – deep state plandemic! "
        "Scamdemic – government hiding real numbers. #VaccineLie",
        "They are poisoning the water supply – sarkar chhupa rahi hai! "
        "Sazish hai – media bikau hai. #VaccineLie",
        "They are poisoning the water supply – stolen votes real! "
        "Government is hiding evidence. False flag! #VaccineLie",
        misinfo_template,
    ]
    for i, txt in enumerate(misinfo_variants):
        age = rng.randint(2, 20)  # new accounts
        offset = rng.uniform(0, 8)  # within 8 minutes → burst
        pid = f"s3_{i:03d}"
        # Repeat a few authors to boost repeat_author_ratio
        author = f"bot_{rng.randint(3000, 3009)}"  # narrow pool → repeats
        posts.append(_post(pid, author, age, _ts(base, offset), txt))

    label = {"scenario": "S3", "cluster_key": "vaccinelie", "expected_level": "HIGH - ACT NOW",
              "expected_threat_type": "organized_misinformation"}
    return posts, label


def _scenario_s4(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S4 – Coordinated inauthentic, moderate harm (#BotsUnite). Expected: MEDIUM.

    Harm stays in [0.4, 0.6) via 'attack the system' and high coordination triggers MEDIUM.
    """
    posts = []
    # Near-duplicate texts with mild incitement; all within 10 minutes; new accounts
    base_text = "Topple the system – take them down! Join us now. #BotsUnite"
    for i in range(12):
        age = rng.randint(1, 7)
        # All within 8 minutes to trigger burst
        offset = rng.uniform(0, 8)
        pid = f"s4_{i:03d}"
        author = f"bot_{rng.randint(4000, 4099)}"
        # Near-duplicate texts
        variant = base_text + f" – post {i}"
        posts.append(_post(pid, author, age, _ts(base, offset), variant))

    label = {"scenario": "S4", "cluster_key": "botsunite", "expected_level": "MEDIUM - NEEDS REVIEW",
              "expected_threat_type": "coordinated_inauthentic"}
    return posts, label


def _scenario_s5(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S5 – Journalism / reporting (#MarketSquareNews). Expected: LOW."""
    posts = []
    reporting_texts = [
        "Police say: rumours of attack reported near Market Square. Stay calm. #MarketSquareNews",
        "Breaking news: authorities say situation under control. We condemn any violence. #MarketSquareNews",
        "Journalists on the ground – unverified reports of disturbance. #MarketSquareNews",
        "Media reported that alleged incident occurred; police are investigating. #MarketSquareNews",
        "We condemn the attack and call for peace – officials urge calm. #MarketSquareNews",
        "According to police, the rumours of mass violence are false. #MarketSquareNews",
        "Officials say: no credible threat; strongly condemn hate speech. #MarketSquareNews",
        "News reports: condemnable acts reported, authorities respond. #MarketSquareNews",
    ]
    for i, txt in enumerate(reporting_texts):
        age = rng.randint(200, 2000)  # established accounts
        offset = rng.uniform(0, 120)  # spread over 2 hours, not a burst
        pid = f"s5_{i:03d}"
        author = f"reporter_{rng.randint(5000, 5099)}"
        posts.append(_post(pid, author, age, _ts(base, offset), txt))

    label = {"scenario": "S5", "cluster_key": "marketsquarenews", "expected_level": "LOW - MONITOR",
              "expected_threat_type": "coordinated_inauthentic"}
    return posts, label


def _scenario_s6(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S6 – Single high-harm post, no coordination. Expected: MEDIUM."""
    posts = [
        _post(
            "s6_000",
            f"lone_{rng.randint(6000, 6099)}",
            rng.randint(30, 500),
            _ts(base, 0),
            "Those traitors must die – kill them all and burn their homes! No hashtag needed.",
        )
    ]
    label = {"scenario": "S6", "cluster_key": "no_hashtag", "expected_level": "MEDIUM - NEEDS REVIEW",
              "expected_threat_type": "incitement"}
    return posts, label


def _scenario_s7(rng: random.Random, base: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """S7 – Hinglish misinfo + incitement (#SazishHai). Expected: HIGH."""
    posts = []
    mixed_texts = [
        "Ye sab jhooth hai – sarkar chhupa rahi hai asli baat #SazishHai",
        "Sazish hai yaar! Media bikau hai, danga failana chahte hain #SazishHai",
        "Andar ki baat: fake khabar failai ja rahi hai #SazishHai",
        "Natak kar rahe hain – fake election results #SazishHai",
        "Government is hiding evidence – media lies confirmed #SazishHai",
        "Danga karo! Sarkar ke khilaf uthho! #SazishHai",
        "Maar do jo rok rahe hain! Khatam karo system ko! #SazishHai",
    ]
    for i, txt in enumerate(mixed_texts):
        age = rng.randint(3, 25)
        offset = rng.uniform(0, 7)
        pid = f"s7_{i:03d}"
        author = f"troll_{rng.randint(7000, 7099)}"
        posts.append(_post(pid, author, age, _ts(base, offset), txt))

    label = {"scenario": "S7", "cluster_key": "sazishhai", "expected_level": "HIGH - ACT NOW",
             "expected_threat_type": "organized_misinformation"}
    return posts, label


def _background_noise(rng: random.Random, base: datetime, n: int = 50) -> list[dict[str, Any]]:
    """Background posts that should produce LOW alerts only."""
    noise_texts = [
        "Beautiful sunset today #Nature #Photography",
        "Great match last night! #Cricket #Sports",
        "Recipe for dal makhani – share if you like it #Food #Cooking",
        "Traffic jam on the highway today #Commute",
        "Happy birthday to my friend Rohan (fictional)! #Celebration",
        "Just finished reading a great novel #Books",
        "Weather is lovely this morning #Morning",
        "Excited for the weekend trip #Travel",
        "New café opened downtown – must visit #FoodReview",
        "Study tips for competitive exams #Education",
        "Yoga session was refreshing today #Wellness",
        "My cat discovered the sofa #Pets #Funny",
        "Film review: the new thriller was gripping #Movies",
        "Startup advice from a mentor – thread #Entrepreneurship",
        "River cleanup drive – volunteers welcome #Environment",
    ]
    posts = []
    for i in range(n):
        txt = rng.choice(noise_texts)
        age = rng.randint(100, 3000)
        offset = rng.uniform(0, 480)
        pid = f"bg_{i:03d}"
        author = f"user_{rng.randint(9000, 9999)}"
        posts.append(_post(pid, author, age, _ts(base, offset), txt))
    return posts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def make_dataset(seed: int = 42, out_dir: str = "data") -> None:
    rng = random.Random(seed)
    base = datetime(2024, 6, 15, 8, 0, 0, tzinfo=timezone.utc)

    os.makedirs(out_dir, exist_ok=True)

    all_posts: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    for builder in [_scenario_s1, _scenario_s2, _scenario_s3,
                    _scenario_s4, _scenario_s5, _scenario_s6, _scenario_s7]:
        scenario_base = base + timedelta(hours=rng.randint(0, 48))
        posts, label = builder(rng, scenario_base)
        all_posts.extend(posts)
        labels.append(label)

    noise = _background_noise(rng, base + timedelta(hours=72), n=50)
    all_posts.extend(noise)

    # Write files
    with open(os.path.join(out_dir, "posts.json"), "w", encoding="utf-8") as fh:
        json.dump(all_posts, fh, indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump(labels, fh, indent=2, ensure_ascii=False)

    print(f"[make_dataset] seed={seed} -> {len(all_posts)} posts, {len(labels)} labels -> {out_dir}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic TRACE dataset")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-dir", type=str, default="data")
    args = parser.parse_args()
    make_dataset(seed=args.seed, out_dir=args.out_dir)
