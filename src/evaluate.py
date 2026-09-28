"""
evaluate.py
Multi-seed evaluation of the TRACE engine against ground-truth labels.

Usage:
  python evaluate.py               # seeds 42, 99, 7, 2024, 1337
  python evaluate.py --seeds 42 99 # custom seeds
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any

# Allow running from project root
sys.path.insert(0, os.path.dirname(__file__))

from make_dataset import make_dataset
from trace_engine import analyze


LEVEL_ORDER = {"HIGH - ACT NOW": 0, "MEDIUM - NEEDS REVIEW": 1, "LOW - MONITOR": 2}
DEFAULT_SEEDS = [42, 99, 7, 2024, 1337]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_seed(seed: int) -> dict[str, Any]:
    """Generate data for seed, run analysis, return per-scenario results."""
    out_dir = f"data/seed_{seed}"
    make_dataset(seed=seed, out_dir=out_dir)

    with open(os.path.join(out_dir, "posts.json"), encoding="utf-8") as fh:
        posts = json.load(fh)
    with open(os.path.join(out_dir, "ground_truth.json"), encoding="utf-8") as fh:
        ground_truth: list[dict[str, Any]] = json.load(fh)

    result = analyze(posts)
    alert_map: dict[str, dict[str, Any]] = {
        a["cluster"].lower(): a for a in result["alerts"]
    }

    scenario_results = []
    for label in ground_truth:
        cluster_key = label["cluster_key"].lower()
        expected_level = label["expected_level"]
        scenario = label["scenario"]

        # Find alert for this cluster
        alert = alert_map.get(cluster_key)
        if alert is None:
            predicted_level = "LOW - MONITOR"  # missing cluster -> treated as no alert
        else:
            predicted_level = alert["level"]

        correct = predicted_level == expected_level
        scenario_results.append({
            "scenario": scenario,
            "cluster": cluster_key,
            "expected": expected_level,
            "predicted": predicted_level,
            "correct": correct,
            "harm_score": alert["harm_score"] if alert else 0.0,
            "coord_score": alert["coordination_score"] if alert else 0.0,
        })

    # Background: any non-scenario cluster should be LOW
    scenario_clusters = {l["cluster_key"].lower() for l in ground_truth}
    false_alarms = [
        a for a in result["alerts"]
        if a["cluster"].lower() not in scenario_clusters
        and a["level"] != "LOW - MONITOR"
    ]

    return {
        "seed": seed,
        "scenario_results": scenario_results,
        "false_alarm_count": len(false_alarms),
        "false_alarms": false_alarms,
        "total_alerts": len(result["alerts"]),
    }


def _precision_recall(
    results: list[dict[str, Any]], level: str
) -> tuple[float, float]:
    """Compute precision and recall for a specific alert level."""
    tp = sum(1 for r in results if r["expected"] == level and r["predicted"] == level)
    fp = sum(1 for r in results if r["expected"] != level and r["predicted"] == level)
    fn = sum(1 for r in results if r["expected"] == level and r["predicted"] != level)
    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    return round(precision, 2), round(recall, 2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def evaluate(seeds: list[int]) -> None:
    all_seed_results: list[dict[str, Any]] = []

    for seed in seeds:
        print(f"\n{'='*60}")
        print(f"  Seed {seed}")
        print(f"{'='*60}")
        seed_result = _run_seed(seed)
        all_seed_results.append(seed_result)

        results = seed_result["scenario_results"]
        passed = sum(1 for r in results if r["correct"])
        print(f"  Pass: {passed}/{len(results)}  |  False alarms: {seed_result['false_alarm_count']}")
        print()
        print(f"  {'Scenario':<6} {'Cluster':<22} {'Expected':<25} {'Predicted':<25} {'H':>5} {'C':>5}  OK?")
        print(f"  {'-'*6} {'-'*22} {'-'*25} {'-'*25} {'-'*5} {'-'*5}  {'-'*4}")
        for r in results:
            ok = "OK" if r["correct"] else "FAIL"
            print(
                f"  {r['scenario']:<6} {r['cluster']:<22} {r['expected']:<25} "
                f"{r['predicted']:<25} {r['harm_score']:>5.2f} {r['coord_score']:>5.2f}  {ok}"
            )

        print()
        for level in ["HIGH - ACT NOW", "MEDIUM - NEEDS REVIEW", "LOW - MONITOR"]:
            p, r = _precision_recall(results, level)
            lbl = level.split(" - ")[0]
            p_str = f"{p:.2f}" if p == p else "N/A"
            r_str = f"{r:.2f}" if r == r else "N/A"
            print(f"  {lbl:<8}  precision={p_str}  recall={r_str}")

    # Aggregate across seeds
    print(f"\n{'='*60}")
    print("  AGGREGATE (all seeds)")
    print(f"{'='*60}")

    # Collect per-scenario across seeds
    per_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sr in all_seed_results:
        for r in sr["scenario_results"]:
            per_scenario[r["scenario"]].append(r)

    print(f"\n  {'Scenario':<8} {'Cluster':<22} {'Pass Rate':>10}  {'Avg H':>6}  {'Avg C':>6}")
    print(f"  {'-'*8} {'-'*22} {'-'*10}  {'-'*6}  {'-'*6}")
    for scen, rs in sorted(per_scenario.items()):
        pass_rate = sum(1 for r in rs if r["correct"]) / len(rs)
        avg_h = sum(r["harm_score"] for r in rs) / len(rs)
        avg_c = sum(r["coord_score"] for r in rs) / len(rs)
        print(f"  {scen:<8} {rs[0]['cluster']:<22} {pass_rate:>10.0%}  {avg_h:>6.3f}  {avg_c:>6.3f}")

    all_results_flat = [r for sr in all_seed_results for r in sr["scenario_results"]]
    total_fa = sum(sr["false_alarm_count"] for sr in all_seed_results)

    print()
    for level in ["HIGH - ACT NOW", "MEDIUM - NEEDS REVIEW", "LOW - MONITOR"]:
        p, r = _precision_recall(all_results_flat, level)
        lbl = level.split(" - ")[0]
        p_str = f"{p:.2f}" if p == p else "N/A"
        r_str = f"{r:.2f}" if r == r else "N/A"
        print(f"  {lbl:<8}  precision={p_str}  recall={r_str}")

    print(f"\n  Total false alarms across all seeds: {total_fa}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate TRACE engine")
    parser.add_argument(
        "--seeds", type=int, nargs="+", default=DEFAULT_SEEDS,
        help="Random seeds to evaluate (default: 42 99 7 2024 1337)"
    )
    args = parser.parse_args()
    evaluate(args.seeds)
