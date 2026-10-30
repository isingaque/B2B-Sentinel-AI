"""Reproducible evaluation on published Prometheus alert-rule definitions.

This is NOT an industrial incident benchmark. Published rules are not real
firing incidents; no event description/PromQL/labels are given to classifier.
The category label is a curator proxy based on exporter family.
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from app.ai import classify
from app.triage_v2 import classify_v2

DATASET = Path(__file__).resolve().parents[1] / "backend" / "tests" / "fixtures" / "public_prometheus_rules.csv"
EXPECTED_CATEGORIES = {"server", "network", "database", "application"}
EXPECTED_SEVERITIES = {"critical", "warning", "info"}
PRIORITY_FOR_SEVERITY = {"critical": "P1", "warning": "P2", "info": "P4"}


def evaluate(rows, classifier=classify):
    totals = Counter()
    category_confusion = defaultdict(Counter)
    severity_confusion = defaultdict(Counter)
    by_source = defaultdict(Counter)
    errors = []
    for row in rows:
        alert_name = row["alert_name"]
        category = row["category"]
        severity = row["severity"]
        if category not in EXPECTED_CATEGORIES or severity not in EXPECTED_SEVERITIES:
            raise ValueError("Unrecognized reference label: " + alert_name)
        # No category or severity labels: prevent target leakage.
        prediction = classifier({"alert_name": alert_name, "title": "", "description": "", "labels": {}})
        category_ok = prediction["category"] == category
        severity_ok = prediction["severity"] == severity
        priority_ok = prediction["priority"] == PRIORITY_FOR_SEVERITY[severity]
        joint_ok = category_ok and severity_ok and priority_ok
        totals["total"] += 1
        totals["category_correct"] += category_ok
        totals["severity_correct"] += severity_ok
        totals["priority_correct"] += priority_ok
        totals["joint_correct"] += joint_ok
        category_confusion[category][prediction["category"]] += 1
        severity_confusion[severity][prediction["severity"]] += 1
        by_source[row["source_file"]]["total"] += 1
        by_source[row["source_file"]]["joint_correct"] += joint_ok
        if not joint_ok:
            errors.append({
                "alert_name": alert_name,
                "expected": f"{category}/{severity}/{PRIORITY_FOR_SEVERITY[severity]}",
                "predicted": f"{prediction['category']}/{prediction['severity']}/{prediction['priority']}",
                "source_file": row["source_file"],
            })

    n = totals["total"]
    if not n:
        raise ValueError("Empty benchmark")
    return {
        "dataset": str(DATASET.name),
        "dataset_kind": "published_alert_rules_not_firing_incidents",
        "inputs": "alert_name_only_no_labels_or_descriptions",
        "sample_count": n,
        "category_accuracy": round(totals["category_correct"] / n, 4),
        "severity_accuracy": round(totals["severity_correct"] / n, 4),
        "priority_accuracy": round(totals["priority_correct"] / n, 4),
        "joint_accuracy": round(totals["joint_correct"] / n, 4),
        "category_confusion": {k: dict(v) for k, v in category_confusion.items()},
        "severity_confusion": {k: dict(v) for k, v in severity_confusion.items()},
        "by_source": {k: dict(v) for k, v in by_source.items()},
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path, help="Optional local report path")
    parser.add_argument("--engine", choices=("legacy", "v2"), default="legacy")
    parser.add_argument("--dataset", type=Path, default=DATASET,
                        help="Override the CSV path (useful inside Docker)")
    args = parser.parse_args()
    with args.dataset.open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    report = evaluate(rows, classifier=classify_v2 if args.engine == "v2" else classify)
    report["engine"] = args.engine
    report["dataset"] = str(args.dataset.name)
    print(f"Published rules: {report['sample_count']} (NOT observed incidents)")
    print("Input: alert name only; no source category or severity hints")
    for metric in ("category_accuracy", "severity_accuracy", "priority_accuracy", "joint_accuracy"):
        print(f"{metric}: {report[metric]:.1%}")
    print(f"Mismatches: {len(report['errors'])}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Report written: {args.json_out}")


if __name__ == "__main__":
    main()
