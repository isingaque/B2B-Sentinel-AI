"""Generic labeled-incident quality evaluation for Sentinel AI.

Evaluates independent, reviewer-labeled incidents when the dataset exists.
No external API, DB writes or infrastructure commands. Default excludes known
target category/severity/priority labels to avoid answer leakage.
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from app.ai import classify

CATEGORIES = {"server", "network", "database", "application"}
SEVERITIES = {"critical", "warning", "info"}
PRIORITIES = {"critical": "P1", "warning": "P2", "info": "P4"}
FIELDS = ("alert_name", "title", "description", "labels_json",
          "expected_category", "expected_severity", "expected_priority")
LEAKAGE_LABELS = {"category", "severity", "priority", "incident_category",
                  "incident_severity", "predicted_category", "predicted_severity"}


def score_rows(rows, use_source_severity=False):
    score = Counter()
    category_confusion = defaultdict(Counter)
    severity_confusion = defaultdict(Counter)
    misses = []
    for index, row in enumerate(rows, start=2):
        if any(field not in row for field in FIELDS):
            raise ValueError("Missing mandatory input columns")
        expected_category = row["expected_category"].strip()
        expected_severity = row["expected_severity"].strip()
        expected_priority = row["expected_priority"].strip()
        if expected_category not in CATEGORIES or expected_severity not in SEVERITIES:
            raise ValueError(f"Invalid reference values at CSV line {index}")
        if expected_priority not in ("P1", "P2", "P3", "P4"):
            raise ValueError(f"Invalid priority at CSV line {index}")
        labels = json.loads(row["labels_json"] or "{}")
        if not isinstance(labels, dict):
            raise ValueError(f"labels_json must be an object on line {index}")
        labels = {str(k): str(v) for k, v in labels.items()}
        if not use_source_severity:
            labels = {k: v for k, v in labels.items() if k.lower() not in LEAKAGE_LABELS}
        else:
            # Always exclude the expected category and priority labels.
            labels = {k: v for k, v in labels.items() if k.lower() not in
                      (LEAKAGE_LABELS - {"severity", "incident_severity"})}
        alert = {
            "alert_name": row["alert_name"],
            "title": row["title"],
            "description": row["description"],
            "labels": labels,
        }
        prediction = classify(alert)
        results = {
            "category": prediction["category"] == expected_category,
            "severity": prediction["severity"] == expected_severity,
            "priority": prediction["priority"] == expected_priority,
        }
        score["count"] += 1
        for name, ok in results.items():
            score[name] += ok
        score["joint"] += all(results.values())
        category_confusion[expected_category][prediction["category"]] += 1
        severity_confusion[expected_severity][prediction["severity"]] += 1
        if not all(results.values()):
            misses.append({
                "alert_name": row["alert_name"],
                "expected": {"category": expected_category, "severity": expected_severity, "priority": expected_priority},
                "predicted": {k: prediction[k] for k in ("category", "severity", "priority")},
            })
    if not score["count"]:
        raise ValueError("No labeled incidents")
    count = score["count"]
    return {
        "count": count,
        "mode": "include_source_severity" if use_source_severity else "independent_prediction",
        "category_accuracy": round(score["category"] / count, 4),
        "severity_accuracy": round(score["severity"] / count, 4),
        "priority_accuracy": round(score["priority"] / count, 4),
        "joint_accuracy": round(score["joint"] / count, 4),
        "category_confusion": {k: dict(v) for k, v in category_confusion.items()},
        "severity_confusion": {k: dict(v) for k, v in severity_confusion.items()},
        "incorrect": misses,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate labeled incident CSV")
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--include-source-severity", action="store_true",
                        help="Operational mode, NOT an independent severity test")
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero unless >=100 cases and >=90% exact joint accuracy")
    args = parser.parse_args()
    with args.csv.open(encoding="utf-8-sig", newline="") as handle:
        report = score_rows(csv.DictReader(handle), args.include_source_severity)
    for key in ("category_accuracy", "severity_accuracy", "priority_accuracy", "joint_accuracy"):
        print(f"{key}: {report[key]:.1%}")
    print("Cases:", report["count"], "| Mode:", report["mode"])
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.strict:
        if report["count"] < 100 or report["joint_accuracy"] < .90:
            raise SystemExit("NOT PASSED: requires >=100 cases and >=90% joint accuracy")
        print("Numeric gate passed. Verify source independence separately.")


if __name__ == "__main__":
    main()
