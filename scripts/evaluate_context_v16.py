"""Evaluate full-context text classification on source-disjoint alert definitions.

This is not a production incident evaluation. PromQL is a *separate* shadow
experiment: expressions are NOT present in live /api/v1/alerts payloads.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import confusion_matrix, f1_score

from app.ai import classify as legacy
from app.triage_v2 import classify_v2
from app.ml_v16 import CORPUS_DIR, MODEL_PATH, read_rows, split_corpus, text_of
from app.ml_v14 import feature_text

CATS = ["application", "database", "network", "server"]
SEVS = ["critical", "info", "warning"]


def evaluate(rows, model):
    methods = ("legacy", "rules_v2", "ml_annotation_context", "ml_with_promql_research")
    counts = {name: Counter() for name in methods}
    guesses = {name: {"cat": [], "sev": [], "errors": []} for name in methods}
    actual_cat, actual_sev = [], []

    for row in rows:
        alert = {
            "alert_name": row["alert_name"], "title": row["summary"],
            "description": row["description"], "labels": {},
        }
        production_text = text_of(row)
        promql_text = text_of(row, True)
        m1, m2 = model["modes"]["production_text"], model["modes"]["promql_research"]
        prior = legacy(alert)
        v2 = classify_v2(alert)
        predictions = {
            "legacy": (prior["category"], prior["severity"]),
            "rules_v2": (v2["category"], v2["severity"]),
            "ml_annotation_context": (
                str(m1["category"].predict([production_text])[0]),
                str(m1["severity"].predict([production_text])[0]),
            ),
            "ml_with_promql_research": (
                str(m2["category"].predict([promql_text])[0]),
                str(m2["severity"].predict([promql_text])[0]),
            ),
        }
        actual_cat.append(row["category"])
        actual_sev.append(row["severity"])
        for name in methods:
            cat, sev = predictions[name]
            count = counts[name]
            guess = guesses[name]
            count["category_correct"] += cat == row["category"]
            count["severity_correct"] += sev == row["severity"]
            count["joint_correct"] += (
                cat == row["category"] and sev == row["severity"]
            )
            guess["cat"].append(cat)
            guess["sev"].append(sev)
            if (cat != row["category"] or sev != row["severity"]) and len(
                    guess["errors"]) < 30:
                guess["errors"].append({
                    "name": row["alert_name"],
                    "source": row["source_file"],
                    "expected": [row["category"], row["severity"]],
                    "predicted": [cat, sev],
                })
    n = len(rows)
    if not n:
        raise ValueError("No records")
    return {
        "size": n,
        "category_distribution": dict(Counter(actual_cat)),
        "severity_distribution": dict(Counter(actual_sev)),
        "metrics": {
            key: {
                "category_accuracy": round(counts[key]["category_correct"] / n, 4),
                "severity_accuracy": round(counts[key]["severity_correct"] / n, 4),
                "joint_exact_match": round(counts[key]["joint_correct"] / n, 4),
                "joint_correct": counts[key]["joint_correct"],
                "category_macro_f1": round(f1_score(
                    actual_cat, guesses[key]["cat"], labels=CATS,
                    average="macro", zero_division=0), 4),
                "severity_macro_f1": round(f1_score(
                    actual_sev, guesses[key]["sev"], labels=SEVS,
                    average="macro", zero_division=0), 4),
                "category_confusion": {
                    "labels": CATS,
                    "matrix": confusion_matrix(
                        actual_cat, guesses[key]["cat"], labels=CATS).tolist(),
                },
                "severity_confusion": {
                    "labels": SEVS,
                    "matrix": confusion_matrix(
                        actual_sev, guesses[key]["sev"], labels=SEVS).tolist(),
                },
                "example_mismatches": guesses[key]["errors"],
            }
            for key in methods
        },
    }


def main():
    from joblib import load

    parser = argparse.ArgumentParser()
    parser.add_argument("--final", action="store_true",
                        help="Unlock final frozen sample after training")
    parser.add_argument("--fixtures", type=Path, default=CORPUS_DIR)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    train, validation = split_corpus(args.fixtures)
    model = load(args.model)  # Locally generated trusted model only.
    final = read_rows(args.fixtures / "ml_v16_holdout.csv") if args.final else []
    if args.final:
        if any(row["split"] != "holdout" for row in final):
            raise ValueError("Holdout contains non-holdout samples")
        group = lambda row: row["source_file"].split("/")[2]
        train_val_groups = {group(row) for row in train + validation}
        if any(group(row) in train_val_groups for row in final):
            raise ValueError("Holdout exporter overlaps training or validation")
    rows = final if args.final else validation
    seen = {feature_text({"alert_name": row["alert_name"]}) for row in train}
    duplicates = [row["alert_name"] for row in rows if
                  feature_text({"alert_name": row["alert_name"]}) in seen]
    if duplicates:
        raise ValueError("Name collision with training; evaluation invalid")
    report = evaluate(rows, model)
    report["test"] = "final_source_group_holdout" if args.final else "validation"
    report["dataset_type"] = "public_alert_definitions_not_observed_incidents"
    report["training_examples"] = len(train)
    report["heldout_source_labels_provided_to_model"] = False
    report["model_choice_based_on_validation_only"] = {
        k: v["chosen_c"] for k, v in model["modes"].items()
    }
    for name, metrics in report["metrics"].items():
        print(f"{name}: category={metrics['category_accuracy']:.1%} "
              f"severity={metrics['severity_accuracy']:.1%} "
              f"joint={metrics['joint_exact_match']:.1%} "
              f"({metrics['joint_correct']}/{report['size']})")
    print(f"Dataset: {report['size']} published alert rules; "
          "PromQL mode is NOT available via live /api/v1/alerts.")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2,
                             ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
