"""Supervised ML evaluation with exporter-family separation and no target labels.

The final holdout is used only for reporting after training. These are
published alert definitions, NOT observed production incidents.
"""
import argparse
import csv
import json
from pathlib import Path

from app.ai import classify
from app.ml_v14 import (
    DEFAULT_FIXTURES, DEFAULT_MODEL, FINAL_FILES, TRAIN_FILES, VALIDATION_FILE,
    feature_text, read_csv, prepare_training, classify_learned, classify_ml,
)
from app.triage_v2 import classify_v2


def evaluate(name, rows, model, training_names):
    names = [row for row in rows if feature_text({"alert_name": row["alert_name"]}) not in training_names]
    collisions = len(rows) - len(names)
    if not names:
        raise ValueError("All evaluation examples overlap training!")
    results = {}
    for label, classifier in (
        ("legacy_rules", classify),
        ("offline_rules_v2", classify_v2),
        ("supervised_ml_v14", lambda alert: classify_learned(alert, model=model)),
        ("validation_selected_hybrid", lambda alert: classify_ml(alert, model=model)),
    ):
        c = s = joint = 0
        errors = []
        for row in names:
            # Do not include source-file metadata, labels, target category,
            # severity, configured thresholds or correct answers.
            predicted = classifier({"alert_name": row["alert_name"],
                                    "title": "", "description": "", "labels": {}})
            cat_ok = predicted["category"] == row["category"]
            sev_ok = predicted["severity"] == row["severity"]
            c += cat_ok
            s += sev_ok
            joint += cat_ok and sev_ok
            if not (cat_ok and sev_ok) and len(errors) < 20:
                errors.append({
                    "name": row["alert_name"],
                    "expected": [row["category"], row["severity"]],
                    "predicted": [predicted["category"], predicted["severity"]],
                })
        n = len(names)
        results[label] = {
            "category_accuracy": round(c / n, 4),
            "severity_accuracy": round(s / n, 4),
            "joint_accuracy": round(joint / n, 4),
            "joint_correct": joint,
            "sample_count": n,
            "example_errors": errors,
        }
    return {
        "name": name,
        "source": "public_prometheus_alert_rules_not_firing_incidents",
        "inputs": "alert_name_only_no_prometheus_labels_or_descriptions",
        "skipped_exact_name_collisions": collisions,
        "results": results,
    }


def main():
    from joblib import load

    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--final", action="store_true",
                        help="Explicitly evaluate untouched exporter families")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    model = load(args.model)
    train, validation = prepare_training(args.fixtures)
    train_names = {feature_text({"alert_name": row["alert_name"]}) for row in train}
    final = read_csv(args.fixtures / file for file in FINAL_FILES) if args.final else []
    if args.final:
        # No training on these exporter families, including no hyperparam tuning.
        train_groups = {r["source_file"].split("/")[2] for r in train}
        validation_groups = {r["source_file"].split("/")[2] for r in validation}
        final_groups = {r["source_file"].split("/")[2] for r in final}
        if train_groups & final_groups or validation_groups & final_groups:
            raise ValueError("Final exporter-family split is contaminated")
    evaluation = evaluate("holdout" if args.final else "validation",
                          final if args.final else validation, model, train_names)
    report = {
        "train_examples": len(train),
        "validation_examples": len(validation),
        "model_choice_based_only_on_validation": model["selected_c"],
        "model_validation": model["validation_metrics"],
        "final_holdout_evaluated": args.final,
        "evaluation": evaluation,
    }
    print(f"Training: {len(train)} | evaluation: {evaluation['name']} | "
          f"exact-name collisions removed: {evaluation['skipped_exact_name_collisions']}")
    for label, metrics in evaluation["results"].items():
        print(f"{label}: category={metrics['category_accuracy']:.1%} "
              f"severity={metrics['severity_accuracy']:.1%} "
              f"joint={metrics['joint_accuracy']:.1%} "
              f"({metrics['joint_correct']}/{metrics['sample_count']})")
    print("NOTE: published rules and exporter-proxy categories, not real incidents.")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
