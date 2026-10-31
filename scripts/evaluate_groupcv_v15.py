"""Reproducible cross-exporter assessment of Sentinel AI classification.

GroupKFold keeps exporters together; train/test never share a named alert.
Results are exploratory: model choice / hyperparameters were tuned in earlier
versions on subsets of these public configurations.

These are published alert *definitions*, not actual firing incidents.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import (
    accuracy_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import GroupKFold

from app.ai import classify as classify_legacy
from app.triage_v2 import classify_v2
from app.ml_v14 import (
    DEFAULT_FIXTURES, TRAIN_FILES, VALIDATION_FILE, FINAL_FILES,
    feature_text, read_csv, build_pipeline,
)

LABEL_CATEGORIES = ["application", "database", "network", "server"]
LABEL_SEVERITIES = ["critical", "info", "warning"]
MODEL_C = 4.0  # frozen selection from the preceding v1.4 experiment
N_SPLITS = 5


def evaluate(fixtures_dir=DEFAULT_FIXTURES):
    folder = Path(fixtures_dir)
    filenames = (*TRAIN_FILES, VALIDATION_FILE, *FINAL_FILES)
    rows = read_csv(folder / name for name in filenames)
    if not rows:
        raise ValueError("Empty dataset")

    groups = [row["source_file"].split("/")[2] for row in rows]
    features = [feature_text({"alert_name": row["alert_name"]}) for row in rows]
    categories = [row["category"] for row in rows]
    severities = [row["severity"] for row in rows]
    if not set(categories).issubset(LABEL_CATEGORIES):
        raise ValueError("Unknown category labels")
    if not set(severities).issubset(LABEL_SEVERITIES):
        raise ValueError("Unknown severity labels")

    outputs = {engine: [] for engine in (
        "legacy", "offline_v2", "learned_svm", "hybrid_rules_category_svm_severity"
    )}
    gt_categories, gt_severities = [], []
    fold_details = []
    cross_val = GroupKFold(n_splits=N_SPLITS)

    for fold, (train_idx, test_idx) in enumerate(
            cross_val.split(features, categories, groups), start=1):
        test_groups = {groups[i] for i in test_idx}
        train_groups = {groups[i] for i in train_idx}
        if train_groups & test_groups:
            raise AssertionError("Exporter family leaked across fold boundary")
        # No training on alerts that share normalized name with any test
        # example, even when their exporter family differs.
        test_names = {features[i] for i in test_idx}
        train_idx = [i for i in train_idx if features[i] not in test_names]
        if not train_idx:
            raise ValueError("No training examples after removal of duplicates")
        train_x = [features[i] for i in train_idx]
        cat_model = build_pipeline(MODEL_C)
        sev_model = build_pipeline(MODEL_C)
        cat_model.fit(train_x, [categories[i] for i in train_idx])
        sev_model.fit(train_x, [severities[i] for i in train_idx])
        examples = [features[i] for i in test_idx]
        predicted_cat = [str(x) for x in cat_model.predict(examples)]
        predicted_sev = [str(x) for x in sev_model.predict(examples)]

        fold_correct = Counter()
        for j, index in enumerate(test_idx):
            alert = {
                "alert_name": rows[index]["alert_name"],
                "title": "", "description": "", "labels": {},
            }
            legacy = classify_legacy(alert)
            rules = classify_v2(alert)
            candidate_predictions = {
                "legacy": (legacy["category"], legacy["severity"]),
                "offline_v2": (rules["category"], rules["severity"]),
                "learned_svm": (predicted_cat[j], predicted_sev[j]),
                "hybrid_rules_category_svm_severity":
                    (rules["category"], predicted_sev[j]),
            }
            gt_categories.append(categories[index])
            gt_severities.append(severities[index])
            for name, prediction in candidate_predictions.items():
                outputs[name].append(prediction)
                fold_correct[name] += (
                    prediction == (categories[index], severities[index])
                )
        fold_details.append({
            "fold": fold,
            "test_rules": len(test_idx),
            "test_exporter_families": sorted(test_groups),
            "train_rules_after_name_deduplication": len(train_idx),
            "joint_by_engine": {
                name: round(fold_correct[name] / len(test_idx), 4)
                for name in outputs
            },
        })

    metrics = {}
    for engine, predictions in outputs.items():
        pred_category = [x[0] for x in predictions]
        pred_severity = [x[1] for x in predictions]
        n = len(predictions)
        metrics[engine] = {
            "count": n,
            "category_accuracy": round(accuracy_score(gt_categories, pred_category), 4),
            "severity_accuracy": round(accuracy_score(gt_severities, pred_severity), 4),
            "category_macro_f1": round(f1_score(
                gt_categories, pred_category, labels=LABEL_CATEGORIES,
                average="macro", zero_division=0), 4),
            "severity_macro_f1": round(f1_score(
                gt_severities, pred_severity, labels=LABEL_SEVERITIES,
                average="macro", zero_division=0), 4),
            "joint_exact_match": round(sum(
                gt_categories[i] == pred_category[i] and
                gt_severities[i] == pred_severity[i]
                for i in range(n)) / n, 4),
            "category_confusion": {
                "labels": LABEL_CATEGORIES,
                "matrix": confusion_matrix(
                    gt_categories, pred_category, labels=LABEL_CATEGORIES
                ).tolist(),
            },
            "severity_confusion": {
                "labels": LABEL_SEVERITIES,
                "matrix": confusion_matrix(
                    gt_severities, pred_severity, labels=LABEL_SEVERITIES
                ).tolist(),
            },
            "by_category": {
                cat: {
                    "examples": sum(x == cat for x in gt_categories),
                    "category_accuracy": round(
                        sum(a == cat and p == cat for a, p in
                            zip(gt_categories, pred_category)) /
                        max(1, sum(x == cat for x in gt_categories)), 4),
                    "joint_accuracy": round(
                        sum(gt_categories[i] == cat and
                            pred_category[i] == cat and
                            gt_severities[i] == pred_severity[i]
                            for i in range(n)) /
                        max(1, sum(x == cat for x in gt_categories)), 4),
                }
                for cat in LABEL_CATEGORIES
            },
        }

    return {
        "dataset": "frozen_published_prometheus_rule_definitions_not_incidents",
        "claim": "cross_source_exploratory_not_production_accuracy",
        "feature": "alert_name_only_without_source_labels_or_target_severity",
        "model_C_chosen_before_this_evaluation": MODEL_C,
        "split": "5-fold GroupKFold, group=exporter_family",
        "samples": len(rows),
        "exporter_families": len(set(groups)),
        "category_distribution": dict(Counter(gt_categories)),
        "severity_distribution": dict(Counter(gt_severities)),
        "folds": fold_details,
        "metrics": metrics,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    report = evaluate()
    print("Source-separated grouped cross-validation:", report["samples"],
          "rule definitions across", report["exporter_families"], "exporter families")
    print("Distribution:", report["category_distribution"])
    print("Note: exploratory evaluation; model tuned in previous version on overlapping corpus.")
    for engine, data in report["metrics"].items():
        print(
            f"{engine}: category={data['category_accuracy']:.1%}, "
            f"severity={data['severity_accuracy']:.1%}, "
            f"joint={data['joint_exact_match']:.1%}, "
            f"macroF1(category)={data['category_macro_f1']:.1%}, "
            f"macroF1(severity)={data['severity_macro_f1']:.1%}"
        )
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(
            report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
