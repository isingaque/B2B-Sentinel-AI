"""Offline supervised text classifier (category and severity).

The training set is frozen public Prometheus alert definitions, *not*
observed incidents.  No API keys, web calls or automation of remediation.

The model is created from trusted local CSV snapshots at build time. Do NOT
load externally supplied joblib files: joblib/pickle can execute code.
"""
from __future__ import annotations

import argparse
import csv
import json
from functools import lru_cache
from pathlib import Path

from app.triage_v2 import classify_v2, _split_identifier

ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL = ROOT / "ml_v14_model.joblib"
DEFAULT_FIXTURES = ROOT.parent / "tests" / "fixtures"
TRAIN_FILES = ("public_prometheus_rules.csv", "heldout_prometheus_rules.csv",
               "ml_v14_source_part0.csv", "ml_v14_source_part1.csv")
VALIDATION_FILE = "ml_v14_source_part2.csv"
FINAL_FILES = ("ml_v14_source_part3.csv", "ml_v14_source_part4.csv")
VALID_CATEGORIES = {"server", "network", "database", "application"}
VALID_SEVERITIES = {"critical", "warning", "info"}
PRIORITY = {"critical": "P1", "warning": "P2", "info": "P4"}


def read_csv(paths):
    rows = []
    for path in paths:
        with Path(path).open(encoding="utf-8", newline="") as stream:
            rows.extend(csv.DictReader(stream))
    return rows


def prepare_training(fixtures_dir=DEFAULT_FIXTURES):
    """Source-group split, de-duplication, and leakage protection."""
    folder = Path(fixtures_dir)
    train = read_csv(folder / filename for filename in TRAIN_FILES)
    validation = read_csv([folder / VALIDATION_FILE])
    # Never open or inspect the final test set during training.
    for rows in (train, validation):
        for row in rows:
            if row["category"] not in VALID_CATEGORIES:
                raise ValueError("Invalid category in frozen corpus")
            if row["severity"] not in VALID_SEVERITIES:
                raise ValueError("Invalid severity in frozen corpus")
    group = lambda row: row["source_file"].split("/")[2]
    train_groups = {group(row) for row in train}
    val_groups = {group(row) for row in validation}
    if train_groups & val_groups:
        raise ValueError("Exporter-family leakage between dataset splits")

    # Remove *training* alert-name duplicates that appear in evaluation,
    # avoiding accidental memorization; NEVER edit test reference labels.
    protected_names = {_split_identifier(row["alert_name"]) for row in validation}
    train = [row for row in train if _split_identifier(row["alert_name"]) not in protected_names]
    seen = set()
    deduped = []
    for row in train:
        key = _split_identifier(row["alert_name"])
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    if len(deduped) < 300 or len(validation) < 30:
        raise ValueError("Insufficient training or heldout examples")
    return deduped, validation


def feature_text(alert: dict) -> str:
    parts = [alert.get("alert_name") or "", alert.get("title") or "",
             alert.get("description") or ""]
    return " ".join(_split_identifier(x) for x in parts if x)


def build_pipeline(choice):
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.svm import LinearSVC
    # Use character ngrams for previously unseen names / vendors and
    # word ngrams for symptom names (down, overloaded, replication, etc).
    char_features = TfidfVectorizer(
        analyzer="char", ngram_range=(2, 5), min_df=2,
        max_features=25000, sublinear_tf=True)
    word_features = TfidfVectorizer(
        analyzer="word", token_pattern=r"(?u)\b\w+\b", ngram_range=(1, 2),
        max_features=12000, sublinear_tf=True)
    features = FeatureUnion(
        [("char", char_features), ("word", word_features)],
        transformer_weights={"char": 1.0, "word": 1.2})
    return Pipeline([
        ("features", features),
        ("classifier", LinearSVC(C=choice, class_weight="balanced")),
    ])


def score_models(category_model, severity_model, rows):
    if not rows:
        raise ValueError("Empty dataset")
    names = [feature_text({"alert_name": row["alert_name"]}) for row in rows]
    cat = category_model.predict(names)
    sev = severity_model.predict(names)
    category_correct = sum(str(p) == r["category"] for p, r in zip(cat, rows))
    severity_correct = sum(str(p) == r["severity"] for p, r in zip(sev, rows))
    joint = sum(str(c) == r["category"] and str(s) == r["severity"]
                for c, s, r in zip(cat, sev, rows))
    n = len(rows)
    return {
        "examples": n,
        "category_accuracy": round(category_correct / n, 4),
        "severity_accuracy": round(severity_correct / n, 4),
        "joint_accuracy": round(joint / n, 4),
    }


def train_and_save(fixtures_dir=DEFAULT_FIXTURES, model_path=DEFAULT_MODEL):
    """Choose hyperparameter solely on validation; final holdout not read for scoring."""
    from joblib import dump
    train, val = prepare_training(fixtures_dir)
    X = [feature_text({"alert_name": row["alert_name"]}) for row in train]
    X_valid = [feature_text({"alert_name": row["alert_name"]}) for row in val]
    candidate_results = []
    for c in (0.15, 1.0, 4.0):
        category_model = build_pipeline(c)
        severity_model = build_pipeline(c)
        category_model.fit(X, [row["category"] for row in train])
        severity_model.fit(X, [row["severity"] for row in train])
        metrics = score_models(category_model, severity_model, val)
        candidate_results.append((metrics["joint_accuracy"], c, category_model,
                                  severity_model, metrics))
    # Prefer simpler regularization at same validation exact-match accuracy.
    best = sorted(candidate_results, key=lambda x: (-x[0], x[1]))[0]
    _, c, category_model, severity_model, metrics = best
    # A hybrid is selected ONLY on the validation exporters. The final
    # holdout CSV is never opened until after the strategy is frozen.
    ml_categories = category_model.predict(X_valid)
    ml_severities = severity_model.predict(X_valid)
    rule_predictions = [
        classify_v2({"alert_name": row["alert_name"], "labels": {}})
        for row in val
    ]
    strategy_scores = {}
    for strategy in ("ml_both", "rules_category_ml_severity",
                     "ml_category_rules_severity", "rules_both"):
        correct = 0
        for i, row in enumerate(val):
            category = (rule_predictions[i]["category"] if strategy in
                        ("rules_category_ml_severity", "rules_both")
                        else str(ml_categories[i]))
            severity = (rule_predictions[i]["severity"] if strategy in
                        ("ml_category_rules_severity", "rules_both")
                        else str(ml_severities[i]))
            correct += category == row["category"] and severity == row["severity"]
        strategy_scores[strategy] = round(correct / len(val), 4)
    strategy = max(strategy_scores, key=strategy_scores.get)
    payload = {
        "version": "supervised-tfidf-svm-v14",
        "category": category_model,
        "severity": severity_model,
        "train_count": len(train),
        "validation_count": len(val),
        "selected_c": c,
        "validation_metrics": metrics,
        "selected_strategy": strategy,
        "strategy_validation_joint": strategy_scores,
    }
    path = Path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    dump(payload, path, compress=3)
    return payload


@lru_cache(maxsize=1)
def load_model():
    from joblib import load
    # The file is generated from trusted project snapshots during local build.
    if not DEFAULT_MODEL.is_file():
        raise FileNotFoundError("ML model not trained; use CLASSIFIER_ENGINE=v2")
    return load(DEFAULT_MODEL)


def classify_learned(alert: dict, model=None):
    """Independent prediction; no externally supplied category/severity labels."""
    model = model if model is not None else load_model()
    text = feature_text(alert)
    if not text.strip():
        return classify_v2(alert)
    category = str(model["category"].predict([text])[0])
    severity = str(model["severity"].predict([text])[0])
    return {
        "category": category,
        "severity": severity,
        "priority": PRIORITY[severity],
        "confidence": None,  # SVM margins are not calibrated probabilities.
        "review_required": True,
        "explanation": (
            "Категория и критичность предсказаны локальной обученной "
            "текстовой моделью по названию и описанию. "
            "Прогноз требует проверки инженером."),
        "model_version": model["version"],
    }


def classify_ml(alert: dict, model=None):
    """Operational hybrid: prefer authoritative source labels when present."""
    v2 = classify_v2(alert)
    model = model if model is not None else load_model()
    predicted = classify_learned(
        {**alert, "labels": {}}, model=model)
    labels = {str(k).lower(): str(v).lower() for k, v in
              (alert.get("labels") or {}).items()}
    from app.triage_v2 import MONITORING_JOB_FAMILIES
    source = " ".join(labels.get(k, "") for k in
                      ("job", "exporter", "service", "app", "component"))
    has_source = (labels.get("category") in VALID_CATEGORIES or
                  any(pattern.search(source) for _, pattern in MONITORING_JOB_FAMILIES))
    strategy = model["selected_strategy"]
    # Validation-selected hybrid; NOT tuned against final holdout.
    category = (v2["category"] if has_source or strategy in
                ("rules_category_ml_severity", "rules_both")
                else predicted["category"])
    from_source = labels.get("severity") in VALID_SEVERITIES
    severity = (v2["severity"] if from_source or strategy in
                ("ml_category_rules_severity", "rules_both")
                else predicted["severity"])
    return {
        "category": category,
        "severity": severity,
        "priority": PRIORITY[severity],
        "confidence": None,
        "review_required": True,
        "explanation": (
            ("Категория получена из метаданных мониторинга. " if has_source
             else "Категория предсказана ML-моделью. ") +
            ("Критичность передана Prometheus. " if from_source
             else "Критичность предсказана ML-моделью. ") +
            "Решение требует проверки инженером."
        ),
        "model_version": model["version"] if model else "supervised-tfidf-svm-v14",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--model-out", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args()
    if not args.train:
        parser.error("Pass --train to build a model from frozen training CSVs.")
    model = train_and_save(args.fixtures, args.model_out)
    print(json.dumps({
        "version": model["version"],
        "train_count": model["train_count"],
        "validation_count": model["validation_count"],
        "selected_c": model["selected_c"],
        "validation_metrics": model["validation_metrics"],
        "selected_strategy": model["selected_strategy"],
        "strategy_validation_joint": model["strategy_validation_joint"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
