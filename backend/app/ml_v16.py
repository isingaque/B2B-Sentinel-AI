"""Train local text classifier from source-frozen Prometheus rule annotations.

Only title/description fields available via /api/v1/alerts are used by the
deployable model; a separate PromQL experiment is never deployed unless
a monitoring-rule adapter explicitly provides that expression.

Training reads train and validation ONLY. Final holdout is opened solely by
the separate evaluation script after model/parameters are frozen.
Never load arbitrary user-submitted joblib files.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from app.ml_v14 import build_pipeline, feature_text
from app.triage_v2 import classify_v2

DIR = Path(__file__).resolve().parent
CORPUS_DIR = DIR.parent / "tests" / "fixtures"
MODEL_PATH = DIR / "context_ml_v16_model.joblib"
CANDIDATES = (0.15, 1.0, 4.0)
SEVERITIES = ("critical", "warning", "info")
CATEGORIES = ("server", "network", "database", "application")
PRIORITY = {"critical": "P1", "warning": "P2", "info": "P4"}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fd:
        rows = list(csv.DictReader(fd))
    expected = {
        "alert_name", "category", "severity", "source_file",
        "source_sha", "summary", "description", "expression", "split",
    }
    if not rows or not expected.issubset(rows[0]):
        raise ValueError(f"Bad or empty corpus: {path.name}")
    for row in rows:
        if row["category"] not in CATEGORIES or row["severity"] not in SEVERITIES:
            raise ValueError("Bad category or severity in corpus")
    return rows


def text_of(row: dict, with_expression: bool = False) -> str:
    # Never read target labels (category/severity) or file path.
    alert = {
        "alert_name": row.get("alert_name", ""),
        "title": row.get("summary", ""),
        "description": row.get("description", ""),
    }
    text = feature_text(alert)
    if with_expression:
        # Research-only; rule expression is absent from Prometheus /api/v1/alerts.
        text += " " + feature_text({"description": row.get("expression", "")})
    return text


def split_corpus(fixtures_dir=CORPUS_DIR):
    folder = Path(fixtures_dir)
    train = read_rows(folder / "ml_v16_train.csv")
    validation = read_rows(folder / "ml_v16_validation.csv")
    if any(x["split"] != "train" for x in train):
        raise ValueError("Incorrect training split labels")
    if any(x["split"] != "validation" for x in validation):
        raise ValueError("Incorrect validation split labels")
    group = lambda x: x["source_file"].split("/")[2]
    a, b = {group(x) for x in train}, {group(x) for x in validation}
    if a & b:
        raise ValueError("Exporter-family leakage between training/validation")

    # Protect against exact duplicate names from separate exporters.
    reserved = {feature_text({"alert_name": x["alert_name"]}) for x in validation}
    keep = []
    names = set()
    for row in train:
        name = feature_text({"alert_name": row["alert_name"]})
        if name not in names and name not in reserved:
            keep.append(row)
            names.add(name)
    if len(keep) < 300 or len(validation) < 50:
        raise ValueError("Not enough non-overlapping alerts")
    return keep, validation


def metrics_for(cm, sm, rows: list[dict], with_expression=False) -> dict:
    x = [text_of(r, with_expression) for r in rows]
    pcat, psev = cm.predict(x), sm.predict(x)
    cat_correct = sum(p == r["category"] for p, r in zip(pcat, rows))
    sev_correct = sum(p == r["severity"] for p, r in zip(psev, rows))
    joint = sum(
        c == row["category"] and s == row["severity"]
        for c, s, row in zip(pcat, psev, rows)
    )
    n = len(rows)
    return {
        "n": n,
        "category_accuracy": round(cat_correct / n, 4),
        "severity_accuracy": round(sev_correct / n, 4),
        "joint_accuracy": round(joint / n, 4),
        "joint_correct": joint,
    }


def train_and_save(fixtures_dir=CORPUS_DIR, model_path=MODEL_PATH):
    from joblib import dump

    folder = Path(fixtures_dir)
    train, validation = split_corpus(folder)
    datasets = {}
    for mode, with_expr in (("production_text", False), ("promql_research", True)):
        x = [text_of(r, with_expr) for r in train]
        ycat = [r["category"] for r in train]
        ysev = [r["severity"] for r in train]
        choices = []
        for c in CANDIDATES:
            cm, sm = build_pipeline(c), build_pipeline(c)
            cm.fit(x, ycat)
            sm.fit(x, ysev)
            measure = metrics_for(cm, sm, validation, with_expr)
            choices.append((measure["joint_accuracy"], c, cm, sm, measure))
        _, chosen_c, cm, sm, measure = sorted(choices, key=lambda it: (-it[0], it[1]))[0]
        datasets[mode] = {
            "category": cm,
            "severity": sm,
            "chosen_c": chosen_c,
            "validation": measure,
        }

    payload = {
        "version": "tfidf-svm-context-v16",
        "n_train": len(train),
        "n_validation": len(validation),
        "training_file_sha256": hashlib.sha256(
            (folder / "ml_v16_train.csv").read_bytes()).hexdigest(),
        "validation_file_sha256": hashlib.sha256(
            (folder / "ml_v16_validation.csv").read_bytes()).hexdigest(),
        "modes": datasets,
    }
    path = Path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    dump(payload, path, compress=3)
    return payload


@lru_cache(maxsize=1)
def load_model():
    from joblib import load
    if not MODEL_PATH.is_file():
        raise FileNotFoundError("Offline model missing; select CLASSIFIER_ENGINE=v2")
    return load(MODEL_PATH)


def classify_context(alert: dict, model=None) -> dict:
    """Inference using real Prometheus alert name + annotations; no target labels."""
    model = model if model is not None else load_model()
    text = feature_text(alert)
    if not text.strip():
        return classify_v2(alert)
    models = model["modes"]["production_text"]
    cat = str(models["category"].predict([text])[0])
    sev = str(models["severity"].predict([text])[0])
    return {
        "category": cat,
        "severity": sev,
        "priority": PRIORITY[sev],  # Domain policy in service layer may override.
        "confidence": None,  # Uncalibrated SVM decision margins.
        "review_required": True,
        "explanation": (
            "Обученная локальная модель оценила название, summary и description "
            "инцидента. Метки категории/критичности источника не использовались. "
            "Требуется проверка дежурного."),
        "model_version": model["version"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true", required=True)
    parser.add_argument("--fixtures", type=Path, default=CORPUS_DIR)
    parser.add_argument("--model-out", type=Path, default=MODEL_PATH)
    args = parser.parse_args()
    model = train_and_save(args.fixtures, args.model_out)
    print(json.dumps({
        "model": model["version"],
        "train": model["n_train"],
        "validation": model["n_validation"],
        "modes": {
            name: {
                "C": result["chosen_c"],
                "validation_metrics": result["validation"],
            }
            for name, result in model["modes"].items()
        },
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
