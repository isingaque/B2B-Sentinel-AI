"""Prometheus-source-first decision for the experimental ML classifier.

This deliberately separates a model's INDEPENDENT prediction from metadata
provided by the monitoring system. A source label is not an ML prediction.
Only allow-list category/severity values are accepted; unknown labels fall
back to the learned text model. No external requests or database writes.
"""
from __future__ import annotations

from app.ml_v16 import classify_context

CATEGORIES = {"server", "network", "database", "application"}
SEVERITIES = {"critical", "warning", "info"}
PRIORITY = {"critical": "P1", "warning": "P2", "info": "P4"}


def _labels(alert: dict) -> dict[str, str]:
    raw = alert.get("labels") or {}
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in raw.items()}


def guarded_classification(
    alert: dict,
    *,
    ml_prediction: dict | None = None,
    predict_fn=None,
) -> dict:
    """Applied decision with explicit evidence provenance and human review."""
    predictor = predict_fn or classify_context
    # Text-only input: do not allow reference labels into independent ML model.
    ml_input = {
        "alert_name": alert.get("alert_name") or "",
        "title": alert.get("title") or "",
        "description": alert.get("description") or "",
        "labels": {},
    }
    predicted = ml_prediction if ml_prediction is not None else predictor(ml_input)
    if predicted["category"] not in CATEGORIES or predicted["severity"] not in SEVERITIES:
        raise ValueError("ML predicted an unsupported category or severity")

    labels = _labels(alert)
    configured_category = labels.get("category")
    configured_severity = labels.get("severity")
    source_category = configured_category if configured_category in CATEGORIES else None
    source_severity = configured_severity if configured_severity in SEVERITIES else None

    applied_category = source_category or predicted["category"]
    applied_severity = source_severity or predicted["severity"]
    differences = {
        "category": source_category is not None and source_category != predicted["category"],
        "severity": source_severity is not None and source_severity != predicted["severity"],
    }
    used_fields = [key for key, value in (
        ("category", source_category), ("severity", source_severity)
    ) if value is not None]
    summary = []
    if source_category:
        summary.append(
            "Категория взята из настройки Prometheus: "
            f"{source_category} (прогноз ML: {predicted['category']})."
        )
    else:
        summary.append(
            "Метка категории Prometheus отсутствует или не распознана; "
            f"использован прогноз ML: {predicted['category']}."
        )
    if source_severity:
        summary.append(
            "Критичность взята из настройки Prometheus: "
            f"{source_severity} (прогноз ML: {predicted['severity']})."
        )
    else:
        summary.append(
            "Метка критичности Prometheus отсутствует или не распознана; "
            f"использован прогноз ML: {predicted['severity']}."
        )
    if any(differences.values()):
        summary.append(
            "Результаты мониторинга и модели РАСХОДЯТСЯ; "
            "дежурный должен сверить правило и фактические метрики."
        )
    else:
        summary.append("Решение требует проверки инженером.")

    return {
        "category": applied_category,
        "severity": applied_severity,
        "priority": PRIORITY[applied_severity],
        "confidence": None,
        "review_required": True,
        "explanation": " ".join(summary),
        "model_version": "tfidf-svm-context-v16+source-guard-v18",
        "model_prediction": {
            "category": predicted["category"],
            "severity": predicted["severity"],
        },
        "source_labels": {
            "category": source_category,
            "severity": source_severity,
        },
        "differences_from_source": differences,
        "used_source_fields": used_fields,
        "is_independent_ml_accuracy": False,
    }
