"""Regression tests for CPU demo conflict and truthful metadata provenance."""
from app.comparison import compare_incident_classifiers
from app.source_guard import guarded_classification

CPU_ML = {
    "category": "server", "severity": "warning", "priority": "P2",
    "confidence": None, "review_required": True,
    "explanation": "Обученная модель оценила текст",
    "model_version": "tfidf-svm-context-v16",
}


def cpu_alert():
    return {
        "alert_name": "HighCPUUsage",
        "title": "Высокая загрузка CPU на сервере",
        "description": "CPU utilization exceeded 95% for server node-01",
        "labels": {
            "scenario": "cpu_high", "severity": "critical",
            "category": "server", "service": "compute",
        },
    }


def test_cpu_uses_configured_critical_but_preserves_ml_warning():
    seen = []
    def fake_predict(text):
        seen.append(text)
        return dict(CPU_ML)

    alert = cpu_alert()
    applied = guarded_classification(alert, predict_fn=fake_predict)
    assert seen and seen[0]["labels"] == {}
    assert alert["labels"]["severity"] == "critical"
    assert applied["severity"] == "critical"
    assert applied["category"] == "server"
    assert applied["priority"] == "P1"
    assert applied["model_prediction"]["severity"] == "warning"
    assert applied["source_labels"] == {"category": "server", "severity": "critical"}
    assert applied["differences_from_source"] == {"category": False, "severity": True}
    assert "РАСХОДЯТСЯ" in applied["explanation"]
    assert applied["review_required"] is True
    assert applied["confidence"] is None
    assert applied["is_independent_ml_accuracy"] is False


def test_missing_configured_labels_falls_back_to_ml():
    result = guarded_classification(
        {"alert_name": "UnknownAlert", "labels": {"job": "test"}},
        ml_prediction=dict(CPU_ML),
    )
    assert result["severity"] == "warning"
    assert result["category"] == "server"
    assert result["source_labels"] == {"category": None, "severity": None}
    assert not any(result["differences_from_source"].values())
    assert "использован прогноз ML" in result["explanation"]


def test_invalid_labels_are_not_treated_as_known_answers():
    result = guarded_classification(
        {"labels": {"severity": "fatal", "category": "gpu"}},
        ml_prediction=dict(CPU_ML),
    )
    assert result["severity"] == "warning"
    assert result["category"] == "server"
    assert result["used_source_fields"] == []


def test_mixed_source_ml_category_and_severity_conflicts():
    result = guarded_classification(
        {"labels": {"Severity": "INFO", "category": "network"}},
        ml_prediction=dict(CPU_ML),
    )
    assert result["category"] == "network"
    assert result["severity"] == "info"
    assert result["priority"] == "P4"
    assert result["differences_from_source"] == {"category": True, "severity": True}


def test_comparison_discloses_configured_cpu_and_does_not_change_projections():
    def old(inp):
        assert inp["labels"] == {}
        return {
            "category": "server", "severity": "critical", "priority": "P1",
            "explanation": "keyword 95%", "model_version": "expert-rules-v1",
            "review_required": True,
        }

    def learned(inp):
        assert inp["labels"] == {}
        return dict(CPU_ML)

    result = compare_incident_classifiers(cpu_alert(), old, learned)
    assert result["baseline"]["severity"] == "critical"
    assert result["ml"]["severity"] == "warning"
    assert result["source_guard_preview"]["severity"] == "critical"
    assert result["source_guard_preview"]["model_prediction"]["severity"] == "warning"
    assert result["source_guard_preview"]["differences_from_source"]["severity"] is True
    assert "не измеряет реальную загрузку CPU" in result["demo_notice"]
    assert result["is_accuracy_measurement"] is False


def test_staging_environment_changes_priority_not_source_severity():
    alert = cpu_alert()
    alert["labels"]["environment"] = "staging"
    def old(_):
        return {
            "category": "server", "severity": "critical",
            "priority": "P1", "explanation": "old",
            "model_version": "expert-rules-v1", "review_required": True,
        }
    result = compare_incident_classifiers(alert, old, lambda _: dict(CPU_ML))
    assert result["source_guard_preview"]["severity"] == "critical"
    assert result["source_guard_preview"]["priority"] == "P2"
    assert result["baseline"]["priority"] == "P2"
