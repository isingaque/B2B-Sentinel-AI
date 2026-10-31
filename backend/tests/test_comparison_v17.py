"""Comparison is read-only, uses identical text, and cannot leak label answers."""
from types import SimpleNamespace

from app.comparison import compare_incident_classifiers
from app.main import app
from app.auth import current_user


def test_equal_inputs_exclude_all_prometheus_labels():
    captured = []
    def baseline(alert):
        captured.append(("old", alert))
        return {
            "category": "server", "severity": "warning",
            "model_version": "expert-rules-v1",
            "explanation": "Legacy test", "review_required": False,
        }

    def learned(alert):
        captured.append(("ml", alert))
        return {
            "category": "database", "severity": "critical",
            "model_version": "tfidf-svm-context-v16",
            "explanation": "ML test", "review_required": True,
        }

    event = {
        "alert_name": "PostgresqlDown", "title": "DB unavailable",
        "description": "Connections refused",
        "labels": {
            "category": "application", "severity": "info",
            "environment": "staging", "instance": "host-1",
        },
    }
    result = compare_incident_classifiers(event, baseline, learned)
    assert captured[0][1] == captured[1][1]
    assert captured[0][1]["labels"] == {}
    assert event["labels"]["severity"] == "info"  # Source is not modified.
    assert result["target_source_labels_excluded"] is True
    assert result["baseline"]["priority"] == "P3"
    assert result["ml"]["priority"] == "P2"
    assert result["differences"] == {
        "category": True, "severity": True, "priority": True,
    }
    assert result["is_accuracy_measurement"] is False


def test_comparison_does_not_call_database_or_write_history():
    def echo(alert):
        return {
            "category": "server", "severity": "warning",
            "model_version": "test-only", "explanation": "Comparison",
            "review_required": False,
        }

    result = compare_incident_classifiers(
        {"alert_name": "HostCPUHigh", "title": "High CPU",
         "description": "CPU high", "labels": {"environment": "prod"}},
        echo, echo,
    )
    assert result["differences"] == {
        "category": False, "severity": False, "priority": False,
    }
    assert result["baseline"]["priority"] == "P2"
    assert result["ml"]["priority"] == "P2"


def test_compare_endpoint_is_authenticated_get_only():
    path = "/api/v1/incidents/{incident_id}/analysis/compare"
    routes = [r for r in app.routes if getattr(r, "path", "") == path]
    assert len(routes) == 1
    route = routes[0]
    assert route.methods == {"GET"}
    assert any(dep.call is current_user for dep in route.dependant.dependencies)
