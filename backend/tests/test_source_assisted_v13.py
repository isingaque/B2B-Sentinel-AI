"""Source-assisted categorization and provenance tests.

Configured severity labels are authoritative monitoring metadata, not
machine-learning predictions. Unknown sources remain review-required.
"""
import pytest
from app.triage_v2 import classify_v2


@pytest.mark.parametrize("job,expected", [
    ("ipmi-exporter", "server"),
    ("smartctl-exporter", "server"),
    ("snmp-exporter", "network"),
    ("coredns", "network"),
    ("consul-exporter", "network"),
    ("mongodb-exporter", "database"),
    ("clickhouse", "database"),
    ("cassandra-exporter", "database"),
    ("elasticsearch", "database"),
    ("rabbitmq-exporter", "application"),
    ("haproxy", "application"),
    ("jvm-exporter", "application"),
    ("caddy", "application"),
])
def test_job_metadata_routes_generic_alert(job, expected):
    result = classify_v2({
        "alert_name": "GenericAlert",
        "description": "Metric changed",
        "labels": {"job": job},
    })
    assert result["category"] == expected
    assert result["confidence"] is None
    assert result["review_required"]
    assert "источника метрик" in result["explanation"]


def test_severity_label_is_used_but_not_presented_as_ai_inference():
    result = classify_v2({
        "alert_name": "GenericAlert",
        "labels": {"job": "mongodb-exporter", "severity": "critical"},
    })
    assert result["category"] == "database"
    assert result["severity"] == "critical"
    assert result["priority"] == "P1"
    assert "Критичность передана источником мониторинга" in result["explanation"]
    assert result["confidence"] is None


def test_wrong_or_missing_metadata_never_fabricates_calibrated_confidence():
    result = classify_v2({
        "alert_name": "GenericAlert",
        "labels": {"job": "totally-unknown-provider", "severity": "extreme"},
    })
    assert result["confidence"] is None
    assert result["review_required"]
    assert result["severity"] in ("critical", "warning", "info")


def test_explicit_category_overrides_job_metadata():
    result = classify_v2({
        "alert_name": "GenericAlert",
        "labels": {"job": "rabbitmq-exporter", "category": "network", "severity": "warning"},
    })
    assert result["category"] == "network"
    assert "передана источником" in result["explanation"]
