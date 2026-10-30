"""Offline triage v2: classification, source metadata, review safeguards."""
import pytest

from app.triage_v2 import classify_v2


@pytest.mark.parametrize("name,description,category,severity", [
    ("HighCPUUsage", "CPU utilization above 95% on a server", "server", "critical"),
    ("HostHighCpuLoad", "CPU load remains above normal", "server", "warning"),
    ("HostCpuIsUnderutilized", "CPU is underutilized", "server", "info"),
    ("PostgreSQLDown", "Database service unavailable", "database", "critical"),
    ("MysqlSlowQueries", "The query latency is high", "database", "warning"),
    ("NginxDown", "HTTP 502 from nginx", "application", "critical"),
    ("SnmpInterfaceHighBandwidthUsageInbound", "Network bandwidth high", "network", "warning"),
    ("CiliumAgentUnreachableNodes", "Agents cannot reach nodes", "network", "warning"),
    ("AppError", "application exception errors increased", "application", "info"),
    ("NetworkPacketLoss", "packet loss exceeds warning threshold", "network", "warning"),
])
def test_name_and_description(name, description, category, severity):
    result = classify_v2({"alert_name": name, "title": "", "description": description, "labels": {}})
    assert (result["category"], result["severity"]) == (category, severity)
    assert result["priority"] == {"critical": "P1", "warning": "P2", "info": "P4"}[severity]
    assert result["confidence"] is None
    assert result["review_required"] is True
    assert result["model_version"] == "offline-triage-v2"


def test_prometheus_source_labels_are_distinct_from_inference():
    result = classify_v2({
        "alert_name": "UnknownSomething",
        "labels": {"severity": "critical", "category": "network", "instance": "node-1"}
    })
    assert result["category"] == "network"
    assert result["severity"] == "critical"
    assert "источником мониторинга" in result["explanation"]
    assert result["confidence"] is None


def test_service_metadata_disambiguates_category_but_not_severity():
    result = classify_v2({"alert_name": "ReplicationLag", "description": "Replication lag rising",
                          "labels": {"job": "postgres-exporter"}})
    assert result["category"] == "database"
    assert result["severity"] == "warning"
    assert "по источнику метрик" in result["explanation"]


def test_no_executable_instructions_or_unbounded_text():
    result = classify_v2({"alert_name": "PostgreSQLDown", "description": "x" * 100000})
    assert len(result["explanation"]) < 500
    assert "sudo" not in result["explanation"]


def test_unknown_is_reviewed_and_not_reported_as_high_confidence():
    result = classify_v2({"alert_name": "SomeNewSignal", "labels": {}})
    assert result["confidence"] is None
    assert result["review_required"]
