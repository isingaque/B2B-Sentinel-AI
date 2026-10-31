"""Tests for the generic labeled-incident benchmark."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.evaluate_labeled_incidents import score_rows

BASE = {
    "alert_name": "PostgreSQLDown",
    "title": "DB connection refused",
    "description": "Postgres database service unavailable",
    "labels_json": '{"category":"network","severity":"info","instance":"node-db-1"}',
    "expected_category": "database",
    "expected_severity": "critical",
    "expected_priority": "P1",
}


def test_labels_are_excluded_by_default():
    report = score_rows([BASE])
    assert report["count"] == 1
    assert report["joint_accuracy"] == 1.0


def test_operational_label_mode_is_identified_as_not_independent():
    report = score_rows([BASE], use_source_severity=True)
    assert report["mode"] == "include_source_severity"
    assert report["severity_accuracy"] == 0


def test_invalid_reference_values_are_rejected():
    import pytest
    with pytest.raises(ValueError):
        score_rows([dict(BASE, expected_category="unknown")])
    with pytest.raises(ValueError):
        score_rows([dict(BASE, labels_json="[]")])
