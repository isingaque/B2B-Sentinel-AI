"""Integrity checks for the frozen external alert-rule corpus.

These are snapshots of published configurations, NOT real firing incidents.
The benchmark is diagnostic; it does not demand an artificial 90% pass rate.
"""
import csv
from pathlib import Path

from scripts.evaluate_public_rules import evaluate

FILE = Path(__file__).parent / "fixtures" / "public_prometheus_rules.csv"


def test_snapshot_integrity():
    with FILE.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 185
    assert len({(r["source_file"], r["alert_name"]) for r in rows}) == len(rows)
    assert len({r["source_file"] for r in rows}) == 14
    assert {r["category"] for r in rows} == {"server", "network", "database", "application"}
    assert {r["severity"] for r in rows} == {"critical", "warning", "info"}
    assert all(len(r["source_sha"]) == 40 for r in rows)


def test_evaluation_excludes_target_labels():
    rows = [{"alert_name": "PostgreSQLDown", "category": "database",
             "severity": "critical", "source_file": "test.yml"}]
    report = evaluate(rows)
    assert report["sample_count"] == 1
    assert report["joint_accuracy"] == 1.0


def test_invalid_reference_labels_fail():
    rows = [{"alert_name": "SomeAlert", "category": "wrong",
             "severity": "critical", "source_file": "test.yml"}]
    import pytest
    with pytest.raises(ValueError):
        evaluate(rows)
