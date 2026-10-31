"""Tests for the reproducible offline supervised text model."""
from pathlib import Path

from app.ml_v14 import (
    DEFAULT_FIXTURES, DEFAULT_MODEL, prepare_training,
    load_model, classify_learned, classify_ml,
)


def test_public_dataset_group_disjoint_and_large_enough():
    train, val = prepare_training()
    assert len(train) >= 300
    assert len(val) >= 30
    train_groups = {r["source_file"].split("/")[2] for r in train}
    val_groups = {r["source_file"].split("/")[2] for r in val}
    assert not train_groups.intersection(val_groups)
    assert {r["category"] for r in train} == {"server", "network", "database", "application"}
    assert {r["severity"] for r in train} == {"critical", "warning", "info"}


def test_model_is_locally_trained_and_valid():
    assert DEFAULT_MODEL.is_file(), "Build ML model before running pytest"
    model = load_model()
    assert model["train_count"] >= 300
    assert model["version"] == "supervised-tfidf-svm-v14"
    assert model["selected_strategy"] in (
        "ml_both", "rules_category_ml_severity",
        "ml_category_rules_severity", "rules_both"
    )
    assert 0.0 <= model["validation_metrics"]["joint_accuracy"] <= 1.0
    classification = classify_learned({
        "alert_name": "PostgresqlDown", "title": "", "description": ""
    })
    assert classification["category"] in ("server", "network", "database", "application")
    assert classification["severity"] in ("critical", "warning", "info")
    assert classification["priority"] in ("P1", "P2", "P4")
    assert classification["review_required"] is True
    assert classification["confidence"] is None


def test_source_severity_is_passthrough_not_claimed_as_prediction():
    result = classify_ml({
        "alert_name": "UnknownEvent",
        "labels": {"severity": "critical", "job": "postgres-exporter"},
    })
    assert result["category"] == "database"
    assert result["severity"] == "critical"
    assert result["priority"] == "P1"
    assert "Критичность передана Prometheus" in result["explanation"]
    assert result["confidence"] is None


def test_unknown_event_does_not_claim_high_accuracy():
    result = classify_ml({"alert_name": "PreviouslyUnseenSignal", "labels": {}})
    assert result["review_required"] is True
    assert result["confidence"] is None
