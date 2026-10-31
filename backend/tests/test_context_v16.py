"""No-leakage and deployability tests of the annotation-based classifier."""
from app.ml_v16 import (
    MODEL_PATH, split_corpus, load_model, classify_context, text_of, read_rows,
    CORPUS_DIR
)


def test_source_group_split_and_annotation_coverage():
    train, validation = split_corpus()
    assert len(train) >= 500
    assert len(validation) == 74
    train_families = {r["source_file"].split("/")[2] for r in train}
    validation_families = {r["source_file"].split("/")[2] for r in validation}
    assert not (train_families & validation_families)
    assert all(r["summary"] and r["description"] for r in train[:5])


def test_true_labels_never_injected_in_text_features():
    record = {
        "alert_name": "ServiceXDown",
        "summary": "Failed to connect",
        "description": "Database connection refused",
        "expression": "up == 0",
        "category": "SENTINEL_LABEL_NEVER_IN_FEATURES",
        "severity": "SENTINEL_TARGET_NEVER_IN_FEATURES",
        "source_file": "SENTINEL_PATH_NEVER_IN_FEATURES",
    }
    text = text_of(record)
    assert "sentinel" not in text
    assert "failed" in text
    assert "database" in text
    assert "up" not in text
    assert "up" in text_of(record, True)


def test_frozen_model_produces_a_reviewable_analysis():
    assert MODEL_PATH.exists(), "Train context v16 before pytest"
    model = load_model()
    assert model["n_train"] >= 500
    assert model["n_validation"] == 74
    assert set(model["modes"]) == {"production_text", "promql_research"}
    result = classify_context({
        "alert_name": "PostgresqlDown",
        "title": "Postgres database down",
        "description": "Connection refused",
        "labels": {"severity": "info", "category": "network"},
    })
    assert result["category"] in ("server", "network", "database", "application")
    assert result["severity"] in ("critical", "warning", "info")
    assert result["confidence"] is None
    assert result["review_required"]
    assert result["model_version"] == "tfidf-svm-context-v16"


def test_all_three_frozen_splits_have_distinct_exporters():
    train, val = split_corpus()
    final = read_rows(CORPUS_DIR / "ml_v16_holdout.csv")
    groups = lambda rows: {r["source_file"].split("/")[2] for r in rows}
    assert len(final) == 118
    assert not (groups(final) & groups(train + val))
    assert {x["category"] for x in final} == {
        "server", "network", "database", "application"
    }
