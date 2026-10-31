"""Priority domain policy regression tests (spec's production policy)."""
import pytest

from app.priority_policy import assign_priority


@pytest.mark.parametrize(
    "severity,production,nonproduction",
    [
        ("critical", "P1", "P2"),
        ("warning", "P2", "P3"),
        ("info", "P4", "P4"),
    ],
)
def test_priority_matrix(severity, production, nonproduction):
    priority, review, reason = assign_priority(severity, {"environment": "production"})
    assert priority == production
    assert not review
    assert "production" in reason
    priority, review, reason = assign_priority(severity, {"env": "staging"})
    assert priority == nonproduction
    assert not review


@pytest.mark.parametrize("labels", [
    {}, {"environment": "unspecified"}, {"environment": "prod", "stage": "qa"},
    {"env": "prod;rm -rf /"}, {"env": "test production"},
])
def test_ambiguous_environment_defaults_conservatively(labels):
    priority, review, reason = assign_priority("critical", labels)
    assert priority == "P1"
    assert review
    assert "требуется ручная проверка" in reason


def test_casing_aliases_and_stage():
    assert assign_priority("warning", {"Environment": "QA"})[:2] == ("P3", False)
    assert assign_priority("critical", {"stage": "LIVE"})[:2] == ("P1", False)


def test_unsupported_severity_rejected():
    with pytest.raises(ValueError):
        assign_priority("fatal", {"environment": "production"})
