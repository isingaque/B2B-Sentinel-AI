"""Operational priority policy, independent from severity classification.

The same incident severity can require different response urgency depending on
production impact. Labels are untrusted; unknown environment is treated as
production for conservative prioritization, with mandatory human review.
"""
from __future__ import annotations

PRODUCTION = {"production", "prod", "live", "prd"}
NONPRODUCTION = {
    "development", "develop", "dev", "test", "testing", "qa", "staging",
    "stage", "preprod", "preproduction", "sandbox", "local", "demo",
}
ENV_LABELS = ("environment", "env", "deployment_environment", "stage")
POLICY = {
    "production": {"critical": "P1", "warning": "P2", "info": "P4"},
    "nonproduction": {"critical": "P2", "warning": "P3", "info": "P4"},
}


def assign_priority(severity: str, labels: dict | None) -> tuple[str, bool, str]:
    """Return priority, review_required, explanation for source metadata.

    Unknown / ambiguous environments default to production, but do not claim
    that production status was actually observed. All output is human-reviewed.
    """
    if severity not in ("critical", "warning", "info"):
        raise ValueError(f"Unsupported severity: {severity}")
    safe_labels = {str(k).lower(): str(v).strip().lower() for k, v in
                   (labels or {}).items()}
    present = [(key, safe_labels[key]) for key in ENV_LABELS if safe_labels.get(key)]
    classes = set()
    for _key, value in present:
        if value in PRODUCTION:
            classes.add("production")
        elif value in NONPRODUCTION:
            classes.add("nonproduction")
        else:
            classes.add("unknown")
    if classes == {"production"}:
        family, review, explanation = (
            "production", False, "Приоритет рассчитан для production по метке окружения")
    elif classes == {"nonproduction"}:
        family, review, explanation = (
            "nonproduction", False, "Приоритет рассчитан для non-production по метке окружения")
    else:
        family, review, explanation = (
            "production", True,
            "Окружение отсутствует или неоднозначно; приоритет рассчитан как production, "
            "требуется ручная проверка")
    return POLICY[family][severity], review, explanation
