"""Read-only, label-blind side-by-side comparison of baseline and ML v1.6.

Both models receive exactly the same title and description, never target
category/severity labels. Priority is a shared business rule with environment
metadata and therefore is not a separately learned prediction.
"""
from app.ai import classify
from app.ml_v16 import classify_context
from app.source_guard import guarded_classification
from app.priority_policy import assign_priority


def compare_incident_classifiers(alert: dict, baseline=None, learned=None) -> dict:
    # Explicit safe input projection. Even unrelated source labels are excluded
    # because legacy v1.1 scans all label values for its keyword rules.
    common_input = {
        "alert_name": str(alert.get("alert_name") or "")[:200],
        "title": str(alert.get("title") or "")[:300],
        "description": str(alert.get("description") or "")[:5000],
        "labels": {},
    }
    old = (baseline or classify)(dict(common_input))
    new = (learned or classify_context)(dict(common_input))

    def view(predicted: dict) -> dict:
        priority, needs_environment_review, priority_explanation = assign_priority(
            predicted["severity"], alert.get("labels") or {}
        )
        return {
            "category": predicted["category"],
            "severity": predicted["severity"],
            "priority": priority,
            "model_version": predicted["model_version"],
            "explanation": predicted["explanation"],
            "priority_explanation": priority_explanation,
            "review_required": predicted["review_required"] or needs_environment_review,
        }

    v1 = view(old)
    ml = view(new)
    guarded = guarded_classification(alert, ml_prediction=new)
    operational_priority, _, priority_reason = assign_priority(
        guarded["severity"], alert.get("labels") or {}
    )
    guarded["priority"] = operational_priority
    guarded["priority_explanation"] = priority_reason
    differences = {
        key: v1[key] != ml[key] for key in ("category", "severity", "priority")
    }
    return {
        "baseline": v1,
        "ml": ml,
        "differences": differences,
        "comparison_kind": "label_blind_text_only",
        "used_inputs": ["alert_name", "title", "description"],
        "target_source_labels_excluded": True,
        "priority_policy_uses_environment": True,
        "is_accuracy_measurement": False,
        "source_guard_preview": guarded,
        "demo_notice": (
            "Это демонстрационный сигнал: переключатель симулятора активирует "
            "правило Prometheus, но не измеряет реальную загрузку CPU."
            if str((alert.get("labels") or {}).get("scenario") or "").lower() == "cpu_high"
            else None
        ),
    }
