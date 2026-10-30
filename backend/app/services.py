"""Business logic: incident ingestion, AI persistence and audit."""
from datetime import datetime, timezone
import hashlib
import json
import logging
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.ai import classify, embed, pick_runbooks
from app.triage_v2 import classify_v2
from app.ml_v14 import classify_ml
from app.config import settings
from app.models import Incident, MonitoringSource, Analysis, Recommendation, AuditEvent, Runbook, utcnow

log = logging.getLogger(__name__)

def parse_datetime(text):
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, AttributeError):
        return utcnow()

def add_audit(db: Session, incident_id: str, action: str, actor: str, entity_kind: str,
              entity_id: str, before=None, after=None):
    db.add(AuditEvent(incident_id=incident_id, action=action, actor_username=actor,
                      entity_kind=entity_kind, entity_id=str(entity_id), before=before, after=after))

def fingerprint(alert: dict) -> str:
    # activeAt establishes a new episode if an identical alarm reoccurs after recovery.
    payload = {"labels": alert.get("labels", {}), "activeAt": alert.get("activeAt", "")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def normalize_alert(alert: dict):
    labels = {str(k): str(v) for k,v in (alert.get("labels") or {}).items()}
    annotations = {str(k): str(v) for k,v in (alert.get("annotations") or {}).items()}
    return dict(labels=labels, annotations=annotations, alert_name=labels.get("alertname", "UnknownAlert"),
        title=annotations.get("summary") or labels.get("alertname", "UnknownAlert"),
        description=annotations.get("description", ""),
        monitor_state="firing" if alert.get("state") == "firing" else "pending",
        started_at=parse_datetime(alert.get("activeAt")))

def ingest_alerts(db: Session, source: MonitoringSource, alerts: list[dict]) -> list[str]:
    """Call exclusively after successful Prometheus poll; do NOT resolve alerts on failed poll."""
    seen = set()
    created = []
    now = utcnow()
    for alert in alerts:
        if alert.get("state") not in ("firing", "pending"):
            continue
        normalized = normalize_alert(alert)
        fp = fingerprint(alert)
        seen.add(fp)
        existing = db.scalar(select(Incident).where(Incident.source_id == source.id, Incident.fingerprint == fp))
        if existing:
            if existing.monitor_state != "resolved":
                existing.monitor_state = normalized["monitor_state"]
                existing.last_seen_at = now
                existing.missing_polls = 0
        else:
            i = Incident(source_id=source.id, fingerprint=fp, **normalized, last_seen_at=now)
            db.add(i)
            db.flush()
            db.add(Analysis(incident_id=i.id, status="pending", model_version="expert-rules-v1"))
            add_audit(db, i.id, "incident.created", "system", "incident", i.id,
                      after={"alert_name": i.alert_name, "monitor_state": i.monitor_state})
            created.append(i.id)
    active = db.scalars(select(Incident).where(Incident.source_id == source.id, Incident.monitor_state != "resolved")).all()
    for i in active:
        if i.fingerprint not in seen:
            i.missing_polls += 1
            if i.missing_polls >= 2:
                i.monitor_state = "resolved"
                i.resolved_at = now
                add_audit(db, i.id, "monitor.resolved", "system", "incident", i.id,
                          before={"monitor_state": "firing"}, after={"monitor_state": "resolved"})
    db.flush()
    return created

def perform_analysis(db: Session, incident_id: str, analysis_id: str):
    analysis = db.get(Analysis, analysis_id)
    incident = db.get(Incident, incident_id)
    if analysis is None or incident is None or analysis.status != "pending":
        return
    analysis.status = "running"
    db.commit()
    try:
        alert = dict(labels=incident.labels, alert_name=incident.alert_name,
                     title=incident.title, description=incident.description)
        result = (classify_ml(alert) if settings.classifier_engine == "ml" else
                  classify_v2(alert) if settings.classifier_engine == "v2" else classify(alert))
        runbooks = db.scalars(select(Runbook).where(Runbook.is_active.is_(True))).all()
        candidates = pick_runbooks(alert, result, runbooks)
        # Remove old suggestions only when no plan has been adopted; chosen plan is immutable.
        adopted = any(r.is_adopted for r in incident.recommendations)
        if not adopted:
            for r in list(incident.recommendations):
                db.delete(r)
            db.flush()
            for r, score, reason in candidates:
                snapshot = [dict(position=step.position, instruction=step.instruction, is_risky=step.is_risky) for step in r.steps]
                db.add(Recommendation(incident_id=incident.id, runbook_id=r.id, runbook_version=r.version,
                                      runbook_title=r.title, score=score, reason=reason, steps_snapshot=snapshot))
        for field in ("severity", "category", "priority"):
            setattr(incident, field, result[field])
            setattr(analysis, field, result[field])
        analysis.confidence = result["confidence"]
        analysis.review_required = result["review_required"]
        analysis.explanation = result["explanation"]
        analysis.model_version = result["model_version"]
        analysis.status = "completed"
        analysis.completed_at = utcnow()
        add_audit(db, incident.id, "analysis.completed", "system", "analysis", analysis.id,
                  after={"model_version": result["model_version"], "category": result["category"], "severity": result["severity"]})
        db.commit()
    except Exception:
        db.rollback()
        log.exception("AI analysis failed for incident %s", incident_id)
        failed = db.get(Analysis, analysis_id)
        if failed:
            failed.status = "failed"
            failed.error_code = "ANALYSIS_FAILED"
            failed.completed_at = utcnow()
            db.commit()
        raise
