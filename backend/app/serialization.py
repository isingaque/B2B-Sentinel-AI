from app.models import Incident, Analysis, Runbook, Recommendation, ChecklistItem, AuditEvent

def incident_json(i: Incident):
    return dict(id=i.id, source_id=i.source_id, source_name=i.source.name, alert_name=i.alert_name,
        title=i.title, description=i.description, labels=i.labels, annotations=i.annotations,
        monitor_state=i.monitor_state, workflow_status=i.workflow_status,
        severity=i.severity, category=i.category, priority=i.priority,
        started_at=i.started_at, last_seen_at=i.last_seen_at, resolved_at=i.resolved_at,
        acknowledged_at=i.acknowledged_at, acknowledged_by=i.acknowledged_by,
        closed_at=i.closed_at, closed_by=i.closed_by, resolution_note=i.resolution_note)

def analysis_json(a: Analysis | None):
    return None if not a else dict(id=a.id, status=a.status, severity=a.severity,
        category=a.category, priority=a.priority, confidence=a.confidence,
        review_required=a.review_required, explanation=a.explanation, model_version=a.model_version,
        error_code=a.error_code, created_at=a.created_at, completed_at=a.completed_at)

def checklist_json(c: ChecklistItem):
    return dict(id=c.id, incident_id=c.incident_id, recommendation_id=c.recommendation_id,
        position=c.position, instruction=c.instruction, status=c.status, note=c.note,
        updated_by=c.updated_by, updated_at=c.updated_at)

def detail_json(i: Incident):
    r = incident_json(i)
    r.update(latest_analysis=analysis_json(i.analyses[-1]) if i.analyses else None,
        adopted_recommendation_id=next((x.id for x in i.recommendations if x.is_adopted), None),
        checklist=[checklist_json(c) for c in i.checklist])
    return r

def runbook_json(r: Runbook):
    return dict(id=r.id, title=r.title, condition_text=r.condition_text, category=r.category,
        severity=r.severity, is_active=r.is_active, version=r.version,
        steps=[dict(id=x.id, position=x.position, instruction=x.instruction, is_risky=x.is_risky) for x in r.steps],
        created_at=r.created_at, updated_at=r.updated_at)

def recommendation_json(r: Recommendation):
    return dict(id=r.id, incident_id=r.incident_id, runbook_id=r.runbook_id,
        runbook_version=r.runbook_version, runbook_title=r.runbook_title,
        score=r.score, reason=r.reason, steps_snapshot=r.steps_snapshot,
        is_adopted=r.is_adopted, created_at=r.created_at)

def audit_json(a: AuditEvent):
    return dict(id=a.id, incident_id=a.incident_id, actor_username=a.actor_username,
        action=a.action, entity_kind=a.entity_kind, entity_id=a.entity_id,
        before=a.before, after=a.after, request_id=a.request_id, created_at=a.created_at)
