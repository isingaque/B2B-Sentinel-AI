"""Duty AI API. All infrastructure-changing operations are intentionally absent."""
import csv
import io
from uuid import UUID, uuid4
from datetime import datetime, timezone
import httpx
import redis
from fastapi import FastAPI, Depends, HTTPException, Request, Query, UploadFile, File
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from sqlalchemy import select, func, or_, text
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.exc import IntegrityError
from app.auth import current_user, operator, admin, hasher, make_token, user_json
from app.config import settings
from app.database import get_db
from app.models import (User, MonitoringSource, Incident, Analysis, Runbook, RunbookStep,
                        Recommendation, ChecklistItem, AuditEvent, utcnow)
from app.ai import embed
from app.schemas import LoginRequest, RunbookCreateRequest, RunbookUpdateRequest, ChecklistUpdateRequest, CloseIncidentRequest
from app.serialization import incident_json, detail_json, recommendation_json, checklist_json, runbook_json, audit_json
from app.services import add_audit
from app.tasks import sync_prometheus, analyze_incident

app = FastAPI(title="Duty AI — B2B Incident Copilot", version="1.1.0", description="Assists operators; NEVER executes remediation commands.")

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request.state.request_id = str(uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    mapping = {400:"BAD_REQUEST",401:"UNAUTHORIZED",403:"FORBIDDEN",404:"NOT_FOUND",409:"CONFLICT",422:"VALIDATION_ERROR",503:"UNAVAILABLE"}
    return JSONResponse(status_code=exc.status_code, media_type="application/problem+json", content={
        "type":"about:blank", "title": "Request failed", "status":exc.status_code,
        "code": mapping.get(exc.status_code,"ERROR"), "detail":str(exc.detail),
        "request_id":request.state.request_id}, headers=exc.headers)

@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, media_type="application/problem+json", content={
        "type":"about:blank", "title":"Validation error", "status":422, "code":"VALIDATION_ERROR",
        "detail":"Invalid request: " + "; ".join(".".join(map(str,x["loc"])) + ": " + x["msg"] for x in exc.errors())[:1200],
        "request_id":request.state.request_id})

def load_incident(db: Session, incident_id: UUID, lock: bool = False):
    query = select(Incident).where(Incident.id == str(incident_id))
    if lock:
        query = query.with_for_update(of=Incident)
    i = db.scalar(query)
    if not i:
        raise HTTPException(404, "Incident not found")
    return i

def get_runbook(db: Session, runbook_id: UUID, lock=False):
    stmt = select(Runbook).where(Runbook.id == str(runbook_id))
    if lock:
        stmt = stmt.with_for_update(of=Runbook)
    r = db.scalar(stmt)
    if not r:
        raise HTTPException(404, "Runbook not found")
    return r

@app.get("/health/live", tags=["Health"])
def live():
    return {"status":"ok"}

@app.get("/health/ready", tags=["Health"])
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        redis.Redis.from_url(settings.redis_url).ping()
    except Exception:
        raise HTTPException(503, "Dependency unavailable")
    return {"status":"ok"}

@app.post("/api/v1/auth/login", tags=["Auth"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not hasher.verify(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    return make_token(user)

@app.get("/api/v1/auth/me", tags=["Auth"])
def me(user: User = Depends(current_user)):
    return user_json(user)

@app.get("/api/v1/dashboard/summary", tags=["Dashboard"])
def summary(db: Session = Depends(get_db), _=Depends(current_user)):
    stats = dict(db.execute(select(Incident.workflow_status, func.count()).group_by(Incident.workflow_status)).all())
    critical_open = db.scalar(select(func.count()).select_from(Incident).where(Incident.severity == "critical", Incident.workflow_status != "closed")) or 0
    pending = db.scalar(select(func.count()).select_from(Analysis).where(Analysis.status.in_(["pending", "running"]))) or 0
    connected = db.scalar(select(func.count()).select_from(MonitoringSource).where(MonitoringSource.health == "healthy")) or 0
    return {"open": stats.get("open", 0), "acknowledged": stats.get("acknowledged", 0), "closed": stats.get("closed", 0),
            "critical_open": critical_open, "analysis_pending": pending, "source_connected": bool(connected), "updated_at": utcnow()}

@app.get("/api/v1/monitoring/sources", tags=["Monitoring"])
def sources(db: Session = Depends(get_db), _=Depends(current_user)):
    return {"items":[{ "id":s.id, "name":s.name, "kind":s.kind, "health":s.health,
                        "last_polled_at":s.last_polled_at, "last_error":s.last_error, "enabled":s.enabled }
                      for s in db.scalars(select(MonitoringSource)).all()]}

@app.post("/api/v1/monitoring/sources/{source_id}/sync", status_code=202, tags=["Monitoring"])
def sync_now(source_id: UUID, db: Session = Depends(get_db), _=Depends(admin)):
    if not db.get(MonitoringSource, str(source_id)):
        raise HTTPException(404, "Monitoring source not found")
    task = sync_prometheus.delay()
    return {"job_id": task.id, "status": "queued"}

@app.get("/api/v1/incidents", tags=["Incidents"])
def incidents(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
              monitor_state: str | None = None, workflow_status: str | None = None,
              severity: str | None = None, category: str | None = None, priority: str | None = None,
              q: str | None = Query(None, max_length=200), hide_closed: bool = False, db: Session = Depends(get_db), _=Depends(current_user)):
    allowed = {"monitor_state": ("pending", "firing", "resolved"), "workflow_status": ("open", "acknowledged", "closed"),
               "severity": ("info", "warning", "critical"), "category": ("server", "network", "database", "application"),
               "priority": ("P1", "P2", "P3", "P4")}
    stmt = select(Incident)
    for key in allowed:
        value = locals()[key]
        if value is not None:
            if value not in allowed[key]:
                raise HTTPException(422, f"Invalid {key}")
            stmt = stmt.where(getattr(Incident, key) == value)
    if hide_closed:
        stmt = stmt.where(Incident.workflow_status != "closed")
    if q:
        stmt = stmt.where(or_(Incident.title.ilike(f"%{q}%"), Incident.alert_name.ilike(f"%{q}%"), Incident.description.ilike(f"%{q}%")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(Incident.started_at.desc(), Incident.id.desc()).offset((page - 1)*page_size).limit(page_size)).all()
    return {"items":[incident_json(i) for i in items], "page":page, "page_size":page_size, "total":total}

@app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
def incident_detail(incident_id: UUID, db: Session = Depends(get_db), _=Depends(current_user)):
    return detail_json(load_incident(db, incident_id))

@app.get("/api/v1/incidents/{incident_id}/timeline", tags=["Incidents"])
def timeline(incident_id: UUID, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
             db: Session = Depends(get_db), _=Depends(current_user)):
    load_incident(db, incident_id)
    stmt = select(AuditEvent).where(AuditEvent.incident_id == str(incident_id))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    data = db.scalars(stmt.order_by(AuditEvent.created_at.desc()).offset((page - 1)*page_size).limit(page_size)).all()
    return {"items":[audit_json(e) for e in data], "page":page, "page_size":page_size, "total":total}

@app.post("/api/v1/incidents/{incident_id}/acknowledge", tags=["Incidents"])
def acknowledge(incident_id: UUID, db: Session = Depends(get_db), user: User = Depends(operator)):
    i = load_incident(db, incident_id, lock=True)
    if i.workflow_status != "open":
        raise HTTPException(409, "Only an open incident can be acknowledged")
    i.workflow_status = "acknowledged"
    i.acknowledged_at = utcnow()
    i.acknowledged_by = user.id
    add_audit(db, i.id, "incident.acknowledged", user.username, "incident", i.id, before={"status":"open"}, after={"status":"acknowledged"})
    db.commit()
    return detail_json(i)

@app.post("/api/v1/incidents/{incident_id}/close", tags=["Incidents"])
def close(incident_id: UUID, payload: CloseIncidentRequest, db: Session = Depends(get_db), user: User = Depends(operator)):
    i = load_incident(db, incident_id, lock=True)
    if i.workflow_status != "acknowledged" or i.monitor_state != "resolved":
        raise HTTPException(409, "Acknowledge the incident and wait for Prometheus to resolve it")
    if any(x.status == "pending" for x in i.checklist):
        raise HTTPException(409, "Complete or skip all checklist items first")
    i.workflow_status = "closed"
    i.closed_at = utcnow()
    i.closed_by = user.id
    i.resolution_note = payload.resolution_note
    add_audit(db, i.id, "incident.closed", user.username, "incident", i.id, after={"resolution_note":i.resolution_note})
    db.commit()
    return detail_json(i)

@app.post("/api/v1/incidents/{incident_id}/analysis/retry", status_code=202, tags=["Incidents"])
def retry(incident_id: UUID, db: Session = Depends(get_db), user: User = Depends(operator)):
    i = load_incident(db, incident_id, lock=True)
    if i.workflow_status == "closed":
        raise HTTPException(409, "Cannot reanalyze closed incident")
    if i.analyses and i.analyses[-1].status in ("pending", "running"):
        raise HTTPException(409, "Analysis is already running")
    a = Analysis(incident_id=i.id, status="pending", model_version="expert-rules-v1")
    db.add(a)
    db.flush()
    add_audit(db, i.id, "analysis.requested", user.username, "analysis", a.id)
    db.commit()
    job = analyze_incident.delay(i.id, a.id)
    return {"job_id":job.id, "status":"queued"}

@app.get("/api/v1/incidents/{incident_id}/recommendations", tags=["Recommendations"])
def recommendations(incident_id: UUID, db: Session = Depends(get_db), _=Depends(current_user)):
    i = load_incident(db, incident_id)
    return {"items":[recommendation_json(r) for r in sorted(i.recommendations, key=lambda x:x.score, reverse=True)]}

@app.post("/api/v1/incidents/{incident_id}/recommendations/{recommendation_id}/adopt", tags=["Recommendations"])
def adopt(incident_id: UUID, recommendation_id: UUID, db: Session = Depends(get_db), user: User = Depends(operator)):
    i = load_incident(db, incident_id, lock=True)
    if i.workflow_status == "closed":
        raise HTTPException(409, "Incident is closed")
    if any(x.is_adopted for x in i.recommendations):
        raise HTTPException(409, "A runbook has already been adopted")
    rec = next((x for x in i.recommendations if x.id == str(recommendation_id)), None)
    if not rec:
        raise HTTPException(404, "Recommendation not found")
    rec.is_adopted = True
    for step in rec.steps_snapshot:
        db.add(ChecklistItem(incident_id=i.id, recommendation_id=rec.id,
               position=step["position"], instruction=step["instruction"], status="pending"))
    add_audit(db, i.id, "recommendation.adopted", user.username, "recommendation", rec.id,
              after={"runbook_title":rec.runbook_title, "version":rec.runbook_version})
    db.commit()
    return {"items":[checklist_json(x) for x in i.checklist]}

@app.patch("/api/v1/incidents/{incident_id}/checklist/{item_id}", tags=["Recommendations"])
def update_checklist(incident_id: UUID, item_id: UUID, payload: ChecklistUpdateRequest,
                     db: Session = Depends(get_db), user: User = Depends(operator)):
    i = load_incident(db, incident_id, lock=True)
    if i.workflow_status == "closed":
        raise HTTPException(409, "Incident is closed")
    item = next((x for x in i.checklist if x.id == str(item_id)), None)
    if not item:
        raise HTTPException(404, "Checklist item not found")
    if item.status != "pending":
        raise HTTPException(409, "This step was already confirmed")
    if payload.status == "skipped" and not (payload.note or "").strip():
        raise HTTPException(422, "Reason required for skipped step")
    previous = item.status
    item.status = payload.status
    item.note = payload.note
    item.updated_by = user.id
    item.updated_at = utcnow()
    add_audit(db, i.id, "checklist.updated", user.username, "checklist", item.id,
              before={"status":previous}, after={"status":item.status, "note":item.note})
    db.commit()
    return checklist_json(item)

def apply_runbook_payload(r: Runbook, payload: RunbookCreateRequest):
    for name in ("title", "condition_text", "category", "severity", "is_active"):
        setattr(r, name, getattr(payload, name))
    r.embedding = embed(payload.title + " " + payload.condition_text)
    r.steps = [RunbookStep(position=index+1, instruction=s.instruction, is_risky=s.is_risky)
               for index,s in enumerate(payload.steps)]
    r.updated_at = utcnow()

@app.get("/api/v1/runbooks", tags=["Runbooks"])
def runbooks(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
             q: str | None = Query(None, max_length=200), category: str | None = None, is_active: bool = True,
             db: Session = Depends(get_db), _=Depends(current_user)):
    if category is not None and category not in ("server", "network", "database", "application"):
        raise HTTPException(422, "Invalid category")
    stmt = select(Runbook).where(Runbook.is_active == is_active)
    if category:
        stmt = stmt.where(Runbook.category == category)
    if q:
        stmt = stmt.where(or_(Runbook.title.ilike(f"%{q}%"),Runbook.condition_text.ilike(f"%{q}%")))
    count = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(Runbook.updated_at.desc()).offset((page-1)*page_size).limit(page_size)).all()
    return {"items":[runbook_json(r) for r in items], "page":page, "page_size":page_size, "total":count}

@app.post("/api/v1/runbooks", status_code=201, tags=["Runbooks"])
def create_runbook(payload: RunbookCreateRequest, db: Session = Depends(get_db), _=Depends(admin)):
    r = Runbook(version=1)
    apply_runbook_payload(r, payload)
    db.add(r)
    db.commit()
    return runbook_json(r)

@app.get("/api/v1/runbooks/{runbook_id}", tags=["Runbooks"])
def read_runbook(runbook_id: UUID, db: Session = Depends(get_db), _=Depends(current_user)):
    return runbook_json(get_runbook(db, runbook_id))

@app.patch("/api/v1/runbooks/{runbook_id}", tags=["Runbooks"])
def update_runbook(runbook_id: UUID, payload: RunbookUpdateRequest, db: Session = Depends(get_db), _=Depends(admin)):
    r = get_runbook(db, runbook_id, lock=True)
    if r.version != payload.version:
        raise HTTPException(409, "Runbook version conflict")
    r.version += 1
    apply_runbook_payload(r, payload)
    db.commit()
    return runbook_json(r)

@app.delete("/api/v1/runbooks/{runbook_id}", status_code=204, tags=["Runbooks"])
def archive_runbook(runbook_id: UUID, db: Session = Depends(get_db), _=Depends(admin)):
    r = get_runbook(db, runbook_id, lock=True)
    if not r.is_active:
        raise HTTPException(409, "Already archived")
    r.is_active = False
    r.version += 1
    db.commit()
    return Response(status_code=204)

@app.post("/api/v1/runbooks/{runbook_id}/restore", tags=["Runbooks"])
def restore_runbook(runbook_id: UUID, db: Session = Depends(get_db), _=Depends(admin)):
    """Bring an archived runbook back to retrieval without losing its identity."""
    r = get_runbook(db, runbook_id, lock=True)
    if r.is_active:
        raise HTTPException(409, "Runbook is already active")
    r.is_active = True
    r.version += 1
    r.updated_at = utcnow()
    db.commit()
    return runbook_json(r)

@app.delete("/api/v1/runbooks/{runbook_id}/purge", status_code=204, tags=["Runbooks"])
def purge_runbook(runbook_id: UUID, db: Session = Depends(get_db), _=Depends(admin)):
    """Permanent deletion is allowed only for archived, never-referenced runbooks.

    Recommendation snapshots and incident history must remain immutable; referenced
    runbooks are rejected, not removed or cascaded.
    """
    r = get_runbook(db, runbook_id, lock=True)
    if r.is_active:
        raise HTTPException(409, "Archive the runbook before permanent deletion")
    used = db.scalar(select(Recommendation.id).where(Recommendation.runbook_id == r.id).limit(1))
    if used:
        raise HTTPException(409, "Runbook is referenced by incident history and cannot be permanently deleted")
    db.delete(r)
    db.commit()
    return Response(status_code=204)

@app.post("/api/v1/runbooks/import", status_code=201, tags=["Runbooks"])
async def import_runbooks(file: UploadFile = File(...), db: Session = Depends(get_db), _=Depends(admin)):
    raw = await file.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise HTTPException(422, "CSV exceeds 512KB")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        if not reader.fieldnames or not {"title", "condition_text", "action_text"}.issubset(set(reader.fieldnames)):
            raise ValueError("Missing title,condition_text,action_text columns")
        payloads = []
        for row in reader:
            payloads.append(RunbookCreateRequest(title=row["title"], condition_text=row["condition_text"],
                category=row.get("category") or None, severity=row.get("severity") or None,
                steps=[{"instruction":row["action_text"], "is_risky":False}]))
        if not payloads or len(payloads) > 100:
            raise ValueError("1-100 rows required")
    except (UnicodeError, ValueError, KeyError) as exc:
        raise HTTPException(422, f"Invalid CSV: {exc}")
    for payload in payloads:
        r = Runbook(version=1)
        apply_runbook_payload(r, payload)
        db.add(r)
    db.commit()
    return {"created_count":len(payloads)}

SCENARIOS = ("cpu_high","disk_full","database_down","nginx_down","packet_loss")

@app.post("/api/v1/demo/scenarios/{scenario}/trigger", status_code=202, tags=["Demo"])
def trigger(scenario: str, _=Depends(admin)):
    if scenario not in SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    try:
        response = httpx.post(settings.demo_exporter_url+"/trigger/"+scenario,
                              headers={"X-Demo-Token":settings.demo_token}, timeout=5)
        response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(503, "Demo metrics exporter unavailable")
    return {"scenario":scenario, "status":"triggered"}

@app.post("/api/v1/demo/reset", status_code=202, tags=["Demo"])
def demo_reset(_=Depends(admin)):
    try:
        response = httpx.post(settings.demo_exporter_url+"/reset", headers={"X-Demo-Token":settings.demo_token}, timeout=5)
        response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(503, "Demo metrics exporter unavailable")
    return {"scenario":"all", "status":"reset"}

# Single source of truth for documented HTTP contract (no separately evolving FastAPI schema).
def contract_openapi():
    if app.openapi_schema is None:
        from pathlib import Path
        import yaml
        path = Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml"
        if not path.exists():
            path = Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml"
        app.openapi_schema = yaml.safe_load(path.read_text(encoding="utf-8"))
    return app.openapi_schema

app.openapi = contract_openapi
