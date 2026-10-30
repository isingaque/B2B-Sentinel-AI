"""Celery tasks; one Redis lock prevents overlapping Prometheus syncs."""
import logging
import httpx
import redis
from celery import Celery
from app.config import settings
from app.database import SessionLocal
from app.models import MonitoringSource, Analysis, utcnow
from app.services import ingest_alerts, perform_analysis

log = logging.getLogger(__name__)
celery = Celery("duty_ai", broker=settings.redis_url, backend=settings.redis_url)
celery.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"], timezone="UTC", enable_utc=True,
                   beat_schedule={"prometheus-sync": {"task": "app.tasks.sync_prometheus", "schedule": 8.0}})

@celery.task(name="app.tasks.sync_prometheus", bind=True, max_retries=2)
def sync_prometheus(self):
    r = redis.Redis.from_url(settings.redis_url)
    # Atomic lock; TTL longer than network timeout and typical task duration.
    lock = r.lock("dutyai:sync:prometheus", timeout=45, blocking=False)
    if not lock.acquire(blocking=False):
        return {"status": "busy"}
    try:
        with SessionLocal() as db:
            source = db.query(MonitoringSource).filter_by(name="Prometheus").first()
            if not source or not source.enabled:
                return {"status": "disabled"}
            try:
                response = httpx.get(settings.prometheus_url + "/api/v1/alerts", timeout=7)
                response.raise_for_status()
                body = response.json()
                if body.get("status") != "success" or not isinstance(body.get("data", {}).get("alerts"), list):
                    raise ValueError("Unexpected Prometheus response")
                ids = ingest_alerts(db, source, body["data"]["alerts"])
                source.health = "healthy"
                source.last_polled_at = utcnow()
                source.last_error = None
                db.commit()
            except Exception as exc:
                db.rollback()
                source = db.query(MonitoringSource).filter_by(name="Prometheus").first()
                if source:
                    source.health = "unhealthy"
                    source.last_error = str(exc)[:1000]
                    db.commit()
                log.warning("Prometheus failed: %s", exc)
                return {"status": "error", "reason": str(exc)}
        for incident_id in ids:
            with SessionLocal() as db:
                a = db.query(Analysis).filter_by(incident_id=incident_id).order_by(Analysis.created_at.desc()).first()
                if a:
                    analyze_incident.delay(incident_id, a.id)
        return {"status": "ok", "created": len(ids)}
    finally:
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass

@celery.task(name="app.tasks.analyze_incident", bind=True, max_retries=1)
def analyze_incident(self, incident_id: str, analysis_id: str):
    with SessionLocal() as db:
        perform_analysis(db, incident_id, analysis_id)
