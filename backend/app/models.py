import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from pgvector.sqlalchemy import Vector
from app.database import Base

def uuid4() -> str:
    return str(uuid.uuid4())

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="operator")

class MonitoringSource(Base):
    __tablename__ = "monitoring_sources"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(30), default="prometheus")
    health: Mapped[str] = mapped_column(String(30), default="never_connected")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("source_id", "fingerprint", name="uq_source_episode"), Index("ix_incident_started", "started_at"),)
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    source_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("monitoring_sources.id"), index=True)
    source: Mapped[MonitoringSource] = relationship()
    fingerprint: Mapped[str] = mapped_column(String(64))
    alert_name: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[dict] = mapped_column(JSONB, default=dict)
    annotations: Mapped[dict] = mapped_column(JSONB, default=dict)
    monitor_state: Mapped[str] = mapped_column(String(20), default="pending")
    workflow_status: Mapped[str] = mapped_column(String(20), default="open")
    severity: Mapped[str | None] = mapped_column(String(30))
    category: Mapped[str | None] = mapped_column(String(30))
    priority: Mapped[str | None] = mapped_column(String(3))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    missing_polls: Mapped[int] = mapped_column(Integer, default=0)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    resolution_note: Mapped[str | None] = mapped_column(Text)
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="incident", order_by="Analysis.created_at", cascade="all, delete-orphan")
    recommendations: Mapped[list["Recommendation"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    checklist: Mapped[list["ChecklistItem"]] = relationship(back_populates="incident", order_by="ChecklistItem.position", cascade="all, delete-orphan")

class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("incidents.id"), index=True)
    incident: Mapped[Incident] = relationship(back_populates="analyses")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    severity: Mapped[str | None] = mapped_column(String(20))
    category: Mapped[str | None] = mapped_column(String(30))
    priority: Mapped[str | None] = mapped_column(String(3))
    confidence: Mapped[float | None] = mapped_column(Float)
    review_required: Mapped[bool] = mapped_column(Boolean, default=True)
    explanation: Mapped[str | None] = mapped_column(Text)
    model_version: Mapped[str] = mapped_column(String(100), default="rules-v1")
    error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class Runbook(Base):
    __tablename__ = "runbooks"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(200))
    condition_text: Mapped[str] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(30))
    severity: Mapped[str | None] = mapped_column(String(20))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(384))
    steps: Mapped[list["RunbookStep"]] = relationship(back_populates="runbook", order_by="RunbookStep.position", cascade="all, delete-orphan")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class RunbookStep(Base):
    __tablename__ = "runbook_steps"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    runbook_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("runbooks.id"), index=True)
    runbook: Mapped[Runbook] = relationship(back_populates="steps")
    position: Mapped[int] = mapped_column(Integer)
    instruction: Mapped[str] = mapped_column(Text)
    is_risky: Mapped[bool] = mapped_column(Boolean, default=False)

class Recommendation(Base):
    __tablename__ = "recommendations"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("incidents.id"), index=True)
    incident: Mapped[Incident] = relationship(back_populates="recommendations")
    runbook_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("runbooks.id"))
    runbook_version: Mapped[int] = mapped_column(Integer)
    runbook_title: Mapped[str] = mapped_column(String(200))
    score: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text)
    steps_snapshot: Mapped[list] = mapped_column(JSONB, default=list)
    is_adopted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ChecklistItem(Base):
    __tablename__ = "checklist_items"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("incidents.id"), index=True)
    incident: Mapped[Incident] = relationship(back_populates="checklist")
    recommendation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("recommendations.id"))
    position: Mapped[int] = mapped_column(Integer)
    instruction: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    note: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id"))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=uuid4)
    incident_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("incidents.id"), index=True)
    actor_username: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(100))
    entity_kind: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[str] = mapped_column(String(100))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    request_id: Mapped[str] = mapped_column(String(80), default=uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
