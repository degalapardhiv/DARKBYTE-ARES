from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base


def uid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    preferences: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    assessments: Mapped[list[Assessment]] = relationship(back_populates="owner", foreign_keys="Assessment.created_by")
    targets: Mapped[list[Target]] = relationship(back_populates="creator", foreign_keys="Target.created_by")


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    environment: Mapped[str] = mapped_column(String(24), default="lab", nullable=False)
    authorization_ref: Mapped[str] = mapped_column(String(320), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(160), nullable=False)
    authorization_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    allowed_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False, index=True)
    verified_by: Mapped[str | None] = mapped_column(String(320))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    creator: Mapped[User] = relationship(back_populates="targets", foreign_keys=[created_by])
    assessments: Mapped[list[Assessment]] = relationship(back_populates="target")


class Assessment(Base, TimestampMixin):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    module: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="draft", nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner: Mapped[User] = relationship(back_populates="assessments", foreign_keys=[created_by])
    target: Mapped[Target] = relationship(back_populates="assessments")
    findings: Mapped[list[Finding]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    reports: Mapped[list[Report]] = relationship(back_populates="assessment")
    job: Mapped[ScanJob | None] = relationship(back_populates="assessment", uselist=False, cascade="all, delete-orphan")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    technique_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="open", nullable=False, index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id"), unique=True, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assessment: Mapped[Assessment] = relationship(back_populates="job")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="ready", nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    meta: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="reports")


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    link: Mapped[str | None] = mapped_column(String(300))
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class PluginState(Base, TimestampMixin):
    __tablename__ = "plugin_states"

    plugin_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled_by: Mapped[str | None] = mapped_column(String(320))


class AuditLog(Base):
    """Append-only audit trail with a SHA-256 hash chain.

    No API mutates or deletes these rows. ORM guards below reject updates and
    deletes; production deployments should also revoke UPDATE/DELETE from the
    application's database role.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_email: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), default="success", nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


@event.listens_for(AuditLog, "before_update")
def _block_audit_update(*_args, **_kwargs):
    raise ValueError("Audit log entries are immutable.")


@event.listens_for(AuditLog, "before_delete")
def _block_audit_delete(*_args, **_kwargs):
    raise ValueError("Audit log entries are immutable.")
