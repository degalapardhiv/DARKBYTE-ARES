from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from backend.core.config import get_settings
from backend.core.exceptions import AresError
from backend.database.session import async_session_factory
from backend.models.models import Assessment, Finding, Notification, ScanJob
from backend.services.audit import append_audit
from backend.services.engine_runner import run_engine

logger = logging.getLogger("ares.queue")


class AssessmentQueue:
    """Persistent job records + bounded async worker pool.

    Assessment work is durable across API restarts (job rows are recovered on
    startup). A single process owns the worker pool; horizontal deployments
    should move this loop into a dedicated worker service.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers: list[asyncio.Task] = []
        self._running = False
        self._queued_ids: set[str] = set()

    @property
    def worker_count(self) -> int:
        return len(self._workers)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        settings = get_settings()
        for index in range(settings.max_concurrent_assessments):
            self._workers.append(asyncio.create_task(self._worker_loop(index), name=f"ares-worker-{index}"))
        await self._recover()
        logger.info("Assessment queue started with %s workers", len(self._workers))

    async def stop(self) -> None:
        self._running = False
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def _recover(self) -> None:
        async with async_session_factory() as db:
            jobs = (
                await db.execute(
                    select(ScanJob).where(ScanJob.status.in_(["queued", "running"]))
                )
            ).scalars().all()
            ids: list[str] = []
            for job in jobs:
                if job.status == "running":
                    job.status = "queued"
                    job.started_at = None
                    assessment = await db.get(Assessment, job.assessment_id)
                    if assessment:
                        assessment.status = "queued"
                        assessment.progress = 0
                ids.append(job.id)
            await db.commit()
        for job_id in ids:
            await self._put(job_id)

    async def _put(self, job_id: str) -> None:
        if job_id in self._queued_ids:
            return
        self._queued_ids.add(job_id)
        await self._queue.put(job_id)

    async def enqueue(self, db, assessment: Assessment) -> ScanJob:
        existing = (
            await db.execute(select(ScanJob).where(ScanJob.assessment_id == assessment.id))
        ).scalar_one_or_none()
        if existing and existing.status in {"queued", "running"}:
            raise AresError(
                "This assessment is already queued or running.",
                status_code=409,
                code="assessment_in_progress",
            )
        if existing:
            job = existing
            job.status = "queued"
            job.attempts = 0
            job.error = None
            job.started_at = None
            job.finished_at = None
        else:
            job = ScanJob(assessment_id=assessment.id, status="queued")
            db.add(job)
        assessment.status = "queued"
        assessment.progress = 0
        assessment.error = None
        await db.commit()
        await db.refresh(job)
        await self._put(job.id)
        return job

    async def _worker_loop(self, index: int) -> None:
        while self._running:
            try:
                job_id = await self._queue.get()
            except asyncio.CancelledError:
                break
            try:
                await self._process(job_id)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Unhandled error while processing job %s", job_id)
            finally:
                self._queued_ids.discard(job_id)
                self._queue.task_done()

    async def _process(self, job_id: str) -> None:
        async with async_session_factory() as db:
            job = await db.get(ScanJob, job_id)
            if not job or job.status != "queued":
                return
            assessment = (
                await db.execute(
                    select(Assessment)
                    .options(selectinload(Assessment.target), selectinload(Assessment.owner))
                    .where(Assessment.id == job.assessment_id)
                )
            ).scalar_one_or_none()
            if not assessment or not assessment.target:
                job.status = "failed"
                job.error = "Assessment or target no longer exists."
                await db.commit()
                return
            job.status = "running"
            job.attempts += 1
            job.started_at = datetime.now(UTC)
            assessment.status = "running"
            assessment.started_at = assessment.started_at or datetime.now(UTC)
            assessment.progress = 15
            assessment_id = assessment.id
            assessment_name = assessment.name
            assessment_module = assessment.module
            assessment_owner = assessment.created_by
            assessment_is_demo = assessment.is_demo
            await db.commit()

            try:
                result = await run_engine(db, assessment, assessment.target)
                await db.execute(delete(Finding).where(Finding.assessment_id == assessment.id))
                for draft in result.findings:
                    payload = draft.to_dict(is_demo=assessment.is_demo)
                    db.add(
                        Finding(
                            assessment_id=assessment.id,
                            target_id=assessment.target_id,
                            module=assessment.module,
                            title=payload["title"],
                            description=payload["description"],
                            severity=payload["severity"],
                            cvss_score=payload["cvss_score"],
                            cvss_vector=payload["cvss_vector"],
                            cve_id=payload["cve_id"],
                            evidence=payload["evidence"],
                            remediation=payload["remediation"],
                            references=payload["references"],
                            technique_ids=payload["technique_ids"],
                            status="open",
                            is_demo=assessment.is_demo,
                        )
                    )
                assessment.status = "completed"
                assessment.progress = 100
                assessment.summary = result.summary
                assessment.risk_score = result.risk_score
                assessment.finished_at = datetime.now(UTC)
                job.status = "completed"
                job.finished_at = datetime.now(UTC)
                db.add(
                    Notification(
                        user_id=assessment.created_by,
                        title=f"Assessment complete · {assessment.name}",
                        message=(
                            f"{len(result.findings)} finding(s) across {assessment.module}. "
                            f"Risk score {result.risk_score:.1f}/100."
                        ),
                        level="success",
                        link=f"/assessments/{assessment.id}",
                        is_demo=assessment.is_demo,
                    )
                )
                await append_audit(
                    db,
                    action="assessment.completed",
                    resource_type="assessment",
                    resource_id=assessment.id,
                    actor=assessment.owner,
                    details={
                        "module": assessment.module,
                        "findings": len(result.findings),
                        "risk_score": result.risk_score,
                        "job_id": job.id,
                    },
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                job = await db.get(ScanJob, job_id)
                failed_assessment = await db.get(Assessment, assessment_id)
                if job:
                    job.status = "failed"
                    job.error = str(exc)[:1000]
                    job.finished_at = datetime.now(UTC)
                if failed_assessment:
                    failed_assessment.status = "failed"
                    failed_assessment.progress = 100
                    failed_assessment.error = str(exc)[:1000]
                    failed_assessment.finished_at = datetime.now(UTC)
                    db.add(
                        Notification(
                            user_id=assessment_owner,
                            title=f"Assessment failed · {assessment_name}",
                            message=str(exc)[:500],
                            level="error",
                            link=f"/assessments/{assessment_id}",
                            is_demo=assessment_is_demo,
                        )
                    )
                    await append_audit(
                        db,
                        action="assessment.failed",
                        resource_type="assessment",
                        resource_id=assessment_id,
                        outcome="failure",
                        details={"module": assessment_module, "error": type(exc).__name__},
                    )
                await db.commit()
                logger.warning("Assessment job %s failed: %s", job_id, exc)


assessment_queue = AssessmentQueue()


async def queue_status() -> dict[str, Any]:
    return {
        "workers": assessment_queue.worker_count,
        "queued_memory": assessment_queue._queue.qsize(),
        "running": assessment_queue._running,
    }
