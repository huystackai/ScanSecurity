"""Background task dispatcher (arq on Redis in production, inline asyncio task in dev/test)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from app.config import get_settings
from app.scanner.engine import execute_scan, run_and_persist_ai_analysis

log = logging.getLogger("vibescan.worker")

_background_tasks: set[asyncio.Task[Any]] = set()


def _track_task(coro) -> asyncio.Task[Any]:  # type: ignore[no-untyped-def]
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


async def enqueue_scan_job(scan_id: uuid.UUID) -> None:
    settings = get_settings()
    if settings.task_backend == "arq":
        try:
            pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            try:
                await pool.enqueue_job("arq_run_scan", str(scan_id))
                return
            finally:
                await pool.aclose()
        except Exception as exc:
            log.warning("Failed to enqueue scan via arq (%s); falling back to inline asyncio task", exc)
    _track_task(execute_scan(scan_id))


async def enqueue_analysis_job(scan_id: uuid.UUID, analysis_id: uuid.UUID) -> None:
    settings = get_settings()
    if settings.task_backend == "arq":
        try:
            pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            try:
                await pool.enqueue_job("arq_run_analysis", str(scan_id), str(analysis_id))
                return
            finally:
                await pool.aclose()
        except Exception as exc:
            log.warning("Failed to enqueue analysis via arq (%s); falling back to inline asyncio task", exc)
    _track_task(run_and_persist_ai_analysis(scan_id, analysis_id=analysis_id))


async def wait_for_inline_tasks() -> None:
    """Await any active inline background tasks (used by tests and graceful shutdown)."""
    while _background_tasks:
        pending = list(_background_tasks)
        await asyncio.gather(*pending, return_exceptions=True)


async def arq_run_scan(_ctx: dict[str, Any], scan_id_str: str) -> None:
    await execute_scan(uuid.UUID(scan_id_str))


async def arq_run_analysis(_ctx: dict[str, Any], scan_id_str: str, analysis_id_str: str) -> None:
    await run_and_persist_ai_analysis(uuid.UUID(scan_id_str), analysis_id=uuid.UUID(analysis_id_str))


class WorkerSettings:
    functions = [arq_run_scan, arq_run_analysis]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = 3700
    max_jobs = 4
