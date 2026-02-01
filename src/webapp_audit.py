from __future__ import annotations

import asyncio
import logging
import time
from typing import AsyncIterator, Iterable, Optional

import aiohttp

from src.audit_modules.registry import get_registry
from src.audit_modules.runner import run_modules_for_domain
from src.audit_modules.types import AuditContext, ModuleRunSummary
from src.http import HttpClient
from src.settings.loader import load_settings
from src.webapp_db import (
    ModuleRunRow,
    update_admin_panel,
    update_check,
    update_domain_cms,
    update_module_run,
)

logger = logging.getLogger(__name__)


def _persist_summary(domain: str, summary: ModuleRunSummary, session_factory) -> None:
    """
    Сохраняет результаты модулей в PostgreSQL (webapp_db).

    Важно:
    - payload-и модулей сохраняются через module.persist(...)
    - история запусков модулей — через update_module_run(...)
    - агрегаты домена (checks/admin/cms) — через update_* helpers
    """
    with session_factory() as session:
        registry = get_registry()

        # 1) Payload-и модулей
        for module_output in summary.module_outputs:
            module = registry.get(module_output.module_key)
            if module is None:
                logger.warning(
                    "[audit.persist] module missing in registry: key=%s (skip payload persist)",
                    module_output.module_key,
                )
                continue
            module.persist(session, domain, module_output.payload)

        # 2) История запусков
        for module_run in summary.module_runs:
            update_module_run(
                session,
                domain,
                ModuleRunRow(
                    module_key=module_run.module_key,
                    module_name=module_run.module_name,
                    status=module_run.status,
                    started_ts=module_run.started_ts,
                    finished_ts=module_run.finished_ts,
                    duration_ms=module_run.duration_ms,
                    detail_json=module_run.detail_json,
                    error_message=module_run.error_message,
                ),
            )

        # 3) Обновления доменных сущностей
        for update in summary.check_updates:
            update_check(session, domain, update.key, update.row, description=update.description)

        for update in summary.admin_updates:
            update_admin_panel(session, domain, update.panel_key, update.row)

        for update in summary.cms_updates:
            update_domain_cms(session, domain, update.cms_key, update.cms_name, update.row)


async def _audit_stream(
    domains: Iterable[str],
    *,
    module_keys: Optional[Iterable[str]] = None,
) -> AsyncIterator[tuple[str, ModuleRunSummary]]:
    """
    Потоковый движок аудита.

    Гарантии по памяти:
      - НЕ создаём list(domains)
      - НЕ создаём список tasks на все домены
      - Держим в памяти максимум ~concurrency задач (окно in-flight)

    Поведение:
      - дозапускаем задачи до заполнения окна
      - ждём завершения хотя бы одной (FIRST_COMPLETED)
      - yield-им результат немедленно
      - дозапускаем следующую задачу
    """
    settings = load_settings()
    normalized_module_keys = list(module_keys) if module_keys is not None else None

    concurrency = int(settings.app.audit_concurrency)
    if concurrency <= 0:
        raise ValueError("settings.app.audit_concurrency must be > 0")

    http = HttpClient(
        rps=settings.app.rate_limit_rps,
        total_timeout_s=settings.app.audit_timeout_total,
    )

    logger.info(
        "[audit.stream] start: concurrency=%s rps=%s timeout_total=%ss modules=%s",
        concurrency,
        settings.app.rate_limit_rps,
        settings.app.audit_timeout_total,
        normalized_module_keys,
    )

    # Приводим domains к итератору (важно: не материализуем список).
    it = iter(domains)

    async with aiohttp.ClientSession() as session:

        async def _check_one(domain: str) -> tuple[str, ModuleRunSummary]:
            # Детальный лог — удобно для диагностики “какой домен сейчас пошёл”.
            t0 = time.monotonic()
            logger.info("[audit.stream] run domain=%s modules=%s", domain, normalized_module_keys)
            context = AuditContext(domain=domain, session=session, http=http, config=settings)
            summary = await run_modules_for_domain(context, normalized_module_keys)
            dt_ms = int((time.monotonic() - t0) * 1000)
            logger.info("[audit.stream] done domain=%s duration_ms=%s", domain, dt_ms)
            return domain, summary

        in_flight: set[asyncio.Task[tuple[str, ModuleRunSummary]]] = set()
        produced = 0

        def _schedule_next() -> bool:
            """
            Пытаемся взять следующий домен из итератора и запланировать задачу.
            Возвращает True, если задача создана, иначе False (итератор исчерпан).
            """
            try:
                domain = next(it)
            except StopIteration:
                return False

            # Минимальная “санитарная” нормализация на всякий случай.
            if isinstance(domain, str):
                domain = domain.strip().lower()
            else:
                logger.warning("[audit.stream] non-string domain skipped: %r", domain)
                return True  # продолжаем планирование дальше

            task = asyncio.create_task(_check_one(domain))
            in_flight.add(task)
            return True

        # Заполняем окно.
        for _ in range(concurrency):
            if not _schedule_next():
                break

        # Главный цикл: пока есть что ждать.
        while in_flight:
            done, pending = await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
            in_flight = set(pending)

            for task in done:
                domain, summary = await task
                produced += 1
                logger.info("[audit.stream] progress: produced=%s in_flight=%s", produced, len(in_flight))
                yield domain, summary

                # Дозаполняем окно ровно на 1 (или больше, если в итераторе были не-строки).
                while len(in_flight) < concurrency:
                    if not _schedule_next():
                        break


def run_audit_and_persist(
    domains: Iterable[str],
    session_factory,
    module_keys: Optional[Iterable[str]] = None,
) -> int:
    """
    Синхронная обёртка: потоково аудируем и сразу persist-им.

    Память:
      - O(concurrency)
    Надёжность:
      - если процесс упал на середине, уже сохранённые домены останутся в БД.
    """

    async def _run() -> int:
        saved = 0
        async for domain, summary in _audit_stream(domains, module_keys=module_keys):
            _persist_summary(domain, summary, session_factory)
            saved += 1
            logger.info("[audit.persist] saved=%s domain=%s", saved, domain)
        logger.info("[audit] completed: processed=%s", saved)
        return saved

    return asyncio.run(_run())
