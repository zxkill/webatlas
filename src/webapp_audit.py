from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional

import aiohttp

from src.audit_modules.runner import run_modules_for_domain
from src.audit_modules.types import AuditContext, ModuleRunSummary
from src.config import load_config
from src.http import HttpClient
from src.webapp_db import ModuleRunRow, update_admin_panel, update_check, update_domain_cms, update_module_run

logger = logging.getLogger(__name__)


class WebAuditor:
    """
    Аудитор для веб-админки.

    Использует настройки из config.yaml и запускает подключаемые модули.
    """

    def __init__(self, module_keys: Optional[Iterable[str]] = None) -> None:
        self._cfg = load_config()
        self._module_keys = list(module_keys) if module_keys is not None else None

    async def check_domains(self, domains: Iterable[str]) -> list[tuple[str, ModuleRunSummary]]:
        """Запускаем аудит и возвращаем результаты по доменам."""

        targets = list(domains)
        if not targets:
            logger.warning("Нет доменов для аудита")
            return []

        http = HttpClient(
            rps=self._cfg.rate_limit.rps,
            total_timeout_s=self._cfg.audit.timeouts.total,
        )
        sem = asyncio.Semaphore(self._cfg.audit.concurrency)

        async with aiohttp.ClientSession() as session:
            async def check_one(domain: str) -> tuple[str, ModuleRunSummary]:
                async with sem:
                    logger.info("Запуск проверки домена: %s", domain)
                    context = AuditContext(
                        domain=domain,
                        session=session,
                        http=http,
                        config=self._cfg,
                    )
                    summary = await run_modules_for_domain(context, self._module_keys)
                    return domain, summary

            tasks = [asyncio.create_task(check_one(domain)) for domain in targets]
            results: list[tuple[str, ModuleRunSummary]] = []
            done = 0
            for task in asyncio.as_completed(tasks):
                result = await task
                results.append(result)
                done += 1
                logger.info("[audit] %s/%s done", done, len(targets))

        logger.info("Аудит завершён, доменов обработано: %s", len(results))
        return results


def _persist_summary(domain: str, summary: ModuleRunSummary, session_factory) -> None:
    """Сохраняет результаты модулей в базе данных."""

    with session_factory() as session:
        # Фиксируем каждый запуск модуля отдельной записью для прозрачного аудита.
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
        for update in summary.check_updates:
            update_check(session, domain, update.key, update.row, description=update.description)
        for update in summary.admin_updates:
            update_admin_panel(session, domain, update.panel_key, update.row)
        for update in summary.cms_updates:
            update_domain_cms(session, domain, update.cms_key, update.cms_name, update.row)


def run_audit_and_persist(
    domains: Iterable[str],
    session_factory,
    module_keys: Optional[Iterable[str]] = None,
) -> int:
    """
    Запускаем аудит и сохраняем результаты в PostgreSQL.

    Возвращаем количество обработанных доменов для удобства в логах.
    """

    auditor = WebAuditor(module_keys=module_keys)
    results = asyncio.run(auditor.check_domains(domains))
    for domain, summary in results:
        _persist_summary(domain, summary, session_factory)
    logger.info("Аудит завершён, доменов обработано: %s", len(results))
    return len(results)
