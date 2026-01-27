from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional

import aiohttp

from src.audit_modules.runner import run_modules_for_domain
from src.audit_modules.types import AuditContext, ModuleRunSummary
from src.config import AppConfig
from src.db import Database
from src.http import HttpClient

logger = logging.getLogger(__name__)


class Auditor:
    """
    Базовый аудитор доменов для CLI.

    Использует подключаемые модули и сохраняет результаты через Database.
    """

    def __init__(self, cfg: AppConfig, module_keys: Optional[Iterable[str]] = None) -> None:
        self._cfg = cfg
        self._module_keys = list(module_keys) if module_keys is not None else None

    def run(self) -> None:
        # Синхронный вход в асинхронный аудит, удобен для скриптов.
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        db = Database(self._cfg.db.url)
        targets = db.load_domains()

        if not targets:
            db.close()
            raise SystemExit("Нет доменов для аудита. Сначала импортируйте список доменов.")

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

            tasks = [asyncio.create_task(check_one(d)) for d in targets]
            done = 0
            for fut in asyncio.as_completed(tasks):
                domain, summary = await fut
                _persist_summary(db, domain, summary)
                db.commit()
                done += 1
                logger.info("[audit] %s/%s done", done, len(targets))

        db.close()
        logger.info("[audit] completed.")


def _persist_summary(db: Database, domain: str, summary: ModuleRunSummary) -> None:
    """Сохраняет результаты модулей в базу данных через Database."""

    for update in summary.check_updates:
        db.update_check(domain, update.key, update.row, description=update.description)
    for update in summary.admin_updates:
        db.update_admin_panel(domain, update.panel_key, update.row)
    for update in summary.cms_updates:
        db.update_domain_cms(
            domain,
            update.cms_key,
            update.cms_name,
            update.row.status,
            update.row.confidence,
            update.row.evidence_json,
        )
