from __future__ import annotations

import asyncio
import json
import logging
from typing import Iterable, Optional
from urllib.parse import urlunparse

import aiohttp

from src.bitrix import classify, decode_html, score_bitrix
from src.config import load_config
from src.http import HttpClient
from src.webapp_db import AdminPanelRow, CheckRow, CmsRow, update_admin_panel, update_check, update_domain_cms

logger = logging.getLogger(__name__)


def ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL без лишних параметров, чтобы не было мусора в логах."""

    # Формируем URL вручную, исключая query/fragment для чистого audit-лога.
    return urlunparse((scheme, domain, path, "", "", ""))


class WebAuditor:
    """
    Аудитор для веб-админки.

    Использует настройки из config.yaml для лимитов и таймаутов,
    а запись результатов выполняет в PostgreSQL через webapp_db.
    """

    def __init__(self) -> None:
        self._cfg = load_config()

    async def check_domains(self, domains: Iterable[str]) -> list[tuple[str, CheckRow, AdminPanelRow, Optional[CmsRow]]]:
        """Запускаем аудит и возвращаем результаты по доменам."""

        targets = list(domains)
        if not targets:
            logger.warning("Нет доменов для аудита")
            return []

        http = HttpClient(
            rps=self._cfg.rate_limit.rps,
            total_timeout_s=self._cfg.audit.timeouts.total,
        )
        # Ограничиваем количество одновременных проверок, чтобы не перегружать сеть.
        sem = asyncio.Semaphore(self._cfg.audit.concurrency)

        async with aiohttp.ClientSession() as session:
            async def check_one(domain: str) -> tuple[str, CheckRow, AdminPanelRow, Optional[CmsRow]]:
                # Каждая проверка идёт под семафором, чтобы держать заданный уровень параллельности.
                async with sem:
                    logger.info("Запуск проверки домена: %s", domain)
                    check_row, admin_row, cms_row = await self._check_domain(session, http, domain)
                    return domain, check_row, admin_row, cms_row

            tasks = [asyncio.create_task(check_one(domain)) for domain in targets]
            results: list[tuple[str, CheckRow, AdminPanelRow, Optional[CmsRow]]] = []
            done = 0
            for task in asyncio.as_completed(tasks):
                # Сохраняем результаты по мере завершения задач.
                result = await task
                results.append(result)
                done += 1
                logger.info("[audit] %s/%s done", done, len(targets))

        logger.info("Аудит завершён, доменов обработано: %s", len(results))
        return results

    async def _check_domain(
        self,
        session: aiohttp.ClientSession,
        http: HttpClient,
        domain: str,
    ) -> tuple[CheckRow, AdminPanelRow, Optional[CmsRow]]:
        """
        Выполняет единичную проверку домена и возвращает:
        - результат проверки CMS (CheckRow),
        - статус админки (AdminPanelRow),
        - описание CMS-результата (CmsRow | None).
        """

        evidence: dict = {"domain": domain, "checked": {}}
        admin_evidence: dict = {"domain": domain, "checked": {}}
        cms_evidence: dict = {"domain": domain, "checked": {}}

        homepage = None
        used_scheme = None
        set_cookie_agg = ""

        for scheme in ("https", "http"):
            url = ensure_url(scheme, domain, "/")
            resp = await http.fetch(session, url, allow_redirects=True)
            if resp is None:
                evidence["checked"][scheme] = {"ok": False}
                logger.debug("Домен %s недоступен по %s", domain, scheme)
                continue

            evidence["checked"][scheme] = {"ok": True, "status": resp.status, "final_url": resp.final_url}
            homepage = resp
            used_scheme = scheme
            set_cookie_agg = resp.headers.get("Set-Cookie", "")
            break

        if homepage is None:
            return (
                CheckRow(
                    status="no",
                    score=0,
                    evidence_json=json.dumps({**evidence, "error": "unreachable"}, ensure_ascii=False),
                ),
                AdminPanelRow(
                    status=None,
                    http_status=None,
                    final_url=None,
                    evidence_json=json.dumps({**admin_evidence, "error": "unreachable"}, ensure_ascii=False),
                ),
                None,
            )

        html = decode_html(homepage.body, homepage.charset)
        score, ev = score_bitrix(homepage.headers, set_cookie_agg, html)
        status = classify(score)
        evidence["bitrix"] = {"score": score, **ev}
        evidence["used_url"] = homepage.final_url
        cms_evidence["bitrix"] = {"score": score, **ev}
        cms_evidence["used_url"] = homepage.final_url

        admin_status = None
        admin_http_status = None
        admin_final_url = None

        if status == "yes":
            admin_url = ensure_url(used_scheme or "https", domain, "/bitrix/admin/")
            admin_resp = await http.fetch(session, admin_url, allow_redirects=False)
            if admin_resp is None:
                admin_status = "no"
                admin_evidence["checked"]["bitrix_admin"] = {"ok": False}
            else:
                admin_http_status = admin_resp.status
                admin_final_url = admin_resp.final_url
                admin_evidence["checked"]["bitrix_admin"] = {
                    "ok": True,
                    "status": admin_resp.status,
                    "final_url": admin_resp.final_url,
                }
                admin_status = "yes" if admin_resp.status in (200, 301, 302, 401, 403) else "no"

        cms_row = None
        if status in ("yes", "maybe"):
            cms_row = CmsRow(
                status=status,
                confidence=score,
                evidence_json=json.dumps(cms_evidence, ensure_ascii=False),
            )

        return (
            CheckRow(
                status=status,
                score=score,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            ),
            AdminPanelRow(
                status=admin_status,
                http_status=admin_http_status,
                final_url=admin_final_url,
                evidence_json=json.dumps(admin_evidence, ensure_ascii=False),
            ),
            cms_row,
        )


def run_audit_and_persist(domains: Iterable[str], session_factory) -> int:
    """
    Запускаем аудит и сохраняем результаты в PostgreSQL.

    Возвращаем количество обработанных доменов для удобства в логах.
    """

    auditor = WebAuditor()
    results = asyncio.run(auditor.check_domains(domains))
    for domain, check_row, admin_row, cms_row in results:
        with session_factory() as session:
            update_check(session, domain, "bitrix", check_row, description="Проверка сигнатур Bitrix")
            update_admin_panel(session, domain, "bitrix_admin", admin_row)
            if cms_row is not None:
                update_domain_cms(session, domain, "bitrix", "1C-Bitrix", cms_row)
    logger.info("Аудит завершён, доменов обработано: %s", len(results))
    return len(results)
