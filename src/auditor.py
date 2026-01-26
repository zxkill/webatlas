from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional
from urllib.parse import urlunparse
import aiohttp

from .config import AppConfig
from .db import Database, CheckRow, AdminPanelRow
from .http import HttpClient
from .bitrix import decode_html, score_bitrix, classify


logger = logging.getLogger(__name__)


def ensure_url(scheme: str, domain: str, path: str) -> str:
    # Универсальный сборщик URL: не допускаем “лишних” параметров и фрагментов.
    return urlunparse((scheme, domain, path, "", "", ""))


class Auditor:
    """
    Базовый аудит доменов:
    - проверка главной страницы (https/http)
    - классификация Bitrix по сигнатурам (cookies/html)
    - при уверенном "yes" — проверка /bitrix/admin/ (без логина)
    В дальнейшем здесь будут подключаться дополнительные проверки под разные CMS/фреймворки.
    """

    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg

    def run(self) -> None:
        asyncio.run(self._run_async())

    async def _run_async(self) -> None:
        db = Database(self._cfg.db.path)
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
            async def check_one(domain: str) -> None:
                async with sem:
                    logger.info("Запуск проверки домена: %s", domain)
                    check_row, admin_row, cms_row = await self._check_domain(session, http, domain)
                    db.update_check(domain, "bitrix", check_row, description="Проверка сигнатур Bitrix")
                    db.update_admin_panel(
                        domain,
                        "bitrix_admin",
                        admin_row,
                    )
                    if cms_row is not None:
                        db.update_domain_cms(
                            domain,
                            "bitrix",
                            "1C-Bitrix",
                            cms_row["status"],
                            cms_row["confidence"],
                            cms_row["evidence_json"],
                        )
                    db.commit()

            tasks = [asyncio.create_task(check_one(d)) for d in targets]
            done = 0
            for fut in asyncio.as_completed(tasks):
                await fut
                done += 1
                logger.info("[audit] %s/%s done", done, len(targets))

        db.close()
        logger.info("[audit] completed.")

    async def _check_domain(
        self,
        session: aiohttp.ClientSession,
        http: HttpClient,
        domain: str,
    ) -> tuple[CheckRow, AdminPanelRow, Optional[dict]]:
        """
        Выполняет единичную проверку домена и возвращает:
        - результат проверки CMS (CheckRow),
        - статус админки (AdminPanelRow),
        - описание CMS-результата для связанной таблицы (dict | None).
        """
        evidence: dict = {"domain": domain, "checked": {}}
        admin_evidence: dict = {"domain": domain, "checked": {}}
        cms_evidence: dict = {"domain": domain, "checked": {}}

        # 1) GET / — проверяем доступность домена и собираем сигнатуры.
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

            # Собираем Set-Cookie “как есть”: серверы часто кладут несколько заголовков.
            # aiohttp в dict не сохраняет множественные значения, поэтому здесь фиксируем минимум.
            # Для сигнатуры BITRIX_SM_* обычно достаточно и одного.
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

        # 2) /bitrix/admin/ — только при уверенном yes
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

                # “endpoint существует” — когда получаем 200/30x/401/403
                admin_status = "yes" if admin_resp.status in (200, 301, 302, 401, 403) else "no"

        cms_row = None
        if status in ("yes", "maybe"):
            cms_row = {
                "status": status,
                "confidence": score,
                "evidence_json": json.dumps(cms_evidence, ensure_ascii=False),
            }

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
