from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse, urlunparse
import aiohttp
import tldextract

from .config import AppConfig
from .db import Database, CheckRow
from .http import HttpClient
from .bitrix import decode_html, score_bitrix, classify


def normalize_domain(raw: str) -> str | None:
    raw = (raw or "").strip().lower()
    if not raw or raw.startswith("#"):
        return None

    if "://" in raw:
        p = urlparse(raw)
        candidate = p.netloc or p.path
    else:
        candidate = raw

    candidate = candidate.split("@")[-1].split(":")[0].strip()
    ext = tldextract.extract(candidate)
    if not ext.domain or not ext.suffix:
        return None

    return ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)


def ensure_url(scheme: str, domain: str, path: str) -> str:
    return urlunparse((scheme, domain, path, "", "", ""))


def load_allowlist(path: str) -> set[str]:
    allowed: set[str] = set()
    for line in open(path, "r", encoding="utf-8"):
        d = normalize_domain(line)
        if d:
            allowed.add(d)
    return allowed


class Auditor:
    """
    Аудит доменов только по allowlist (разрешённые цели):
    - проверка главной страницы (https/http)
    - верификация Bitrix по сигнатурам (cookies/html)
    - при уверенном "yes" — проверка /bitrix/admin/ (без логина)
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
            raise SystemExit("Нет доменов с is_allowed=1. Пометьте домены в SQLite и повторите запуск.")

        http = HttpClient(
            rps=self._cfg.rate_limit.rps,
            total_timeout_s=self._cfg.audit.timeouts.total,
        )
        sem = asyncio.Semaphore(self._cfg.audit.concurrency)

        async with aiohttp.ClientSession() as session:
            async def check_one(domain: str) -> None:
                async with sem:
                    res = await self._check_domain(session, http, domain)
                    db.update_check(domain, res)
                    db.commit()

            tasks = [asyncio.create_task(check_one(d)) for d in targets]
            done = 0
            for fut in asyncio.as_completed(tasks):
                await fut
                done += 1
                print(f"[audit] {done}/{len(targets)} done")

        db.close()
        print("[audit] completed.")

    async def _check_domain(self, session: aiohttp.ClientSession, http: HttpClient, domain: str) -> CheckRow:
        evidence: dict = {"domain": domain, "checked": {}}

        # 1) GET /
        homepage = None
        used_scheme = None
        set_cookie_agg = ""

        for scheme in ("https", "http"):
            url = ensure_url(scheme, domain, "/")
            resp = await http.fetch(session, url, allow_redirects=True)
            if resp is None:
                evidence["checked"][scheme] = {"ok": False}
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
            return CheckRow(
                bitrix_status="no",
                bitrix_score=0,
                bitrix_evidence_json=json.dumps({**evidence, "error": "unreachable"}, ensure_ascii=False),
                admin_status=None,
                admin_http_status=None,
                admin_final_url=None,
            )

        html = decode_html(homepage.body, homepage.charset)
        score, ev = score_bitrix(homepage.headers, set_cookie_agg, html)
        status = classify(score)
        evidence["bitrix"] = {"score": score, **ev}
        evidence["used_url"] = homepage.final_url

        # 2) /bitrix/admin/ — только при уверенном yes
        admin_status = None
        admin_http_status = None
        admin_final_url = None

        if status == "yes":
            admin_url = ensure_url(used_scheme or "https", domain, "/bitrix/admin/")
            admin_resp = await http.fetch(session, admin_url, allow_redirects=False)
            if admin_resp is None:
                admin_status = "no"
            else:
                admin_http_status = admin_resp.status
                admin_final_url = admin_resp.final_url

                # “endpoint существует” — когда получаем 200/30x/401/403
                admin_status = "yes" if admin_resp.status in (200, 301, 302, 401, 403) else "no"

        return CheckRow(
            bitrix_status=status,
            bitrix_score=score,
            bitrix_evidence_json=json.dumps(evidence, ensure_ascii=False),
            admin_status=admin_status,
            admin_http_status=admin_http_status,
            admin_final_url=admin_final_url,
        )
