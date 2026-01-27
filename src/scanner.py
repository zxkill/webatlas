from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import aiohttp

from .config import AppConfig
from .db import Database
from .domain_utils import normalize_domain
from .http import HttpClient, HttpResponse


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Finding:
    category: str
    key: str
    severity: str
    description: str
    evidence: dict[str, Any]


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


TECH_SIGNATURES = (
    ("wordpress", "WordPress", re.compile(r"wp-content|wp-includes", re.IGNORECASE), 90),
    ("joomla", "Joomla", re.compile(r"joomla", re.IGNORECASE), 70),
    ("drupal", "Drupal", re.compile(r"/sites/default|Drupal.settings", re.IGNORECASE), 80),
    ("bitrix", "1C-Bitrix", re.compile(r"bitrix|/bitrix/", re.IGNORECASE), 80),
    ("laravel", "Laravel", re.compile(r"laravel", re.IGNORECASE), 60),
    ("django", "Django", re.compile(r"django", re.IGNORECASE), 60),
    ("rails", "Ruby on Rails", re.compile(r"rails", re.IGNORECASE), 60),
    ("next", "Next.js", re.compile(r"_next/", re.IGNORECASE), 70),
    ("nuxt", "Nuxt", re.compile(r"_nuxt/", re.IGNORECASE), 70),
)


HEADER_HINTS = (
    ("x-powered-by", "X-Powered-By"),
    ("server", "Server"),
    ("via", "Via"),
    ("x-aspnet-version", "X-AspNet-Version"),
)


def _build_candidates(domain: str) -> list[str]:
    # Генерируем стандартный набор URL-кандидатов (https/http + www).
    candidates = [
        urlunparse(("https", domain, "/", "", "", "")),
        urlunparse(("http", domain, "/", "", "", "")),
        urlunparse(("https", f"www.{domain}", "/", "", "", "")),
        urlunparse(("http", f"www.{domain}", "/", "", "", "")),
    ]
    return candidates


def _extract_meta_generator(html: str) -> Optional[str]:
    # Пытаемся извлечь meta generator для определения стека.
    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*>', html, re.IGNORECASE)
    if not match:
        return None
    tag = match.group(0)
    content = re.search(r'content=["\']([^"\']+)["\']', tag, re.IGNORECASE)
    return content.group(1).strip() if content else None


def _parse_tls_date(value: str) -> Optional[datetime]:
    # Сертификаты чаще всего возвращают дату в формате 'Apr 10 12:00:00 2025 GMT'.
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _score_findings(findings: list[Finding]) -> int:
    # Простая модель риск-скоринга на основе severity.
    weights = {"low": 1, "medium": 5, "high": 10}
    return sum(weights.get(finding.severity, 0) for finding in findings)


async def _resolve_dns(domain: str) -> dict[str, list[str]]:
    # Best-effort DNS: собираем A/AAAA через стандартный resolver.
    loop = asyncio.get_running_loop()

    def _lookup() -> dict[str, list[str]]:
        result: dict[str, list[str]] = {"A": [], "AAAA": []}
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror:
            return result
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                result["A"].append(sockaddr[0])
            elif family == socket.AF_INET6:
                result["AAAA"].append(sockaddr[0])
        return result

    return await loop.run_in_executor(None, _lookup)


async def _fetch_tls_info(domain: str, timeout_s: float) -> dict[str, Any]:
    # Получаем минимальную информацию о TLS сертификате (issuer, SAN, срок действия).
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx),
            timeout=timeout_s,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
        logger.debug("TLS-соединение не удалось для %s: %s", domain, exc)
        return {"ok": False, "error": str(exc)}

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
    finally:
        writer.close()
        await writer.wait_closed()

    if not cert:
        return {"ok": False, "error": "empty_cert"}

    san = []
    for name, value in cert.get("subjectAltName", []):
        if name == "DNS":
            san.append(value)

    return {
        "ok": True,
        "not_after": cert.get("notAfter"),
        "issuer": cert.get("issuer"),
        "san": san,
    }


def _detect_stack(headers: dict[str, str], html: str) -> list[dict[str, Any]]:
    # Определяем технологии/стек по сигнатурам (header + HTML).
    stack: list[dict[str, Any]] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    joined_html = html or ""
    meta_generator = _extract_meta_generator(joined_html or "")

    if meta_generator:
        stack.append(
            {
                "key": "meta-generator",
                "name": meta_generator,
                "confidence": 50,
                "evidence": "meta-generator",
            }
        )

    for key, name, pattern, confidence in TECH_SIGNATURES:
        if pattern.search(joined_html):
            stack.append(
                {
                    "key": key,
                    "name": name,
                    "confidence": confidence,
                    "evidence": "html-pattern",
                }
            )

    for key, header_name in HEADER_HINTS:
        header_val = lower_headers.get(header_name.lower())
        if header_val:
            stack.append(
                {
                    "key": key,
                    "name": header_val,
                    "confidence": 30,
                    "evidence": f"header:{header_name}",
                }
            )

    return stack


def _analyze_headers(headers: dict[str, str], set_cookies: tuple[str, ...], https: bool) -> tuple[list[Finding], dict[str, Any]]:
    # Анализируем security headers и cookie flags, возвращая findings и сводку.
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing_headers = []
    for header in SECURITY_HEADERS:
        if header.lower() not in lower_headers:
            missing_headers.append(header)
            findings.append(
                Finding(
                    category="headers",
                    key=f"missing_{header.lower()}",
                    severity="low",
                    description=f"Отсутствует security-заголовок {header}.",
                    evidence={"header": header},
                )
            )

    cookie_findings = []
    for cookie in set_cookies:
        flags = cookie.lower()
        missing = []
        if https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            cookie_findings.append({"cookie": cookie, "missing": missing})
            findings.append(
                Finding(
                    category="cookies",
                    key="weak_cookie_flags",
                    severity="medium",
                    description="Cookie без рекомендуемых флагов безопасности.",
                    evidence={"cookie": cookie, "missing": missing},
                )
            )

    summary = {
        "missing_headers": missing_headers,
        "cookie_flags_issues": cookie_findings,
    }
    return findings, summary


class Scanner:
    """
    Выполняет неразрушающий аудит доменов с сохранением в БД:
    - доступность и редиректы,
    - заголовки и TLS,
    - пассивное определение технологий,
    - безопасные проверки common paths,
    - ограниченный порт-скан.
    """

    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg

    def run(self, limit: Optional[int] = None) -> None:
        asyncio.run(self._run_async(limit=limit))

    async def _run_async(self, limit: Optional[int]) -> None:
        db = Database(self._cfg.db.path)
        targets = db.load_domains(limit=limit)

        if not targets:
            db.close()
            raise SystemExit("Нет доменов для сканирования. Сначала импортируйте список доменов.")

        http = HttpClient(
            rps=self._cfg.rate_limit.rps,
            total_timeout_s=self._cfg.audit.timeouts.total,
        )
        sem = asyncio.Semaphore(self._cfg.scan.concurrency)

        async with aiohttp.ClientSession() as session:
            async def scan_one(domain: str) -> None:
                async with sem:
                    normalized = normalize_domain(domain) or domain
                    logger.info("[scan] старт: %s (normalized=%s)", domain, normalized)
                    scan_run_id = db.create_scan_run(domain)
                    if scan_run_id is None:
                        return
                    summary, findings = await self._scan_domain(session, http, normalized)
                    risk_score = _score_findings(findings)
                    for finding in findings:
                        db.add_scan_finding(
                            scan_run_id,
                            finding.category,
                            finding.key,
                            finding.severity,
                            finding.description,
                            json.dumps(finding.evidence, ensure_ascii=False),
                        )
                    db.finish_scan_run(
                        scan_run_id,
                        status="completed",
                        risk_score=risk_score,
                        summary_json=json.dumps(summary, ensure_ascii=False),
                    )
                    db.commit()
                    logger.info("[scan] завершено: %s risk=%s", domain, risk_score)

            tasks = [asyncio.create_task(scan_one(domain)) for domain in targets]
            done = 0
            for task in asyncio.as_completed(tasks):
                await task
                done += 1
                logger.info("[scan] %s/%s domains processed", done, len(targets))

        db.close()
        logger.info("[scan] all done.")

    async def _scan_domain(
        self,
        session: aiohttp.ClientSession,
        http: HttpClient,
        domain: str,
    ) -> tuple[dict[str, Any], list[Finding]]:
        findings: list[Finding] = []
        summary: dict[str, Any] = {
            "domain": domain,
            "started_ts": int(time.time()),
            "availability": {},
            "headers": {},
            "tls": {},
            "technologies": [],
            "common_paths": [],
            "ports": [],
        }

        # Stage A — Normalization & Reachability.
        dns_info = await _resolve_dns(domain)
        summary["dns"] = dns_info
        if not dns_info.get("A") and not dns_info.get("AAAA"):
            findings.append(
                Finding(
                    category="dns",
                    key="dns_missing",
                    severity="medium",
                    description="DNS записи не найдены (A/AAAA отсутствуют).",
                    evidence={"domain": domain},
                )
            )

        candidate_urls = _build_candidates(domain)
        request_budget = self._cfg.scan.request_limit
        used_response: Optional[HttpResponse] = None
        used_url = None

        for url in candidate_urls:
            if request_budget <= 0:
                logger.debug("[scan] лимит запросов исчерпан для %s", domain)
                break

            response = await self._probe_url(session, http, url)
            request_budget -= 1
            if response is None:
                summary["availability"][url] = {"ok": False}
                continue

            used_response = response
            used_url = url
            summary["availability"][url] = {
                "ok": True,
                "status": response.status,
                "final_url": response.final_url,
                "redirect_chain": list(response.history),
                "elapsed_ms": response.elapsed_ms,
            }
            break

        if used_response is None:
            findings.append(
                Finding(
                    category="reachability",
                    key="unreachable",
                    severity="high",
                    description="Ресурс недоступен по стандартным URL-кандидатам.",
                    evidence={"candidates": candidate_urls},
                )
            )
            summary["finished_ts"] = int(time.time())
            return summary, findings

        if len(used_response.history) >= self._cfg.scan.redirects_limit:
            findings.append(
                Finding(
                    category="reachability",
                    key="redirect_loop",
                    severity="medium",
                    description="Обнаружено слишком много редиректов (возможная петля).",
                    evidence={"history": list(used_response.history)},
                )
            )

        # Stage B — Headers & TLS quick checks.
        https_used = urlparse(used_response.final_url).scheme == "https"
        header_findings, header_summary = _analyze_headers(
            used_response.headers, used_response.set_cookies, https_used
        )
        findings.extend(header_findings)
        summary["headers"] = {
            "server": used_response.headers.get("Server"),
            "x_powered_by": used_response.headers.get("X-Powered-By"),
            "via": used_response.headers.get("Via"),
            "x_aspnet_version": used_response.headers.get("X-AspNet-Version"),
            "security_summary": header_summary,
        }

        if https_used:
            tls_info = await _fetch_tls_info(domain, timeout_s=self._cfg.scan.ports.timeout_s)
            summary["tls"] = tls_info
            if tls_info.get("ok") and tls_info.get("not_after"):
                expires = _parse_tls_date(tls_info["not_after"])
                if expires:
                    delta_days = (expires - datetime.now(timezone.utc)).days
                    summary["tls"]["days_left"] = delta_days
                    if delta_days <= self._cfg.scan.tls_expiring_days:
                        findings.append(
                            Finding(
                                category="tls",
                                key="tls_expiring",
                                severity="medium",
                                description="TLS сертификат скоро истекает.",
                                evidence={"days_left": delta_days},
                            )
                        )

        # Stage C — Content fingerprinting (passive).
        html_body = ""
        if request_budget > 0:
            content_resp = await http.fetch(
                session,
                used_response.final_url,
                allow_redirects=True,
                method="GET",
                max_redirects=self._cfg.scan.redirects_limit,
            )
            request_budget -= 1
            if content_resp is not None:
                html_body = content_resp.body.decode(content_resp.charset or "utf-8", errors="ignore")
                summary["technologies"] = _detect_stack(content_resp.headers, html_body)

        # Stage D — Safe common paths checks.
        common_paths_results = []
        for path in self._cfg.scan.common_paths:
            if request_budget <= 0:
                break
            checked_url = urlunparse((urlparse(used_response.final_url).scheme, domain, path, "", "", ""))
            resp = await self._probe_url(session, http, checked_url, allow_redirects=False)
            request_budget -= 1
            if resp is None:
                continue
            status = resp.status
            if status in (200, 301, 302, 401, 403):
                common_paths_results.append(
                    {"path": path, "status": status, "final_url": resp.final_url}
                )
                findings.append(
                    Finding(
                        category="common_paths",
                        key="public_endpoint",
                        severity="medium" if path in ("/.env", "/.git/HEAD", "/backup.zip") else "low",
                        description="Обнаружен публичный путь из safe-списка.",
                        evidence={"path": path, "status": status},
                    )
                )
        summary["common_paths"] = common_paths_results

        # Stage E — Limited port checks.
        ports_result = await self._check_ports(domain)
        summary["ports"] = ports_result
        for port_info in ports_result:
            if port_info.get("open") and port_info.get("port") in (22, 21, 3306, 5432, 6379, 27017):
                findings.append(
                    Finding(
                        category="ports",
                        key="sensitive_port_open",
                        severity="medium",
                        description="Открыт потенциально чувствительный порт.",
                        evidence={"port": port_info["port"]},
                    )
                )

        summary["used_url"] = used_response.final_url
        summary["finished_ts"] = int(time.time())
        return summary, findings

    async def _probe_url(
        self,
        session: aiohttp.ClientSession,
        http: HttpClient,
        url: str,
        allow_redirects: bool = True,
    ) -> Optional[HttpResponse]:
        # Сначала пробуем HEAD, затем fallback на GET.
        logger.debug("[scan] probe url=%s allow_redirects=%s", url, allow_redirects)
        response = await http.fetch(
            session,
            url,
            allow_redirects=allow_redirects,
            method="HEAD",
            max_redirects=self._cfg.scan.redirects_limit,
        )
        if response and response.status not in (405, 400):
            return response

        # Если HEAD недоступен, используем GET для минимального фингерпринта.
        logger.debug("[scan] fallback GET for %s", url)
        return await http.fetch(
            session,
            url,
            allow_redirects=allow_redirects,
            method="GET",
            max_redirects=self._cfg.scan.redirects_limit,
        )

    async def _check_ports(self, domain: str) -> list[dict[str, Any]]:
        # Ограниченный порт-скан с контролем параллельности.
        results: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(self._cfg.scan.ports.concurrency)

        async def check_one(port: int) -> None:
            async with semaphore:
                try:
                    logger.debug("[scan] port-check %s:%s", domain, port)
                    await asyncio.wait_for(
                        asyncio.open_connection(domain, port),
                        timeout=self._cfg.scan.ports.timeout_s,
                    )
                    results.append({"port": port, "open": True})
                except (asyncio.TimeoutError, OSError):
                    results.append({"port": port, "open": False})

        tasks = [asyncio.create_task(check_one(port)) for port in self._cfg.scan.ports.ports]
        await asyncio.gather(*tasks)
        return sorted(results, key=lambda item: item["port"])

