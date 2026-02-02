from __future__ import annotations

import json
import logging
import statistics
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

from .endpoint_map import (
    WELL_KNOWN_DEFAULT,
    endpoint_map_kpis,
    endpoint_map_to_dict,
    fetch_endpoint_map,
)
from .http_profile import build_canonical_profile, compare_www_non_www

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, domain: str, path: str) -> str:
    return urlunparse((scheme, domain, path, "", "", ""))


def _status_bucket(http_status: int | None) -> str:
    if http_status is None:
        return "no_response"
    if 200 <= http_status <= 299:
        return "2xx"
    if 300 <= http_status <= 399:
        return "3xx"
    if http_status in (401, 403):
        return "restricted"
    if 400 <= http_status <= 499:
        return "4xx"
    if 500 <= http_status <= 599:
        return "5xx"
    return "other"


def _headers_subset(headers: dict) -> dict[str, str]:
    """
    Берём минимум, который нужен для профиля/кэша.
    """
    if not headers:
        return {}
    out: dict[str, str] = {}
    for k in (
        "Content-Type",
        "Cache-Control",
        "Expires",
        "ETag",
        "Last-Modified",
        "Vary",
        "Age",
        "Strict-Transport-Security",
    ):
        v = headers.get(k) or headers.get(k.lower())
        if v:
            out[k] = v
    return out


@dataclass(frozen=True)
class AttemptResult:
    ok: bool
    http_status: int | None
    final_url: str | None
    reason_code: str | None
    elapsed_ms: int | None
    ttfb_ms: int | None
    response_bytes: int | None
    content_type: str | None
    redirect_count: int | None
    redirect_cross_scheme: bool | None
    redirect_cross_domain: bool | None
    redirects: list[dict]
    headers: dict[str, str]


class AvailabilityModule:
    key = "availability"
    name = "Доступность сайта"
    description = "Проверяет доступность домена по HTTP/HTTPS, метрики ответа и устойчивость результата."
    depends_on: tuple[str, ...] = ()

    MAX_ATTEMPTS = 3
    PRIMARY_ENDPOINT = "/"
    SECONDARY_ENDPOINTS = ("/robots.txt", "/favicon.ico")
    ENDPOINTS = (PRIMARY_ENDPOINT, *SECONDARY_ENDPOINTS)

    # Новые “профильные” эндпоинты (диагностика)
    PROFILE_ENDPOINTS = (
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/humans.txt",
        *WELL_KNOWN_DEFAULT,
    )

    async def run(self, context: AuditContext) -> ModuleResult:
        domain = context.domain

        evidence: dict = {
            "domain": domain,
            "checked_ts": int(time.time()),
            "schemes": {},
            "summary": {},
            "http_profile": {},
            "endpoints_map": {},
        }

        module_payload: list[dict] = []

        chosen = {
            "reachable": False,
            "healthy": False,
            "restricted": False,
            "used_scheme": None,
            "canonical_url": None,
            "final_host": None,
            "flaky": False,
        }

        # Для HTTP-профиля сохраняем “корневые” результаты по / для http и https
        root_http: dict | None = None
        root_https: dict | None = None

        for scheme in ("https", "http"):
            scheme_block = {"attempts": [], "best": None}
            evidence["schemes"][scheme] = scheme_block

            best_attempt: AttemptResult | None = None
            best_score = -1

            for path in self.ENDPOINTS:
                url = _ensure_url(scheme, domain, path)
                endpoint_attempts: list[AttemptResult] = []

                for attempt_no in range(1, self.MAX_ATTEMPTS + 1):
                    logger.info("[availability] %s attempt=%s/%s url=%s", domain, attempt_no, self.MAX_ATTEMPTS, url)

                    res = await context.http.fetch_ex(
                        context.session,
                        url,
                        allow_redirects=True,
                        method="GET",
                    )

                    if not res.ok or res.response is None:
                        ar = AttemptResult(
                            ok=False,
                            http_status=None,
                            final_url=None,
                            reason_code=res.reason_code,
                            elapsed_ms=res.elapsed_ms,
                            ttfb_ms=None,
                            response_bytes=None,
                            content_type=None,
                            redirect_count=None,
                            redirect_cross_scheme=None,
                            redirect_cross_domain=None,
                            redirects=[],
                            headers={},
                        )
                    else:
                        resp = res.response
                        headers = dict(resp.headers) if resp.headers else {}
                        redirects = [{"url": h.url, "status": h.status, "location": h.location} for h in resp.redirects]

                        redirect_cross_scheme = False
                        redirect_cross_domain = False
                        try:
                            parsed_req = urlparse(resp.request_url or url)
                            parsed_fin = urlparse(resp.final_url)
                            redirect_cross_scheme = (parsed_req.scheme != parsed_fin.scheme)
                            redirect_cross_domain = (parsed_req.netloc != parsed_fin.netloc)
                        except Exception:
                            pass

                        ar = AttemptResult(
                            ok=True,
                            http_status=resp.status,
                            final_url=resp.final_url,
                            reason_code=None,
                            elapsed_ms=resp.elapsed_ms,
                            ttfb_ms=resp.ttfb_ms,
                            response_bytes=resp.response_bytes,
                            content_type=headers.get("Content-Type") or headers.get("content-type"),
                            redirect_count=len(resp.redirects),
                            redirect_cross_scheme=redirect_cross_scheme,
                            redirect_cross_domain=redirect_cross_domain,
                            redirects=redirects,
                            headers=_headers_subset(headers),
                        )

                    endpoint_attempts.append(ar)

                    module_payload.append(
                        {
                            "checked_ts": int(time.time()),
                            "scheme": scheme,
                            "path": path,
                            "attempt_no": attempt_no,
                            "status_bucket": _status_bucket(ar.http_status),
                            "http_status": ar.http_status,
                            "final_url": ar.final_url,
                            "reason_code": ar.reason_code,
                            "elapsed_ms": ar.elapsed_ms,
                            "ttfb_ms": ar.ttfb_ms,
                            "response_bytes": ar.response_bytes,
                            "content_type": ar.content_type,
                            "redirect_count": ar.redirect_count,
                            "redirect_cross_scheme": "yes" if ar.redirect_cross_scheme else "no"
                            if ar.redirect_cross_scheme is not None else None,
                            "redirect_cross_domain": "yes" if ar.redirect_cross_domain else "no"
                            if ar.redirect_cross_domain is not None else None,
                            "evidence_json": None,
                        }
                    )

                def endpoint_rank(a: AttemptResult) -> int:
                    if not a.ok or a.http_status is None:
                        return 0
                    if 200 <= a.http_status <= 399:
                        return 4
                    if a.http_status in (401, 403):
                        return 3
                    if 400 <= a.http_status <= 499:
                        return 2
                    if 500 <= a.http_status <= 599:
                        return 1
                    return 1

                # max rank; among equals take lowest elapsed
                candidate = max(endpoint_attempts, key=lambda a: (endpoint_rank(a), -(a.elapsed_ms or 10**9)))
                cand_rank = endpoint_rank(candidate)
                if cand_rank > best_score:
                    best_score = cand_rank
                    best_attempt = candidate

                scheme_block["attempts"].append(
                    {
                        "path": path,
                        "attempts": [a.__dict__ for a in endpoint_attempts],
                        "best": candidate.__dict__,
                    }
                )

                # Для профиля сохраняем “корень” /
                if path == "/" and best_attempt and best_attempt.final_url:
                    root_payload = {
                        "request_url": url,
                        "final_url": best_attempt.final_url,
                        "status": best_attempt.http_status,
                        "redirects": best_attempt.redirects,
                        "headers": best_attempt.headers,
                    }
                    if scheme == "https":
                        root_https = root_payload
                    else:
                        root_http = root_payload

            scheme_block["best"] = best_attempt.__dict__ if best_attempt else None

            # Выбор канонического “живого” ответа: 2xx/3xx или restricted
            if best_attempt and best_attempt.ok and best_attempt.http_status is not None:
                if 200 <= best_attempt.http_status <= 399:
                    chosen["reachable"] = True
                    chosen["healthy"] = True
                elif best_attempt.http_status in (401, 403):
                    chosen["reachable"] = True
                    chosen["restricted"] = True

                if chosen["reachable"]:
                    chosen["used_scheme"] = scheme
                    chosen["canonical_url"] = best_attempt.final_url
                    try:
                        chosen["final_host"] = urlparse(best_attempt.final_url or "").netloc or None
                    except Exception:
                        chosen["final_host"] = None
                    break

        # flaky: различия статусов по / на выбранной схеме
        flaky = False
        attempts_for_flaky: list[int | None] = []
        if chosen["used_scheme"]:
            sch = evidence["schemes"].get(chosen["used_scheme"], {})
            for ep in sch.get("attempts", []):
                if ep.get("path") == "/":
                    for a in ep.get("attempts", []):
                        attempts_for_flaky.append(a.get("http_status"))
        uniq = {x for x in attempts_for_flaky if x is not None}
        if len(uniq) >= 2:
            flaky = True
        chosen["flaky"] = flaky

        # score/status
        score = 0
        status = "no"
        if chosen["healthy"]:
            status = "yes"
            score = 80
        elif chosen["restricted"]:
            status = "yes"
            score = 60
        elif chosen["reachable"]:
            status = "no"
            score = 30
        else:
            status = "no"
            score = 0

        # perf bonus
        perf_bonus = 0
        ttfb_candidates: list[int] = []
        if chosen["used_scheme"]:
            sch = evidence["schemes"].get(chosen["used_scheme"], {})
            for ep in sch.get("attempts", []):
                for a in ep.get("attempts", []):
                    if a.get("ok") and isinstance(a.get("ttfb_ms"), int):
                        ttfb_candidates.append(a["ttfb_ms"])
        if ttfb_candidates:
            ttfb = min(ttfb_candidates)
            if ttfb < 300:
                perf_bonus = 20
            elif ttfb < 1000:
                perf_bonus = 10

        if flaky:
            score = max(0, score - 10)

        score = min(100, score + perf_bonus)

        # --- HTTP профиль (канонизация) ---
        canonical = build_canonical_profile(root_http, root_https)
        # www/non-www эвристика: сравним финальные host http/https если есть
        www_switch = None
        try:
            h1 = urlparse(root_http["final_url"]).netloc if (root_http and root_http.get("final_url")) else None
            h2 = urlparse(root_https["final_url"]).netloc if (root_https and root_https.get("final_url")) else None
            www_switch = compare_www_non_www(h1, h2)
        except Exception:
            www_switch = None

        evidence["http_profile"] = {
            "canonical_url": canonical.canonical_url,
            "canonical_scheme": canonical.canonical_scheme,
            "canonical_host": canonical.canonical_host,
            "www_mode": canonical.www_mode,
            "trailing_slash_mode": canonical.trailing_slash_mode,
            "www_non_www_detected": www_switch,
            "http_root": root_http,
            "https_root": root_https,
            "hsts": {
                "present": canonical.hsts_present,
                "max_age": canonical.hsts_max_age,
                "include_subdomains": canonical.hsts_includesubdomains,
                "preload": canonical.hsts_preload,
            },
        }

        # --- Карта эндпоинтов (диагностика) ---
        # Используем “финальный” host если есть, чтобы карта шла по каноническому хосту.
        map_scheme = chosen["used_scheme"] or "https"
        map_host = chosen["final_host"] or domain

        endpoints_items = await fetch_endpoint_map(
            context=context,
            scheme=map_scheme,
            host=map_host,
            paths=list(self.PROFILE_ENDPOINTS),
        )

        evidence["endpoints_map"] = {
            "scheme": map_scheme,
            "host": map_host,
            "kpis": endpoint_map_kpis(endpoints_items),
            "items": endpoint_map_to_dict(endpoints_items),
        }

        evidence["summary"] = {
            "chosen": chosen,
            "flaky": flaky,
            "score": score,
        }

        evidence_json = json.dumps(evidence, ensure_ascii=False)
        for item in module_payload:
            item["evidence_json"] = evidence_json

        context.data["availability"] = {
            "reachable": chosen["reachable"],
            "healthy": chosen["healthy"],
            "restricted": chosen["restricted"],
            "used_scheme": chosen["used_scheme"],
            "canonical_url": chosen["canonical_url"],
            "final_host": chosen["final_host"],
            "flaky": flaky,
            "http_profile": evidence["http_profile"],
            "endpoints_map": evidence["endpoints_map"],
        }

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка доступности, HTTP-профиля и базовых эндпоинтов",
                    row=CheckRow(status=status, score=score, evidence_json=evidence_json),
                )
            ],
            module_payload=module_payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        if not payload:
            logger.debug("[availability] нет данных для сохранения: domain=%s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[availability] домен %s отсутствовал — создаём запись", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                AvailabilityCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    scheme=item.get("scheme"),
                    path=item.get("path"),
                    attempt_no=item.get("attempt_no"),
                    status_bucket=item.get("status_bucket"),
                    http_status=item.get("http_status"),
                    final_url=item.get("final_url"),
                    reason_code=item.get("reason_code"),
                    elapsed_ms=item.get("elapsed_ms"),
                    ttfb_ms=item.get("ttfb_ms"),
                    response_bytes=item.get("response_bytes"),
                    content_type=item.get("content_type"),
                    redirect_count=item.get("redirect_count"),
                    redirect_cross_scheme=item.get("redirect_cross_scheme"),
                    redirect_cross_domain=item.get("redirect_cross_domain"),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[availability] сохранено записей: domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "template": "audit_modules/availability/availability.html",
                "name": self.name,
                "description": self.description,
                "summary": {},
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
                "headline": "Данные отсутствуют",
                "kpis": {},
                "insights": [],
                "checks": {
                    "schemes": ["https", "http"],
                    "endpoints": list(self.ENDPOINTS),
                    "attempts_per_endpoint": self.MAX_ATTEMPTS,
                },
                "timeline": [],
                "http_profile": {},
                "endpoints_map": {},
            }

        now_ts = int(time.time())
        ts_24h = now_ts - 24 * 3600
        ts_7d = now_ts - 7 * 24 * 3600

        def load_window(ts_from: int) -> list[AvailabilityCheck]:
            return (
                session.query(AvailabilityCheck)
                .filter(AvailabilityCheck.domain_id == domain_record.id)
                .filter(AvailabilityCheck.checked_ts >= ts_from)
                .filter(AvailabilityCheck.path == self.PRIMARY_ENDPOINT)
                .order_by(AvailabilityCheck.checked_ts.desc())
                .all()
            )

        rows_24h = load_window(ts_24h)
        rows_7d = load_window(ts_7d)

        def summarize(rows: list[AvailabilityCheck]) -> dict:
            if not rows:
                return {
                    "count": 0,
                    "uptime_pct": None,
                    "median_ttfb_ms": None,
                    "median_elapsed_ms": None,
                    "status_buckets": {},
                }

            ok_cnt = 0
            ttfb_values: list[int] = []
            elapsed_values: list[int] = []
            bucket_counter: dict[str, int] = {}

            for r in rows:
                bucket = r.status_bucket or _status_bucket(r.http_status)
                bucket_counter[bucket] = bucket_counter.get(bucket, 0) + 1
                if bucket in ("2xx", "3xx", "restricted"):
                    ok_cnt += 1
                if isinstance(r.ttfb_ms, int):
                    ttfb_values.append(r.ttfb_ms)
                if isinstance(r.elapsed_ms, int):
                    elapsed_values.append(r.elapsed_ms)

            uptime_pct = round(ok_cnt * 100.0 / max(1, len(rows)), 2)
            return {
                "count": len(rows),
                "uptime_pct": uptime_pct,
                "median_ttfb_ms": int(statistics.median(ttfb_values)) if ttfb_values else None,
                "median_elapsed_ms": int(statistics.median(elapsed_values)) if elapsed_values else None,
                "status_buckets": bucket_counter,
            }

        summary = {
            "last_24h": summarize(rows_24h),
            "last_7d": summarize(rows_7d),
        }

        last_rows = (
            session.query(AvailabilityCheck)
            .filter(AvailabilityCheck.domain_id == domain_record.id)
            .order_by(AvailabilityCheck.checked_ts.desc())
            .limit(20)
            .all()
        )

        entries = []
        for row in last_rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            parts = []
            if row.http_status is not None:
                parts.append(f"HTTP {row.http_status}")
            else:
                parts.append("no_response")
            if row.reason_code:
                parts.append(f"reason={row.reason_code}")
            if row.elapsed_ms is not None:
                parts.append(f"elapsed={row.elapsed_ms}ms")
            if row.ttfb_ms is not None:
                parts.append(f"ttfb={row.ttfb_ms}ms")

            entries.append(
                {
                    "timestamp": timestamp,
                    "status": row.status_bucket or _status_bucket(row.http_status),
                    "message": " | ".join(parts),
                    "details": {
                        "scheme": row.scheme,
                        "path": row.path,
                        "attempt_no": row.attempt_no,
                        "final_url": row.final_url,
                        "content_type": row.content_type,
                        "response_bytes": row.response_bytes,
                        "redirect_count": row.redirect_count,
                        "redirect_cross_scheme": row.redirect_cross_scheme,
                        "redirect_cross_domain": row.redirect_cross_domain,
                    },
                }
            )

        # Достаём “свежий” evidence_json из последней записи по /
        http_profile = {}
        endpoints_map = {}
        try:
            latest_root = (
                session.query(AvailabilityCheck)
                .filter(AvailabilityCheck.domain_id == domain_record.id)
                .filter(AvailabilityCheck.path == "/")
                .order_by(AvailabilityCheck.checked_ts.desc())
                .first()
            )
            if latest_root and latest_root.evidence_json:
                ev = json.loads(latest_root.evidence_json)
                http_profile = ev.get("http_profile") or {}
                endpoints_map = ev.get("endpoints_map") or {}
        except Exception as e:
            logger.warning("[availability] failed to parse evidence_json domain=%s err=%s", domain, e)

        s24 = summary.get("last_24h", {}) or {}
        uptime24 = s24.get("uptime_pct")
        buckets24 = s24.get("status_buckets") or {}

        if uptime24 is None:
            headline = "Нет данных"
        elif uptime24 >= 99.99:
            headline = "Сайт стабильно доступен"
        elif uptime24 >= 90:
            headline = "Сайт доступен, но нестабилен"
        else:
            headline = "Обнаружены проблемы с доступностью"

        insights: list[str] = []
        if uptime24 is not None and uptime24 < 100:
            insights.append("За последние 24 часа ответы нестабильны (аптайм ниже 100%).")
        if "5xx" in buckets24:
            insights.append("Зафиксированы ошибки 5xx (сбой на стороне сервера).")
        if "no_response" in buckets24:
            insights.append("Есть проверки без ответа (таймаут/DNS/TLS/соединение).")

        # HTTP-профиль: подсказки
        if http_profile:
            if http_profile.get("canonical_scheme") != "https":
                insights.append("Канонический протокол не HTTPS — рекомендуется принудительно использовать HTTPS.")
            hsts = http_profile.get("hsts") or {}
            if http_profile.get("canonical_scheme") == "https" and not hsts.get("present"):
                insights.append("HSTS не обнаружен — рекомендуется включить Strict-Transport-Security.")
            if http_profile.get("www_non_www_detected") == "www_non_www":
                insights.append("Обнаружено переключение www/non-www — проверьте единый канонический хост.")

        # Таймлайн — последние 10 событий
        timeline = []
        for e in entries[:10]:
            status = e["status"]
            icon = "✅" if status in ("2xx", "3xx", "restricted") else "❌" if status in ("4xx", "5xx") else "⚠️"
            meta = e.get("details", {}) or {}
            timeline.append(
                {
                    "timestamp": e["timestamp"],
                    "status": status,
                    "title": f"{icon} {e['message']}",
                    "meta": {
                        "scheme": meta.get("scheme"),
                        "path": meta.get("path"),
                        "attempt_no": meta.get("attempt_no"),
                    },
                }
            )

        empty_message = "Проверки доступности ещё не выполнялись." if not entries else None

        return {
            "key": self.key,
            "template": "audit_modules/availability/availability.html",
            "name": self.name,
            "description": self.description,

            "summary": summary,
            "entries": entries,
            "empty_message": empty_message,

            "headline": headline,
            "kpis": {
                "uptime_24h_pct": summary["last_24h"].get("uptime_pct"),
                "uptime_7d_pct": summary["last_7d"].get("uptime_pct"),
                "median_ttfb_ms": summary["last_24h"].get("median_ttfb_ms"),
                "median_elapsed_ms": summary["last_24h"].get("median_elapsed_ms"),
            },
            "checks": {
                "schemes": ["https", "http"],
                "endpoints": list(self.ENDPOINTS),
                "attempts_per_endpoint": self.MAX_ATTEMPTS,
                "redirects_allowed": True,
            },
            "insights": insights,
            "timeline": timeline,

            # NEW
            "http_profile": http_profile,
            "endpoints_map": endpoints_map,
        }


class AvailabilityCheck(Base):
    __tablename__ = "availability_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)

    checked_ts = Column(Integer, nullable=False)

    scheme = Column(String(8), nullable=True)
    path = Column(String(128), nullable=True)
    attempt_no = Column(Integer, nullable=True)

    status_bucket = Column(String(32), nullable=True)
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)

    reason_code = Column(String(64), nullable=True)

    elapsed_ms = Column(Integer, nullable=True)
    ttfb_ms = Column(Integer, nullable=True)
    response_bytes = Column(Integer, nullable=True)
    content_type = Column(Text, nullable=True)

    redirect_count = Column(Integer, nullable=True)
    redirect_cross_scheme = Column(String(8), nullable=True)  # yes/no
    redirect_cross_domain = Column(String(8), nullable=True)  # yes/no

    evidence_json = Column(Text, nullable=True)
