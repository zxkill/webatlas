from __future__ import annotations

import json
import logging
import statistics
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL без query/fragment, чтобы не загрязнять логи/БД."""
    return urlunparse((scheme, domain, path, "", "", ""))


def _status_bucket(http_status: int | None) -> str:
    """Класс статуса для быстрых сводок."""
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


class AvailabilityModule:
    """
    Модуль доступности: “первый слой” аудита.
    Делает устойчивое определение reachable/healthy/restricted/down и собирает метрики,
    которые пригодятся всем последующим проверкам.
    """

    key = "availability"
    name = "Доступность сайта"
    description = "Проверяет доступность домена по HTTP/HTTPS, метрики ответа и устойчивость результата."
    depends_on: tuple[str, ...] = ()

    # Конфиг по умолчанию (можно позже вынести в config.yaml)
    MAX_ATTEMPTS = 3
    PRIMARY_ENDPOINT = "/"
    SECONDARY_ENDPOINTS = ("/robots.txt", "/favicon.ico")
    ENDPOINTS = (PRIMARY_ENDPOINT, *SECONDARY_ENDPOINTS)

    async def run(self, context: AuditContext) -> ModuleResult:
        domain = context.domain

        evidence: dict = {
            "domain": domain,
            "checked_ts": int(time.time()),
            "schemes": {},
            "summary": {},
        }
        module_payload: list[dict] = []

        # Итоговое решение по домену (канонический ответ — первый “полезный”)
        chosen = {
            "reachable": False,
            "healthy": False,
            "restricted": False,
            "used_scheme": None,
            "used_path": None,
            "canonical_url": None,
            "final_host": None,
            "set_cookie": "",
            "headers": {},
        }

        # Проверяем https потом http
        for scheme in ("https", "http"):
            scheme_block = {"attempts": [], "best": None}
            evidence["schemes"][scheme] = scheme_block

            best_attempt: AttemptResult | None = None
            best_score = -1

            for path in self.ENDPOINTS:
                url = _ensure_url(scheme, domain, path)

                # Ретраи на каждый endpoint
                endpoint_attempts: list[AttemptResult] = []

                for attempt_no in range(1, self.MAX_ATTEMPTS + 1):
                    logger.info(
                        "[availability] %s attempt=%s/%s url=%s",
                        domain,
                        attempt_no,
                        self.MAX_ATTEMPTS,
                        url,
                    )

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
                        )
                    else:
                        resp = res.response
                        content_type = resp.headers.get("Content-Type")
                        redirects = [
                            {"url": h.url, "status": h.status, "location": h.location}
                            for h in resp.redirects
                        ]
                        # Определяем “кросс” редиректы
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
                            content_type=content_type,
                            redirect_count=len(resp.redirects),
                            redirect_cross_scheme=redirect_cross_scheme,
                            redirect_cross_domain=redirect_cross_domain,
                            redirects=redirects,
                        )

                    endpoint_attempts.append(ar)

                    # Запись в payload (таблица availability_checks)
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
                            if ar.redirect_cross_scheme is not None
                            else None,
                            "redirect_cross_domain": "yes" if ar.redirect_cross_domain else "no"
                            if ar.redirect_cross_domain is not None
                            else None,
                            "evidence_json": None,  # заполним ниже одним общим evidence, чтобы не раздувать
                        }
                    )

                # Определяем лучший результат по endpoint
                # Приоритет: 2xx/3xx > 401/403 > 4xx/5xx > no_response
                def endpoint_rank(a: AttemptResult) -> int:
                    if not a.ok:
                        return 0
                    if a.http_status is None:
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

                # Берём максимум по rank, а среди равных — минимальный elapsed
                candidate = max(
                    endpoint_attempts,
                    key=lambda a: (endpoint_rank(a), -(a.elapsed_ms or 10 ** 9)),
                )

                # Оценка кандидата для выбора “канонического” ответа
                # (не финальный score домена — только выбор лучшего ответа)
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

            scheme_block["best"] = best_attempt.__dict__ if best_attempt else None

            # Если по схеме есть хоть какой-то ответ — считаем reachable для этой схемы
            scheme_reachable = best_attempt is not None and (
                    (best_attempt.ok and best_attempt.http_status is not None) or (best_attempt.reason_code is None)
            )
            scheme_block["reachable"] = bool(scheme_reachable)

            # Если нашли хороший кандидат (2xx/3xx или restricted) — выбираем его и завершаем
            if best_attempt and best_attempt.ok and best_attempt.http_status is not None:
                if 200 <= best_attempt.http_status <= 399:
                    chosen["reachable"] = True
                    chosen["healthy"] = True
                elif best_attempt.http_status in (401, 403):
                    chosen["reachable"] = True
                    chosen["restricted"] = True

                if chosen["reachable"]:
                    chosen["used_scheme"] = scheme
                    # path восстановим по final_url (если можно) иначе оставим None
                    chosen["canonical_url"] = best_attempt.final_url
                    try:
                        chosen["final_host"] = urlparse(best_attempt.final_url or "").netloc or None
                    except Exception:
                        chosen["final_host"] = None
                    break

        # --- Стабильность / Flaky ---
        # Правило: если по выбранной схеме в рамках / есть несколько попыток и они сильно расходятся — flaky.
        flaky = False
        attempts_for_flaky: list[int | None] = []
        if chosen["used_scheme"]:
            sch = evidence["schemes"].get(chosen["used_scheme"], {})
            # Берём только endpoint "/" для флапов
            for ep in sch.get("attempts", []):
                if ep.get("path") == "/":
                    for a in ep.get("attempts", []):
                        attempts_for_flaky.append(a.get("http_status"))
        uniq = {x for x in attempts_for_flaky if x is not None}
        if len(uniq) >= 2:
            flaky = True

        # --- Скоринг ---
        # Доменный скор — отдельный от “внутреннего ранга”
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

        # Добавка за производительность (если есть)
        # Берём ttfb по выбранному каноническому ответу — в evidence он есть внутри схемы, но проще:
        # вытащим минимум ttfb среди успешных ответов на выбранной схеме.
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
            else:
                perf_bonus = 0

        # Штраф за flaky
        if flaky:
            score = max(0, score - 10)

        score = min(100, score + perf_bonus)

        evidence["summary"] = {
            "chosen": chosen,
            "flaky": flaky,
            "score": score,
        }

        # Подставим единый evidence_json в каждую строку payload (чтобы не раздувать разными JSON)
        evidence_json = json.dumps(evidence, ensure_ascii=False)
        for item in module_payload:
            item["evidence_json"] = evidence_json

        # Сохраняем в context данные, полезные для следующих модулей
        context.data["availability"] = {
            "reachable": chosen["reachable"],
            "healthy": chosen["healthy"],
            "restricted": chosen["restricted"],
            "used_scheme": chosen["used_scheme"],
            "canonical_url": chosen["canonical_url"],
            "final_host": chosen["final_host"],
            "flaky": flaky,
        }

        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка доступности и устойчивости ответов",
                    row=CheckRow(
                        status=status,
                        score=score,
                        evidence_json=evidence_json,
                    ),
                )
            ],
            module_payload=module_payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет результаты проверок доступности в таблицу availability_checks.
        """
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
        """
        Backward-compatible report:
        - entries: старый формат для текущего UI (таблица + счетчик)
        - summary: агрегаты (как раньше)
        - empty_message: для UI
        - + headline/kpis/insights/checks/timeline: новый “понятный” слой для будущего UI
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "summary": {},
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
                # v2
                "headline": "Данные отсутствуют",
                "kpis": {},
                "insights": [],
                "checks": {
                    "schemes": ["https", "http"],
                    "endpoints": list(self.ENDPOINTS),
                    "attempts_per_endpoint": self.MAX_ATTEMPTS,
                },
                "timeline": [],
            }

        now_ts = int(time.time())
        ts_24h = now_ts - 24 * 3600
        ts_7d = now_ts - 7 * 24 * 3600

        def load_window(ts_from: int) -> list[AvailabilityCheck]:
            return (
                session.query(AvailabilityCheck)
                .filter(AvailabilityCheck.domain_id == domain_record.id)
                .filter(AvailabilityCheck.checked_ts >= ts_from)
                .filter(AvailabilityCheck.path == self.PRIMARY_ENDPOINT)  # <-- ВАЖНО
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
                    "top_reason_codes": [],
                    "status_buckets": {},
                }

            ok_cnt = 0
            ttfb_values: list[int] = []
            elapsed_values: list[int] = []
            reason_counter: dict[str, int] = {}
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

                if r.reason_code:
                    reason_counter[r.reason_code] = reason_counter.get(r.reason_code, 0) + 1

            def top_n(counter: dict[str, int], n: int = 5) -> list[dict]:
                items = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]
                return [{"reason_code": k, "count": v} for k, v in items]

            uptime_pct = round(ok_cnt * 100.0 / max(1, len(rows)), 2)

            return {
                "count": len(rows),
                "uptime_pct": uptime_pct,
                "median_ttfb_ms": int(statistics.median(ttfb_values)) if ttfb_values else None,
                "median_elapsed_ms": int(statistics.median(elapsed_values)) if elapsed_values else None,
                "top_reason_codes": top_n(reason_counter),
                "status_buckets": bucket_counter,
            }

        summary = {
            "last_24h": summarize(rows_24h),
            "last_7d": summarize(rows_7d),
        }

        # ---------- Старый UI: entries ----------
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

        # ---------- Новый UX-слой (v2) ----------
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
        if "4xx" in buckets24:
            insights.append("Зафиксированы ошибки 4xx (возможна неверная страница/редиректы/эндпоинт).")
        if "5xx" in buckets24:
            insights.append("Зафиксированы ошибки 5xx (сбой на стороне сервера).")
        if "no_response" in buckets24:
            insights.append("Есть проверки без ответа (таймаут/DNS/TLS/соединение).")

        # --- Диагностика secondary endpoints (НЕ влияет на аптайм/вердикт) ---
        secondary_latest = (
            session.query(AvailabilityCheck)
            .filter(AvailabilityCheck.domain_id == domain_record.id)
            .filter(AvailabilityCheck.path.in_(list(self.SECONDARY_ENDPOINTS)))
            .order_by(AvailabilityCheck.checked_ts.desc())
            .limit(200)
            .all()
        )

        # Возьмём по каждому secondary endpoint последний результат
        latest_by_path: dict[str, AvailabilityCheck] = {}
        for r in secondary_latest:
            if r.path and r.path not in latest_by_path:
                latest_by_path[r.path] = r

        secondary_notes: list[str] = []
        for path in self.SECONDARY_ENDPOINTS:
            r = latest_by_path.get(path)
            if not r:
                continue

            bucket = r.status_bucket or _status_bucket(r.http_status)

            # Текст формируем максимально “человеческий”
            if bucket == "2xx":
                secondary_notes.append(f"{path}: доступен (HTTP {r.http_status}).")
            elif bucket == "3xx":
                secondary_notes.append(f"{path}: редирект (HTTP {r.http_status}).")
            elif bucket == "restricted":
                secondary_notes.append(
                    f"{path}: закрыт (HTTP {r.http_status}) — ресурс существует, но требуется доступ.")
            elif bucket == "4xx":
                # 404 для favicon/robots — нормальная ситуация, это НЕ "недоступность сайта"
                if r.http_status == 404:
                    secondary_notes.append(f"{path}: отсутствует (HTTP 404) — не влияет на доступность сайта.")
                else:
                    secondary_notes.append(
                        f"{path}: ошибка клиента (HTTP {r.http_status}) — проверьте маршрут/настройки.")
            elif bucket == "5xx":
                secondary_notes.append(
                    f"{path}: ошибка сервера (HTTP {r.http_status}) — возможно влияет на статические ресурсы/индексацию.")
            else:
                # no_response / other
                reason = f", причина: {r.reason_code}" if r.reason_code else ""
                secondary_notes.append(f"{path}: нет ответа ({bucket}){reason}.")

        # Добавляем в insights с пометкой “Диагностика”
        if secondary_notes:
            insights.append("Диагностика: " + " ".join(secondary_notes))

        # Чуть “человечнее” таймлайн (можно потом в UI)
        timeline = []
        for e in entries[:10]:
            status = e["status"]
            icon = "✅" if status in ("2xx", "3xx", "restricted") else "❌" if status in ("4xx", "5xx") else "⚠️"
            meta = e.get("details", {}) or {}
            ttfb_ms = None
            elapsed_ms = None
            # вытаскиваем из message без парсинга: проще использовать details позже,
            # но сейчас уже есть row.ttfb_ms/elapsed_ms в таблице — UI может показать из details при желании.
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

            # старое — для текущего UI
            "summary": summary,
            "entries": entries,
            "empty_message": empty_message,

            # новое — для будущего UI
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
        }


class AvailabilityCheck(Base):
    """Таблица результатов проверок доступности домена (расширенная)."""

    __tablename__ = "availability_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)

    checked_ts = Column(Integer, nullable=False)

    scheme = Column(String(8), nullable=True)
    path = Column(String(128), nullable=True)

    attempt_no = Column(Integer, nullable=True)

    # Упрощённая классификация статусов для отчётов/аналитики
    status_bucket = Column(String(32), nullable=True)

    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)

    # Нормализованный код причины при ошибке
    reason_code = Column(String(64), nullable=True)

    # Метрики
    elapsed_ms = Column(Integer, nullable=True)
    ttfb_ms = Column(Integer, nullable=True)
    response_bytes = Column(Integer, nullable=True)
    content_type = Column(Text, nullable=True)

    # Редиректы
    redirect_count = Column(Integer, nullable=True)
    redirect_cross_scheme = Column(String(8), nullable=True)  # yes/no
    redirect_cross_domain = Column(String(8), nullable=True)  # yes/no

    evidence_json = Column(Text, nullable=True)
