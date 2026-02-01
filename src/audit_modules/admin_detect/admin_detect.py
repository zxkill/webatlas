from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AdminPanelUpdate, AuditContext, ModuleResult
from src.webapp_db import AdminPanelRow, Base, Domain, create_domain

logger = logging.getLogger(__name__)


# -----------------------------
# Helpers
# -----------------------------

def _ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL без query/fragment (единый формат для отчёта и доказательств)."""
    return urlunparse((scheme, domain, path, "", "", ""))


def _host_only(url: str | None) -> str | None:
    if not url:
        return None
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return None
        return urlunparse((p.scheme, p.netloc, "", "", "", ""))
    except Exception:
        return None


def _safe_getattr(obj: Any, name: str, default=None):
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _hget(headers: dict[str, str] | None, key: str) -> str:
    """case-insensitive header get"""
    if not headers:
        return ""
    if key in headers:
        return headers.get(key, "") or ""
    low = key.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v or ""
    return ""


def _normalize_path(path: str) -> str:
    if not path.startswith("/"):
        return "/" + path
    return path


# -----------------------------
# Signatures
# -----------------------------

@dataclass(frozen=True)
class AdminSignature:
    key: str  # bitrix / wordpress / joomla / generic / ...
    label: str  # human label
    paths: list[str]  # candidate paths
    # optional hints: increase confidence and reduce false positives
    title_hints: list[re.Pattern] = None
    body_hints: list[re.Pattern] = None
    header_hints: list[tuple[str, re.Pattern]] = None
    cookie_hints: list[re.Pattern] = None
    priority: int = 50  # bigger => checked earlier

    def __post_init__(self):
        # dataclass frozen: cannot mutate; keep None checks in code
        pass


def _rx_list(items: list[str]) -> list[re.Pattern]:
    return [re.compile(x, re.I) for x in items]


SIGNATURES: list[AdminSignature] = [
    AdminSignature(
        key="bitrix",
        label="1C-Bitrix admin",
        paths=["/bitrix/admin/"],
        title_hints=_rx_list([r"bitrix", r"1c[- ]bitrix", r"администр"]),
        body_hints=_rx_list([r"/bitrix/", r"BX\.", r"bitrix_sessid", r"AUTH_FORM"]),
        cookie_hints=_rx_list([r"BITRIX_SM_"]),
        priority=100,
    ),
    AdminSignature(
        key="wordpress",
        label="WordPress admin",
        paths=["/wp-admin/", "/wp-login.php"],
        title_hints=_rx_list([r"wordpress", r"log ?in", r"sign ?in"]),
        body_hints=_rx_list([r"/wp-content/", r"/wp-includes/", r"name=[\"']log[\"']", r"id=[\"']loginform[\"']"]),
        cookie_hints=_rx_list([r"wordpress_(logged_in|sec)_"]),
        priority=95,
    ),
    AdminSignature(
        key="joomla",
        label="Joomla administrator",
        paths=["/administrator/"],
        title_hints=_rx_list([r"joomla", r"administrator", r"control panel"]),
        body_hints=_rx_list([r"/administrator/", r"com_login", r"joomla\."]),
        priority=90,
    ),
    AdminSignature(
        key="drupal",
        label="Drupal login",
        paths=["/user/login"],
        title_hints=_rx_list([r"drupal", r"log ?in"]),
        body_hints=_rx_list([r"drupalSettings", r"name=[\"']name[\"']", r"/user/password"]),
        priority=80,
    ),
    AdminSignature(
        key="opencart",
        label="OpenCart admin",
        paths=["/admin/", "/administrator/"],
        title_hints=_rx_list([r"opencart", r"administration", r"log ?in"]),
        body_hints=_rx_list([r"route=common/login", r"index\.php\?route=", r"OpenCart"]),
        priority=75,
    ),
    # Generic / framework-ish
    AdminSignature(
        key="generic",
        label="Generic admin",
        paths=["/admin", "/admin/", "/login", "/signin", "/panel", "/cp", "/backend"],
        title_hints=_rx_list([r"admin", r"dashboard", r"log ?in", r"sign ?in", r"панел", r"вход"]),
        body_hints=_rx_list([r"csrf", r"password", r"username|login", r"two[- ]factor|2fa", r"auth"]),
        header_hints=[("WWW-Authenticate", re.compile(r".+", re.I))],
        priority=30,
    ),
]


# -----------------------------
# Classification rules
# -----------------------------

def _status_bucket(http_status: int | None) -> str:
    """
    Понятная классификация результата проверки.
    """
    if http_status is None:
        return "no_response"
    if http_status == 200:
        return "accessible"  # доступна страница (логин/панель)
    if http_status in (301, 302, 303, 307, 308):
        return "redirect"  # редирект на логин/канонический URL
    if http_status in (401, 403):
        return "restricted"  # доступ ограничен (часто хороший признак панели)
    if http_status == 404:
        return "not_found"
    if 500 <= http_status <= 599:
        return "server_error"
    return "other"


def _score_hit(
        *,
        status: int | None,
        final_url: str | None,
        sig: AdminSignature,
        headers: dict[str, str] | None,
        body_text: str,
        set_cookie_raw: str,
) -> tuple[int, list[dict[str, str]]]:
    """
    Score 0..100 + explain signals.
    - Для специфичных сигнатур (bitrix/wp/joomla) достаточно статуса+минимальных hints.
    - Для generic стараемся требовать hints, чтобы не ловить “/admin -> 200 (пустая страница)”.
    """
    score = 0
    signals: list[dict[str, str]] = []

    if status is None:
        return 0, [{"type": "error", "value": "no response"}]

    bucket = _status_bucket(status)

    # базовый вклад от статуса
    if bucket == "accessible":
        score += 40
        signals.append({"type": "status", "value": "HTTP 200"})
    elif bucket == "redirect":
        score += 30
        signals.append({"type": "status", "value": f"HTTP {status} redirect"})
    elif bucket == "restricted":
        score += 35
        signals.append({"type": "status", "value": f"HTTP {status} restricted"})
    elif bucket == "not_found":
        score += 0
        signals.append({"type": "status", "value": "HTTP 404"})
    elif bucket == "server_error":
        score += 10
        signals.append({"type": "status", "value": f"HTTP {status} server error"})
    else:
        score += 5
        signals.append({"type": "status", "value": f"HTTP {status}"})

    # редирект-таргет (если ведёт на login/admin)
    if final_url and bucket == "redirect":
        try:
            p = urlparse(final_url)
            if re.search(r"(login|signin|auth|admin|panel)", p.path, re.I):
                score += 15
                signals.append({"type": "redirect", "value": f"target path looks like auth: {p.path}"})
        except Exception:
            pass

    # title/body hints (лучше брать body кусок, чем ничего)
    title_hints = sig.title_hints or []
    body_hints = sig.body_hints or []
    header_hints = sig.header_hints or []
    cookie_hints = sig.cookie_hints or []

    # Тайтл — попробуем вытащить очень грубо (без парсера)
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
    title = (m.group(1).strip()[:200] if m else "")

    for rx in title_hints:
        if title and rx.search(title):
            score += 12
            signals.append({"type": "title", "value": rx.pattern})
            break

    for rx in body_hints:
        if body_text and rx.search(body_text):
            score += 12
            signals.append({"type": "body", "value": rx.pattern})
            break

    for hk, rx in header_hints:
        hv = _hget(headers, hk)
        if hv and rx.search(hv):
            score += 10
            signals.append({"type": "header", "value": f"{hk}: {hv[:160]}"})
            break

    for rx in cookie_hints:
        if set_cookie_raw and rx.search(set_cookie_raw):
            score += 15
            signals.append({"type": "cookie", "value": rx.pattern})
            break

    # anti false-positive for generic:
    if sig.key == "generic":
        # Если 200/redirect/restricted без любых hints — резко понижаем уверенность
        has_real_hints = any(s["type"] in ("title", "body", "header", "cookie", "redirect") for s in signals)
        if not has_real_hints and bucket in ("accessible", "redirect", "restricted"):
            score = min(score, 25)
            signals.append({"type": "guard", "value": "generic without hints => downscore"})
    else:
        # Для специфичных сигнатур достаточно статуса + хотя бы чего-то
        pass

    return min(score, 100), signals


def _verdict(score: int, bucket: str) -> str:
    """
    verdict:
      - yes: высокая уверенность, это админка/логин
      - maybe: похоже, но не уверены
      - no: не найдено
    """
    if score >= 70 and bucket in ("accessible", "redirect", "restricted"):
        return "yes"
    if score >= 35 and bucket in ("accessible", "redirect", "restricted"):
        return "maybe"
    return "no"


def _severity(bucket: str, verdict: str) -> str:
    """
    severity для UI pill:
      - ok: found but restricted (401/403) OR no findings
      - warning: redirects/maybe
      - critical: accessible login/panel with high confidence
    """
    if verdict == "no":
        return "ok"
    if bucket == "restricted":
        return "ok"
    if bucket == "accessible" and verdict == "yes":
        return "critical"
    return "warning"


# -----------------------------
# Module
# -----------------------------

class AdminDetectModule:
    """
    Улучшенный модуль поиска админок/логинов.

    Отличия от текущей версии:
    - сигнатуры: path + hints (title/body/headers/cookies)
    - снижение ложноположительных для generic путей
    - приоритизация путей по найденной CMS (если cms_detect уже дал подсказку)
    - ограниченная конкурентность (быстрее, но без перегруза)
    - отчёт v2: headline/kpis/insights/timeline + список попаданий и последних проверок
    """

    key = "admin_detect"
    name = "Поиск админок / логинов"
    description = "Инвентаризация потенциальных входов (CMS/панели): пути + контентные сигнатуры."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        availability = context.data.get("availability", {})
        if not availability or not availability.get("reachable"):
            logger.info("[admin_detect] skip: domain unreachable: %s", context.domain)
            return ModuleResult()

        scheme = availability.get("used_scheme") or "https"

        # CMS подсказка (если уже выполнен cms_detect)
        cms_hint = None
        try:
            cms_summary = (context.data.get("cms", {}) or {}).get("summary", {}) or {}
            detected = cms_summary.get("detected") or []
            if detected:
                cms_hint = detected[0].get("cms_key")
        except Exception:
            cms_hint = None

        # Список проверок: сначала релевантные сигнатуры, потом остальные
        sigs = sorted(SIGNATURES, key=lambda s: s.priority, reverse=True)
        if cms_hint:
            sigs = sorted(sigs, key=lambda s: (0 if s.key == cms_hint else 1, -s.priority))

        # раскрываем в задачи (sig + path)
        tasks: list[dict[str, Any]] = []
        for sig in sigs:
            for p in sig.paths:
                tasks.append({"sig": sig, "path": _normalize_path(p)})

        # ограничим объём (без агрессивного перебора)
        max_checks = 18
        tasks = tasks[:max_checks]

        checked_ts = int(time.time())

        # Доказательства по запуску
        evidence: dict[str, Any] = {
            "domain": context.domain,
            "scheme": scheme,
            "cms_hint": cms_hint,
            "checked_ts": checked_ts,
            "checks": [],
            "hits": [],
        }

        payload: list[dict] = []
        hits: list[dict[str, Any]] = []

        # ограниченная конкурентность на уровне модуля (http-клиент всё равно имеет свой rps/лимиты)
        sem = asyncio.Semaphore(6)

        async def _check_one(sig: AdminSignature, path: str) -> dict[str, Any]:
            url = _ensure_url(scheme, context.domain, path)
            async with sem:
                logger.debug("[admin_detect] check url=%s sig=%s", url, sig.key)
                resp = await context.http.fetch(context.session, url, allow_redirects=False)

            if resp is None:
                return {
                    "ok": False,
                    "url": url,
                    "sig_key": sig.key,
                    "label": sig.label,
                    "path": path,
                    "status": None,
                    "final_url": None,
                    "headers": None,
                    "body": "",
                    "set_cookie": "",
                }

            # максимально аккуратно: не предполагаем интерфейс resp, берём best-effort
            status = _safe_getattr(resp, "status", None)
            final_url = _safe_getattr(resp, "final_url", None)
            headers = _safe_getattr(resp, "headers", None) or {}
            body_bytes = _safe_getattr(resp, "body", b"") or b""
            # ограничим анализ тела (без лишней памяти)
            if isinstance(body_bytes, (bytes, bytearray)):
                body_bytes = body_bytes[:30000]
                body_text = body_bytes.decode("utf-8", errors="replace")
            else:
                body_text = str(body_bytes)[:30000]

            set_cookie = _hget(headers, "Set-Cookie")

            return {
                "ok": True,
                "url": url,
                "sig_key": sig.key,
                "label": sig.label,
                "path": path,
                "status": status,
                "final_url": final_url,
                "headers": headers,
                "body": body_text,
                "set_cookie": set_cookie,
            }

        # запускаем
        results = await asyncio.gather(*[_check_one(t["sig"], t["path"]) for t in tasks], return_exceptions=False)

        # анализ
        best: dict[str, Any] | None = None
        for r in results:
            sig_key = r["sig_key"]
            sig = next((s for s in sigs if s.key == sig_key), None)
            if sig is None:
                continue

            status = r["status"]
            final_url = r["final_url"]
            headers = r["headers"]
            body_text = r["body"]
            set_cookie_raw = r["set_cookie"] or ""

            bucket = _status_bucket(status)
            score, signals = _score_hit(
                status=status,
                final_url=final_url,
                sig=sig,
                headers=headers,
                body_text=body_text,
                set_cookie_raw=set_cookie_raw,
            )
            verdict = _verdict(score, bucket)
            sev = _severity(bucket, verdict)

            item = {
                "checked_ts": checked_ts,
                "panel_key": sig.key,
                "label": sig.label,
                "path": r["path"],
                "status": verdict,  # yes/maybe/no
                "severity": sev,  # ok/warning/critical
                "bucket": bucket,  # accessible/redirect/restricted/...
                "score": score,
                "http_status": status,
                "final_url": final_url,
                "evidence": {
                    "url": r["url"],
                    "signals": signals,
                },
            }

            evidence["checks"].append(
                {
                    "path": r["path"],
                    "panel_key": sig.key,
                    "http_status": status,
                    "bucket": bucket,
                    "score": score,
                    "status": verdict,
                    "final_url": final_url,
                }
            )

            payload.append(
                {
                    "checked_ts": checked_ts,
                    "panel_key": sig.key,
                    "path": r["path"],
                    "status": verdict,
                    "http_status": status,
                    "final_url": final_url,
                    "evidence_json": json.dumps(item, ensure_ascii=False),
                }
            )

            if verdict in ("yes", "maybe"):
                hits.append(item)

                if best is None:
                    best = item
                else:
                    # выбираем лучший по score, затем по “полезности” bucket
                    w_bucket = {"accessible": 3, "redirect": 2, "restricted": 1}.get(bucket, 0)
                    w_best = {"accessible": 3, "redirect": 2, "restricted": 1}.get(best.get("bucket", ""), 0)
                    if (score, w_bucket) > (best.get("score", 0), w_best):
                        best = item

        hits.sort(key=lambda x: (x.get("score", 0), x.get("bucket", "")), reverse=True)
        evidence["hits"] = [{"panel_key": h["panel_key"], "path": h["path"], "score": h["score"], "bucket": h["bucket"],
                             "final_url": h["final_url"]} for h in hits]

        # Итоговый статус для общей таблицы AdminPanelRow
        # Здесь лучше отражать факт нахождения входа, а не “опасность”.
        found_any = any(h["status"] == "yes" for h in hits)
        maybe_any = any(h["status"] == "maybe" for h in hits)

        admin_status = "yes" if found_any else "maybe" if maybe_any else "no"

        admin_row = AdminPanelRow(
            status=admin_status,
            http_status=(best or {}).get("http_status"),
            final_url=(best or {}).get("final_url"),
            evidence_json=json.dumps(evidence, ensure_ascii=False),
        )

        logger.info(
            "[admin_detect] domain=%s cms_hint=%s status=%s hits=%s checked=%s",
            context.domain,
            cms_hint,
            admin_status,
            len(hits),
            len(results),
        )

        return ModuleResult(
            admin_updates=[AdminPanelUpdate(panel_key="admin_detect", row=admin_row)],
            module_payload=payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """Сохраняет историю проверок админок в таблицу admin_detect_checks."""
        if not payload:
            logger.debug("[admin_detect] persist: no payload for %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[admin_detect] persist: create domain=%s before save", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                AdminDetectCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    panel_key=item.get("panel_key", "generic"),
                    path=item.get("path", ""),
                    status=item.get("status", "no"),  # yes/maybe/no
                    http_status=item.get("http_status"),
                    final_url=item.get("final_url"),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[admin_detect] persist: saved domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Report v2:
        - headline/kpis/insights/timeline
        - hits (лучшие находки)
        - entries (последние проверки)
        """
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Нет данных по домену",
                "kpis": {},
                "insights": [],
                "timeline": [],
                "hits": [],
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
            }

        rows = (
            session.query(AdminDetectCheck)
            .filter(AdminDetectCheck.domain_id == domain_record.id)
            .order_by(AdminDetectCheck.checked_ts.desc())
            .limit(30)
            .all()
        )

        if not rows:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Проверка админок ещё не выполнялась",
                "kpis": {},
                "insights": [],
                "timeline": [],
                "hits": [],
                "entries": [],
                "empty_message": "Проверки админок ещё не выполнялись.",
            }

        # возьмём последние N одной сессии (один checked_ts)
        latest_ts = rows[0].checked_ts
        latest = [r for r in rows if r.checked_ts == latest_ts]

        # hits извлекаем из evidence_json
        hits: list[dict[str, Any]] = []
        for r in latest:
            try:
                ev = json.loads(r.evidence_json or "{}")
            except Exception:
                ev = {}
            if ev.get("status") in ("yes", "maybe"):
                hits.append(ev)

        # сортируем по score
        hits.sort(key=lambda x: x.get("score", 0), reverse=True)
        top_hits = hits[:6]

        # KPI
        yes_cnt = sum(1 for h in hits if h.get("status") == "yes")
        maybe_cnt = sum(1 for h in hits if h.get("status") == "maybe")
        checked_cnt = len(latest)

        # “лучшее”
        best = top_hits[0] if top_hits else None

        # headline
        if yes_cnt > 0:
            headline = "Найдены административные панели / страницы входа"
        elif maybe_cnt > 0:
            headline = "Обнаружены вероятные входы (нужна проверка сигналов)"
        else:
            headline = "Админки/логины по сигнатурам не обнаружены"

        # insights (человеческие, но по делу)
        insights: list[str] = []
        if best:
            insights.append(
                f"Лучшее совпадение: {best.get('label')} ({best.get('path')}) — "
                f"{best.get('bucket')}, score={best.get('score')}."
            )
            # security-ish без драматизации: только факт
            if best.get("bucket") == "accessible" and best.get("status") == "yes":
                insights.append(
                    "Страница входа доступна публично (это нормально), но требует внимания к защите (2FA, rate-limit, WAF).")
            if best.get("bucket") == "restricted":
                insights.append("Доступ ограничен (401/403) — обычно признак корректной защиты на периметре.")
        else:
            insights.append("Ни один из проверенных путей не дал признаков панели управления или формы входа.")

        # timeline: последние 6 запусков (по уникальному checked_ts)
        uniq_ts: list[int] = []
        for r in rows:
            if r.checked_ts not in uniq_ts:
                uniq_ts.append(r.checked_ts)
            if len(uniq_ts) >= 6:
                break

        timeline = []
        for ts in uniq_ts:
            stamp = datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")
            group = [x for x in rows if x.checked_ts == ts]
            g_hits = 0
            g_yes = 0
            g_maybe = 0
            for x in group:
                if x.status in ("yes", "maybe"):
                    g_hits += 1
                if x.status == "yes":
                    g_yes += 1
                if x.status == "maybe":
                    g_maybe += 1

            title = f"проверено {len(group)} путей · yes={g_yes} · maybe={g_maybe}"
            timeline.append(
                {"timestamp": stamp, "status": ("yes" if g_yes else "maybe" if g_maybe else "no"), "title": title,
                 "meta": {}})

        # entries: последние 12 проверок (детали)
        entries = []
        for row in rows[:12]:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            if row.http_status is None:
                message = f"{row.path}: нет ответа"
            else:
                message = f"{row.path}: HTTP {row.http_status}"
            entries.append(
                {
                    "timestamp": timestamp,
                    "status": row.status,
                    "message": message,
                    "details": {"panel_key": row.panel_key, "path": row.path, "final_url": row.final_url},
                }
            )

        kpis = {
            "checked_count": checked_cnt,
            "hits_yes": yes_cnt,
            "hits_maybe": maybe_cnt,
            "best_label": (best.get("label") if best else None),
            "best_path": (best.get("path") if best else None),
            "best_http": (best.get("http_status") if best else None),
            "best_final_url": (best.get("final_url") if best else None),
        }

        return {
            "key": self.key,
            "template": "audit_modules/admin_detect/admin_detect.html",
            "name": self.name,
            "description": self.description,
            "headline": headline,
            "kpis": kpis,
            "insights": insights,
            "timeline": timeline,
            "hits": top_hits,
            "entries": entries,
            "empty_message": "Проверки админок ещё не выполнялись.",
        }


class AdminDetectCheck(Base):
    """Таблица истории проверок админок (универсальная)."""

    __tablename__ = "admin_detect_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)

    panel_key = Column(String(64), nullable=False)  # bitrix / wordpress / joomla / generic ...
    path = Column(String(255), nullable=False)

    status = Column(String(32), nullable=False)  # yes/maybe/no
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
