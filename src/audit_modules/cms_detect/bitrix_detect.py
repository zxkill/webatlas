from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, CmsUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, CmsRow, Domain, create_domain

logger = logging.getLogger(__name__)

# =============================================================================
# Bitrix signatures (встроено из бывшего src/bitrix.py)
# =============================================================================

BITRIX_PATH_HINTS = [
    "/bitrix/",
    "/bitrix/js/",
    "/bitrix/admin/",
    "/upload/iblock/",
]

BITRIX_HTML_PATTERNS = [
    re.compile(r"\bBX\.message\b", re.I),
    re.compile(r"\bBX\.", re.I),
    re.compile(r"/bitrix/(js|admin|components|templates)/", re.I),
    re.compile(r"/upload/iblock/", re.I),
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+bitrix", re.I),
]

BITRIX_COOKIE_HINT = re.compile(r"\bBITRIX_SM_", re.I)


def decode_html(body: bytes, charset: Optional[str]) -> str:
    """
    Декодируем HTML.
    Важно: часть сайтов Bitrix может отдавать windows-1251 и т.п. — учитываем charset.
    """
    enc = charset or "utf-8"
    try:
        decoded = body.decode(enc, errors="replace")
        logger.debug("[bitrix] HTML decoded with charset=%s", enc)
        return decoded
    except Exception as exc:
        logger.warning("[bitrix] HTML decode failed charset=%s: %s; fallback to utf-8", enc, exc)
        return body.decode("utf-8", errors="replace")


def score_bitrix(headers: dict[str, str], set_cookie_raw: str, html: str) -> tuple[int, dict]:
    """
    Считаем score уверенности Bitrix по сигналам:
    - cookies (BITRIX_SM_*)
    - headers (X-Powered-By: bitrix)
    - HTML сигнатуры (BX.*, /bitrix/... и т.д.)
    - статические пути (bitrix/upload)
    """
    score = 0
    ev: dict[str, list[dict[str, str]]] = {"signals": []}

    if set_cookie_raw and BITRIX_COOKIE_HINT.search(set_cookie_raw):
        score += 50
        ev["signals"].append({"type": "cookie", "value": "BITRIX_SM_* in Set-Cookie"})
        logger.debug("[bitrix] signal: cookie BITRIX_SM_*")

    x_powered = headers.get("X-Powered-By", "")
    if x_powered and "bitrix" in x_powered.lower():
        score += 30
        ev["signals"].append({"type": "header", "value": f"X-Powered-By: {x_powered}"})
        logger.debug("[bitrix] signal: header X-Powered-By=%s", x_powered)

    for pat in BITRIX_HTML_PATTERNS:
        if pat.search(html):
            score += 15
            ev["signals"].append({"type": "html", "value": pat.pattern})
            logger.debug("[bitrix] signal: html pattern=%s", pat.pattern)

    for h in BITRIX_PATH_HINTS:
        if h in html:
            score += 5
            ev["signals"].append({"type": "path", "value": h})
            logger.debug("[bitrix] signal: path hint=%s", h)

    final_score = min(score, 100)
    logger.debug("[bitrix] score=%s (raw=%s)", final_score, score)
    return final_score, ev


def classify(score: int) -> str:
    """Классификация по порогам."""
    if score >= 70:
        return "yes"
    if score >= 35:
        return "maybe"
    return "no"


# =============================================================================
# Audit module: Bitrix detection (как раньше, но self-contained)
# =============================================================================

class BitrixDetectModule:
    """Модуль определения CMS 1C-Bitrix по сигнатурам."""

    key = "bitrix_detect"
    name = "Определение 1C-Bitrix"
    description = "Проверяет сигнатуры Bitrix (cookies, headers, HTML)."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Анализирует сигнатуры Bitrix и возвращает результат проверки.

        Дополнительно: при уверенном Bitrix можно подключать общий детект админок (admin_detect),
        чтобы проверять /bitrix/admin/ и прочие панели единым модулем.
        """
        availability = context.data.get("availability")
        evidence: dict = {"domain": context.domain, "checked": {}}
        cms_evidence: dict = {"domain": context.domain, "checked": {}}

        if not availability or not availability.get("reachable"):
            logger.info("[bitrix] skip: domain unreachable: %s", context.domain)
            evidence["error"] = "unreachable"
            check_row = CheckRow(status="no", score=0, evidence_json=json.dumps(evidence, ensure_ascii=False))
            context.data.setdefault("cms", {})["bitrix"] = {"status": "no", "confidence": 0}
            return ModuleResult(
                check_updates=[CheckUpdate(key="bitrix", description="Проверка сигнатур Bitrix", row=check_row)],
                module_payload=[{"checked_ts": int(time.time()), "status": "no", "score": 0, "evidence_json": check_row.evidence_json}],
            )

        homepage = availability.get("homepage")
        if homepage is None:
            logger.warning("[bitrix] availability.homepage missing for %s", context.domain)
            evidence["error"] = "availability_missing"
            check_row = CheckRow(status="no", score=0, evidence_json=json.dumps(evidence, ensure_ascii=False))
            context.data.setdefault("cms", {})["bitrix"] = {"status": "no", "confidence": 0}
            return ModuleResult(
                check_updates=[CheckUpdate(key="bitrix", description="Проверка сигнатур Bitrix", row=check_row)],
                module_payload=[{"checked_ts": int(time.time()), "status": "no", "score": 0, "evidence_json": check_row.evidence_json}],
            )

        html = decode_html(homepage.body, homepage.charset)
        score, ev = score_bitrix(homepage.headers, availability.get("set_cookie", ""), html)
        status = classify(score)

        evidence["bitrix"] = {"score": score, **ev}
        evidence["used_url"] = homepage.final_url
        cms_evidence["bitrix"] = {"score": score, **ev}
        cms_evidence["used_url"] = homepage.final_url

        context.data.setdefault("cms", {})["bitrix"] = {"status": status, "confidence": score}

        module_result = ModuleResult(
            check_updates=[
                CheckUpdate(
                    key="bitrix",
                    description="Проверка сигнатур Bitrix",
                    row=CheckRow(status=status, score=score, evidence_json=json.dumps(evidence, ensure_ascii=False)),
                )
            ],
            module_payload=[{"checked_ts": int(time.time()), "status": status, "score": score, "evidence_json": json.dumps(evidence, ensure_ascii=False)}],
        )

        if status in ("yes", "maybe"):
            module_result.cms_updates.append(
                CmsUpdate(
                    cms_key="bitrix",
                    cms_name="1C-Bitrix",
                    row=CmsRow(status=status, confidence=score, evidence_json=json.dumps(cms_evidence, ensure_ascii=False)),
                )
            )

        # В будущем мы масштабируем детект админок отдельным модулем.
        # Если Bitrix подтверждён — можно гарантированно подключать admin_detect.
        if status == "yes":
            module_result.additional_modules.append("admin_detect")
            logger.info("[bitrix] confirmed=yes -> add module admin_detect")

        logger.info("[bitrix] domain=%s status=%s score=%s", context.domain, status, score)
        return module_result

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """Сохраняет результаты определения Bitrix в таблицу bitrix_detect_checks."""
        if not payload:
            logger.debug("[bitrix] persist: no payload for %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[bitrix] persist: create domain=%s before save", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                BitrixDetectCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    status=item.get("status", "no"),
                    score=item.get("score", 0),
                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[bitrix] persist: saved domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """Формирует блок отчёта по определению Bitrix, показывая последние 5 проверок."""
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {"key": self.key, "name": self.name, "description": self.description, "entries": [], "empty_message": "Данные о домене отсутствуют в базе."}

        rows = (
            session.query(BitrixDetectCheck)
            .filter(BitrixDetectCheck.domain_id == domain_record.id)
            .order_by(BitrixDetectCheck.checked_ts.desc())
            .limit(5)
            .all()
        )

        entries = []
        for row in rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            entries.append({"timestamp": timestamp, "status": row.status, "message": f"статус={row.status}, score={row.score}", "details": {}})

        return {"key": self.key, "name": self.name, "description": self.description, "entries": entries, "empty_message": "Проверки сигнатур Bitrix ещё не выполнялись."}


class BitrixDetectCheck(Base):
    """Таблица результатов определения CMS Bitrix."""

    __tablename__ = "bitrix_detect_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    score = Column(Integer, nullable=False, default=0)
    evidence_json = Column(Text, nullable=True)
