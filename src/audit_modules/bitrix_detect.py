from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, CmsUpdate, ModuleResult
from src.bitrix import classify, decode_html, score_bitrix
from src.webapp_db import Base, CheckRow, CmsRow, Domain, create_domain

logger = logging.getLogger(__name__)


class BitrixDetectModule:
    """Модуль определения CMS 1C-Bitrix по сигнатурам."""

    key = "bitrix_detect"
    name = "Определение 1C-Bitrix"
    description = "Проверяет сигнатуры Bitrix (cookies, headers, HTML)."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Анализирует сигнатуры Bitrix и возвращает результат проверки.

        При уверенном определении CMS добавляет зависимый модуль админки.
        """

        availability = context.data.get("availability")
        evidence: dict = {"domain": context.domain, "checked": {}}
        cms_evidence: dict = {"domain": context.domain, "checked": {}}

        if not availability or not availability.get("reachable"):
            logger.info("[bitrix] пропуск: домен %s недоступен", context.domain)
            evidence["error"] = "unreachable"
            check_row = CheckRow(status="no", score=0, evidence_json=json.dumps(evidence, ensure_ascii=False))
            context.data.setdefault("cms", {})["bitrix"] = {"status": "no", "confidence": 0}
            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key="bitrix",
                        description="Проверка сигнатур Bitrix",
                        row=check_row,
                    )
                ],
                module_payload=[
                    {
                        "checked_ts": int(time.time()),
                        "status": "no",
                        "score": 0,
                        "evidence_json": json.dumps(evidence, ensure_ascii=False),
                    }
                ],
            )

        homepage = availability.get("homepage")
        if homepage is None:
            logger.warning("[bitrix] отсутствует ответ главной страницы для домена %s", context.domain)
            evidence["error"] = "availability_missing"
            check_row = CheckRow(status="no", score=0, evidence_json=json.dumps(evidence, ensure_ascii=False))
            context.data.setdefault("cms", {})["bitrix"] = {"status": "no", "confidence": 0}
            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key="bitrix",
                        description="Проверка сигнатур Bitrix",
                        row=check_row,
                    )
                ],
                module_payload=[
                    {
                        "checked_ts": int(time.time()),
                        "status": "no",
                        "score": 0,
                        "evidence_json": json.dumps(evidence, ensure_ascii=False),
                    }
                ],
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
                    row=CheckRow(
                        status=status,
                        score=score,
                        evidence_json=json.dumps(evidence, ensure_ascii=False),
                    ),
                )
            ],
            module_payload=[
                {
                    "checked_ts": int(time.time()),
                    "status": status,
                    "score": score,
                    "evidence_json": json.dumps(evidence, ensure_ascii=False),
                }
            ],
        )

        if status in ("yes", "maybe"):
            module_result.cms_updates.append(
                CmsUpdate(
                    cms_key="bitrix",
                    cms_name="1C-Bitrix",
                    row=CmsRow(
                        status=status,
                        confidence=score,
                        evidence_json=json.dumps(cms_evidence, ensure_ascii=False),
                    ),
                )
            )

        if status == "yes":
            # Автоматически подключаем модуль проверки админки, если CMS подтверждена.
            module_result.additional_modules.append("bitrix_admin")
            logger.info("[bitrix] CMS подтверждена, подключаем модуль bitrix_admin")

        logger.info("[bitrix] домен %s: status=%s, score=%s", context.domain, status, score)
        return module_result

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет результаты определения Bitrix в таблицу bitrix_detect_checks.
        """

        if not payload:
            logger.debug("[bitrix] нет данных для сохранения по домену %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[bitrix] домен %s отсутствовал, создаём запись перед сохранением", domain)
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
        logger.info("[bitrix] сохранены результаты определения CMS: domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Формирует блок отчёта по определению Bitrix, показывая последние 5 проверок.
        """

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "entries": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
            }

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
            message = f"статус={row.status}, score={row.score}"
            entries.append({"timestamp": timestamp, "status": row.status, "message": message, "details": {}})

        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": entries,
            "empty_message": "Проверки сигнатур Bitrix ещё не выполнялись.",
        }


class BitrixDetectCheck(Base):
    """Таблица результатов определения CMS Bitrix."""

    __tablename__ = "bitrix_detect_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    score = Column(Integer, nullable=False, default=0)
    evidence_json = Column(Text, nullable=True)
