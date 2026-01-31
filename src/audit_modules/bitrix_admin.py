from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from urllib.parse import urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AdminPanelUpdate, AuditContext, ModuleResult
from src.webapp_db import AdminPanelRow, Base, Domain, create_domain

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL админки без query/fragment."""

    return urlunparse((scheme, domain, path, "", "", ""))


class BitrixAdminModule:
    """Модуль проверки доступности административной панели Bitrix."""

    key = "bitrix_admin"
    name = "Админка Bitrix"
    description = "Проверяет наличие /bitrix/admin/ при подтверждённой CMS Bitrix."
    depends_on: tuple[str, ...] = ("bitrix_detect",)

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Проверяет /bitrix/admin/ только если Bitrix уже подтверждён.

        В противном случае возвращает пустой результат, чтобы не шуметь в БД.
        """

        cms_info = context.data.get("cms", {}).get("bitrix")
        if not cms_info or cms_info.get("status") != "yes":
            logger.info("[bitrix_admin] пропуск: CMS Bitrix не подтверждена для %s", context.domain)
            return ModuleResult()

        availability = context.data.get("availability", {})
        scheme = availability.get("used_scheme") or "https"
        admin_url = _ensure_url(scheme, context.domain, "/bitrix/admin/")
        logger.debug("[bitrix_admin] проверяем %s", admin_url)

        admin_resp = await context.http.fetch(context.session, admin_url, allow_redirects=False)
        admin_evidence: dict = {"domain": context.domain, "checked": {}}

        module_payload: list[dict] = []
        if admin_resp is None:
            logger.info("[bitrix_admin] админка недоступна для %s", context.domain)
            admin_row = AdminPanelRow(
                status="no",
                http_status=None,
                final_url=None,
                evidence_json=json.dumps({**admin_evidence, "error": "unreachable"}, ensure_ascii=False),
            )
            module_payload.append(
                {
                    "checked_ts": int(time.time()),
                    "status": "no",
                    "http_status": None,
                    "final_url": None,
                    "evidence_json": admin_row.evidence_json,
                }
            )
        else:
            admin_evidence["checked"]["bitrix_admin"] = {
                "ok": True,
                "status": admin_resp.status,
                "final_url": admin_resp.final_url,
            }
            admin_status = "yes" if admin_resp.status in (200, 301, 302, 401, 403) else "no"
            admin_row = AdminPanelRow(
                status=admin_status,
                http_status=admin_resp.status,
                final_url=admin_resp.final_url,
                evidence_json=json.dumps(admin_evidence, ensure_ascii=False),
            )
            module_payload.append(
                {
                    "checked_ts": int(time.time()),
                    "status": admin_status,
                    "http_status": admin_resp.status,
                    "final_url": admin_resp.final_url,
                    "evidence_json": admin_row.evidence_json,
                }
            )
            logger.info(
                "[bitrix_admin] домен %s: status=%s, http=%s",
                context.domain,
                admin_status,
                admin_resp.status,
            )

        return ModuleResult(
            admin_updates=[
                AdminPanelUpdate(
                    panel_key="bitrix_admin",
                    row=admin_row,
                )
            ],
            module_payload=module_payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет результаты проверки админки Bitrix в таблицу bitrix_admin_checks.
        """

        if not payload:
            logger.debug("[bitrix_admin] нет данных для сохранения по домену %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[bitrix_admin] домен %s отсутствовал, создаём запись перед сохранением", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                BitrixAdminCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    status=item.get("status", "no"),
                    http_status=item.get("http_status"),
                    final_url=item.get("final_url"),
                    evidence_json=item.get("evidence_json"),
                )
        )
        session.commit()
        logger.info("[bitrix_admin] сохранены проверки админки: domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Формирует блок отчёта по админке Bitrix, показывая последние 5 проверок.
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
            session.query(BitrixAdminCheck)
            .filter(BitrixAdminCheck.domain_id == domain_record.id)
            .order_by(BitrixAdminCheck.checked_ts.desc())
            .limit(5)
            .all()
        )

        entries = []
        for row in rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            if row.http_status is None:
                message = "админка не ответила"
            else:
                message = f"админка ответила код {row.http_status}"
            entries.append({"timestamp": timestamp, "status": row.status, "message": message, "details": {}})

        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": entries,
            "empty_message": "Проверки админки Bitrix ещё не выполнялись.",
        }


class BitrixAdminCheck(Base):
    """Таблица результатов проверки админки Bitrix."""

    __tablename__ = "bitrix_admin_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False)
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
