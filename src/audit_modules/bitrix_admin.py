from __future__ import annotations

import json
import logging
from urllib.parse import urlunparse

from src.audit_modules.types import AdminPanelUpdate, AuditContext, ModuleResult
from src.webapp_db import AdminPanelRow

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

        if admin_resp is None:
            logger.info("[bitrix_admin] админка недоступна для %s", context.domain)
            admin_row = AdminPanelRow(
                status="no",
                http_status=None,
                final_url=None,
                evidence_json=json.dumps({**admin_evidence, "error": "unreachable"}, ensure_ascii=False),
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
            ]
        )
