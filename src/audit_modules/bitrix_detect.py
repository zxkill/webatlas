from __future__ import annotations

import json
import logging

from src.audit_modules.types import AuditContext, CheckUpdate, CmsUpdate, ModuleResult
from src.bitrix import classify, decode_html, score_bitrix
from src.webapp_db import CheckRow, CmsRow

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
                ]
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
                ]
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
            ]
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
