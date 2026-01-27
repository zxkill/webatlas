from __future__ import annotations

import json
import logging
from urllib.parse import urlunparse

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import CheckRow

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, domain: str, path: str) -> str:
    """Собираем URL без лишних параметров, чтобы не загрязнять логи."""

    return urlunparse((scheme, domain, path, "", "", ""))


class AvailabilityModule:
    """Модуль проверки доступности домена и фиксации ответа главной страницы."""

    key = "availability"
    name = "Доступность сайта"
    description = "Проверяет доступность домена по HTTP/HTTPS и фиксирует ответ главной страницы."
    depends_on: tuple[str, ...] = ()

    async def run(self, context: AuditContext) -> ModuleResult:
        """
        Выполняет проверку доступности и сохраняет данные в контекст.

        В контекст кладём базовую информацию, чтобы другие модули могли её использовать.
        """

        evidence: dict = {"domain": context.domain, "checked": {}}
        set_cookie_agg = ""
        used_scheme = None
        homepage = None

        for scheme in ("https", "http"):
            url = _ensure_url(scheme, context.domain, "/")
            logger.debug("[availability] проверяем %s", url)
            response = await context.http.fetch(context.session, url, allow_redirects=True)
            if response is None:
                evidence["checked"][scheme] = {"ok": False}
                logger.info("[availability] домен %s недоступен по %s", context.domain, scheme)
                continue

            evidence["checked"][scheme] = {
                "ok": True,
                "status": response.status,
                "final_url": response.final_url,
            }
            homepage = response
            used_scheme = scheme
            set_cookie_agg = response.headers.get("Set-Cookie", "")
            logger.info(
                "[availability] домен %s доступен по %s, статус=%s",
                context.domain,
                scheme,
                response.status,
            )
            break

        if homepage is None:
            evidence["error"] = "unreachable"
            logger.warning("[availability] домен %s недоступен по HTTP/HTTPS", context.domain)
            context.data["availability"] = {
                "reachable": False,
                "used_scheme": None,
                "homepage": None,
                "set_cookie": "",
            }
            return ModuleResult(
                check_updates=[
                    CheckUpdate(
                        key=self.key,
                        description="Проверка доступности главной страницы",
                        row=CheckRow(
                            status="no",
                            score=0,
                            evidence_json=json.dumps(evidence, ensure_ascii=False),
                        ),
                    )
                ]
            )

        context.data["availability"] = {
            "reachable": True,
            "used_scheme": used_scheme,
            "homepage": homepage,
            "set_cookie": set_cookie_agg,
        }

        evidence["used_url"] = homepage.final_url
        return ModuleResult(
            check_updates=[
                CheckUpdate(
                    key=self.key,
                    description="Проверка доступности главной страницы",
                    row=CheckRow(
                        status="yes",
                        score=100,
                        evidence_json=json.dumps(evidence, ensure_ascii=False),
                    ),
                )
            ]
        )
