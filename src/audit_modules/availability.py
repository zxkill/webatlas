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
            # Собираем базовый URL без лишних параметров, чтобы лог был лаконичным.
            url = _ensure_url(scheme, context.domain, "/")
            logger.debug("[availability] проверяем %s", url)
            response = await context.http.fetch(context.session, url, allow_redirects=True)
            if response is None:
                # Фиксируем факт сетевой ошибки/таймаута, чтобы позже было проще разбирать причины.
                evidence["checked"][scheme] = {"ok": False, "reason": "request_failed"}
                logger.info("[availability] домен %s недоступен по %s: нет ответа", context.domain, scheme)
                continue

            # Проверяем строгий HTTP 200: только такой ответ считаем доступностью.
            is_available = response.status == 200
            evidence["checked"][scheme] = {
                "ok": is_available,
                "status": response.status,
                "final_url": response.final_url,
            }
            if not is_available:
                # Статусы отличные от 200 считаем недоступностью, но продолжаем проверку второго протокола.
                logger.info(
                    "[availability] домен %s недоступен по %s: статус=%s",
                    context.domain,
                    scheme,
                    response.status,
                )
                continue

            # Сохраняем данные первого успешного ответа, чтобы остальные модули могли использовать их.
            homepage = response
            used_scheme = scheme
            set_cookie_agg = response.headers.get("Set-Cookie", "")
            logger.info(
                "[availability] домен %s доступен по %s, статус=200",
                context.domain,
                scheme,
            )
            break

        if homepage is None:
            # Если по HTTP/HTTPS не удалось получить статус 200, считаем домен недоступным.
            evidence["error"] = "no_http_200"
            logger.warning(
                "[availability] домен %s недоступен по HTTP/HTTPS: нет ответа 200",
                context.domain,
            )
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
