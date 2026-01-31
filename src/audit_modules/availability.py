from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from urllib.parse import urlunparse

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, CheckUpdate, ModuleResult
from src.webapp_db import Base, CheckRow, Domain, create_domain

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
        module_payload: list[dict] = []
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
                module_payload.append(
                    {
                        "checked_ts": int(time.time()),
                        "scheme": scheme,
                        "status": "no",
                        "http_status": None,
                        "final_url": None,
                        "evidence_json": json.dumps(evidence, ensure_ascii=False),
                    }
                )
                logger.info("[availability] домен %s недоступен по %s: нет ответа", context.domain, scheme)
                continue

            # Проверяем строгий HTTP 200: только такой ответ считаем доступностью.
            is_available = response.status == 200
            evidence["checked"][scheme] = {
                "ok": is_available,
                "status": response.status,
                "final_url": response.final_url,
            }
            module_payload.append(
                {
                    "checked_ts": int(time.time()),
                    "scheme": scheme,
                    "status": "yes" if is_available else "no",
                    "http_status": response.status,
                    "final_url": response.final_url,
                    "evidence_json": json.dumps(evidence, ensure_ascii=False),
                }
            )
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
                ],
                module_payload=module_payload,
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
            ],
            module_payload=module_payload,
        )

    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        """
        Сохраняет каждую проверку доступности домена в таблицу availability_checks.
        """

        if not payload:
            logger.debug("[availability] нет данных для сохранения по домену %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[availability] домен %s отсутствовал, создаём запись перед сохранением", domain)
            domain_record = create_domain(session, domain, source="audit")

        for item in payload:
            session.add(
                AvailabilityCheck(
                    domain_id=domain_record.id,
                    checked_ts=item.get("checked_ts", int(time.time())),
                    scheme=item.get("scheme"),
                    status=item.get("status"),
                    http_status=item.get("http_status"),
                    final_url=item.get("final_url"),
                    evidence_json=item.get("evidence_json"),
                )
        )
        session.commit()
        logger.info("[availability] сохранены проверки доступности: domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        """
        Формирует блок отчёта по доступности, показывая последние 5 проверок.
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
            session.query(AvailabilityCheck)
            .filter(AvailabilityCheck.domain_id == domain_record.id)
            .order_by(AvailabilityCheck.checked_ts.desc())
            .limit(5)
            .all()
        )

        entries = []
        for row in rows:
            timestamp = datetime.fromtimestamp(row.checked_ts).strftime("%d.%m.%Y %H:%M:%S")
            if row.http_status is None:
                message = "домен не ответил"
            else:
                message = f"домен ответил код {row.http_status}"
            entries.append(
                {
                    "timestamp": timestamp,
                    "status": row.status,
                    "message": message,
                    "details": {
                        "scheme": row.scheme,
                        "final_url": row.final_url,
                    },
                }
            )

        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "entries": entries,
            "empty_message": "Проверки доступности ещё не выполнялись.",
        }


class AvailabilityCheck(Base):
    """Таблица результатов проверок доступности домена."""

    __tablename__ = "availability_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)
    scheme = Column(String(8), nullable=True)
    status = Column(String(32), nullable=False)
    http_status = Column(Integer, nullable=True)
    final_url = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
