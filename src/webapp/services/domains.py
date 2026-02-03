from __future__ import annotations

import logging

from src.webapp_db import list_domains, get_domain_report, get_domains_focus_data

logger = logging.getLogger(__name__)


def list_domains_svc(session):
    """Обёртка для загрузки списка доменов без фильтров."""
    logger.debug("Сервис list_domains_svc: запрошены последние домены")
    return list_domains(session, 10)


def get_domain_report_svc(session, domain: str):
    """Обёртка для получения отчёта по домену через слой сервисов."""
    logger.info("Сервис get_domain_report_svc: domain=%s", domain)
    return get_domain_report(session, domain)


def get_domains_page_payload(session, *, focus: str | None = None) -> dict:
    """
    Собирает данные для страницы доменов с учётом фокуса.

    Используем уровень сервисов, чтобы роутер оставался "тонким".
    """

    # Подробный лог — помогает быстро понять, какие фильтры задействованы в UI.
    logger.info("Сервис get_domains_page_payload: focus=%s", focus)
    return get_domains_focus_data(session, focus=focus, limit=100, top_n=50, tls_soon_days=14)
