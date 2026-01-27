from __future__ import annotations

import logging

from celery import Celery

from src.webapp_audit import run_audit_and_persist
from src.webapp_config import load_webapp_config
from src.webapp_db import (
    create_db_state,
    create_domain,
    import_domains_from_file,
    init_db,
    list_domains,
)
from src.webapp_logging import configure_logging

logger = logging.getLogger(__name__)

configure_logging()

config = load_webapp_config()

db_state = create_db_state(config.database_url)
init_db(db_state)

celery_app = Celery(
    "webatlas",
    broker=config.celery_broker_url,
    backend=config.celery_backend_url,
)
celery_app.conf.task_always_eager = config.celery_always_eager
celery_app.conf.task_eager_propagates = True


@celery_app.task(name="webatlas.add_domain")
def add_domain_task(domain: str, source: str = "manual") -> dict[str, str]:
    """
    Фоновая задача для добавления домена в базу.

    Возвращаем словарь, чтобы удобно отслеживать результат в логах и UI.
    """

    logger.info("Получена задача на добавление домена: %s", domain)
    with db_state.session_factory() as session:
        record = create_domain(session, domain=domain, source=source)
    return {"domain": record.domain, "source": record.source}


@celery_app.task(name="webatlas.import_domains_from_file")
def import_domains_from_file_task(file_path: str) -> dict[str, int]:
    """Импортируем домены из файла по запросу админки."""

    logger.info("Получена задача на импорт доменов из файла: %s", file_path)
    with db_state.session_factory() as session:
        stats = import_domains_from_file(session, file_path, source="file")
    return {
        "total_lines": stats.total_lines,
        "normalized_domains": stats.normalized_domains,
        "unique_domains": stats.unique_domains,
        "inserted_domains": stats.inserted_domains,
        "skipped_duplicates": stats.skipped_duplicates,
    }


@celery_app.task(name="webatlas.audit_all")
def audit_all_task() -> dict[str, int]:
    """Запускаем аудит всех доменов из базы."""

    logger.info("Получена задача на аудит всех доменов")
    with db_state.session_factory() as session:
        domains = [record.domain for record in list_domains(session, limit=1000000)]
    processed = run_audit_and_persist(domains, db_state.session_factory)
    return {"processed": processed}


@celery_app.task(name="webatlas.audit_limit")
def audit_limit_task(limit: int) -> dict[str, int]:
    """Запускаем аудит ограниченного числа доменов."""

    logger.info("Получена задача на аудит доменов с лимитом: %s", limit)
    with db_state.session_factory() as session:
        domains = [record.domain for record in list_domains(session, limit=limit)]
    processed = run_audit_and_persist(domains, db_state.session_factory)
    return {"processed": processed}


@celery_app.task(name="webatlas.audit_domain")
def audit_domain_task(domain: str) -> dict[str, int]:
    """Запускаем аудит конкретного домена."""

    logger.info("Получена задача на аудит домена: %s", domain)
    processed = run_audit_and_persist([domain], db_state.session_factory)
    return {"processed": processed}
