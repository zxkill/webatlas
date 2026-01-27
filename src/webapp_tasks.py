from __future__ import annotations

import logging

from celery import Celery

from src.webapp_config import load_webapp_config
from src.webapp_db import create_db_state, create_domain, init_db
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
