from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WebAppConfig:
    """Конфигурация веб-слоя и фоновых задач, читаемая из переменных окружения."""

    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_backend_url: str
    app_host: str
    app_port: int
    celery_always_eager: bool


def _get_bool(value: str | None, default: bool) -> bool:
    """Приводим строковую переменную окружения к bool с прозрачной диагностикой."""

    if value is None:
        logger.debug("Переменная окружения не задана, используем значение по умолчанию: %s", default)
        return default
    normalized = value.strip().lower()
    result = normalized in {"1", "true", "yes", "on"}
    logger.debug("Парсинг булевой переменной: raw=%s normalized=%s result=%s", value, normalized, result)
    return result


def load_webapp_config() -> WebAppConfig:
    """
    Загружает конфигурацию веб-приложения.

    Все ключевые параметры берём из окружения, чтобы конфиг был удобен
    для Docker Compose и облачных сред.
    """

    database_url = os.getenv("DATABASE_URL", "postgresql+psycopg2://webatlas:webatlas@postgres:5432/webatlas")
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    celery_broker_url = os.getenv("CELERY_BROKER_URL", redis_url)
    celery_backend_url = os.getenv("CELERY_BACKEND_URL", redis_url)
    app_host = os.getenv("APP_HOST", "0.0.0.0")
    app_port = int(os.getenv("APP_PORT", "8088"))
    celery_always_eager = _get_bool(os.getenv("CELERY_ALWAYS_EAGER"), False)

    logger.info(
        "Загрузка конфигурации веб-приложения: db=%s redis=%s broker=%s backend=%s host=%s port=%s eager=%s",
        database_url,
        redis_url,
        celery_broker_url,
        celery_backend_url,
        app_host,
        app_port,
        celery_always_eager,
    )

    return WebAppConfig(
        database_url=database_url,
        redis_url=redis_url,
        celery_broker_url=celery_broker_url,
        celery_backend_url=celery_backend_url,
        app_host=app_host,
        app_port=app_port,
        celery_always_eager=celery_always_eager,
    )
