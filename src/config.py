from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import logging
import os
import yaml


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DbConfig:
    url: str


@dataclass(frozen=True)
class RateLimitConfig:
    rps: float


@dataclass(frozen=True)
class ImportConfig:
    url_template: str
    file_path: str


@dataclass(frozen=True)
class AuditTimeouts:
    total: int


@dataclass(frozen=True)
class AuditConfig:
    concurrency: int
    timeouts: AuditTimeouts


@dataclass(frozen=True)
class AppConfig:
    db: DbConfig
    rate_limit: RateLimitConfig
    import_cfg: ImportConfig
    audit: AuditConfig


def _read_yaml(path: str) -> dict:
    """
    Читает YAML-файл и возвращает словарь.
    Выбрасывает понятные исключения, чтобы облегчить диагностику при запуске.
    """
    config_path = Path(path)
    if not config_path.exists():
        logger.error("Конфигурационный файл не найден: %s", path)
        raise FileNotFoundError(path)

    try:
        content = config_path.read_text(encoding="utf-8")
        logger.debug("Конфигурационный файл прочитан: %s байт", len(content))
        return yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        logger.error("Ошибка разбора YAML-конфига %s: %s", path, exc)
        raise


def _require_section(data: dict, section: str) -> dict:
    """
    Проверяет наличие секции в конфиге и возвращает её словарь.
    """
    if section not in data or not isinstance(data[section], dict):
        logger.error("Секция %s отсутствует или имеет неверный формат.", section)
        raise KeyError(f"config missing section: {section}")
    return data[section]


def load_config(path: str = "config.yaml") -> AppConfig:
    """
    Загружает конфигурацию из YAML. Все параметры берём только из конфига,
    чтобы запуск был одинаковым и воспроизводимым.
    """

    # Позволяем переопределить путь через переменную окружения для контейнеров.
    config_path = os.getenv("APP_CONFIG_PATH", path)
    logger.info("Загрузка конфигурации приложения из файла: %s", config_path)

    # Читаем YAML и валидируем обязательные секции, чтобы ошибки были явными.
    data = _read_yaml(config_path)
    db_section = _require_section(data, "db")
    rate_section = _require_section(data, "rate_limit")
    import_section = _require_section(data, "import")
    audit_section = _require_section(data, "audit")

    logger.info(
        "Конфигурация загружена: db=%s, rate_limit=%s rps, audit.concurrency=%s",
        bool(db_section.get("url")),
        rate_section.get("rps"),
        audit_section.get("concurrency"),
    )

    return AppConfig(
        db=DbConfig(url=db_section["url"]),
        rate_limit=RateLimitConfig(rps=float(rate_section["rps"])),
        import_cfg=ImportConfig(
            url_template=import_section["url_template"],
            file_path=import_section["file_path"],
        ),
        audit=AuditConfig(
            concurrency=int(audit_section["concurrency"]),
            timeouts=AuditTimeouts(total=int(audit_section["timeouts"]["total"])),
        ),
    )
