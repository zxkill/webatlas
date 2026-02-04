from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


# -----------------------------
# Models
# -----------------------------

@dataclass(frozen=True)
class RuntimeSettings:
    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_backend_url: str
    app_host: str
    app_port: int
    celery_always_eager: bool
    log_level: str


@dataclass(frozen=True)
class AppSettings:
    rate_limit_rps: float
    import_url_template: str
    audit_concurrency: int
    audit_timeout_total: int
    audit_persist_concurrency: int


@dataclass(frozen=True)
class Settings:
    runtime: RuntimeSettings
    app: AppSettings


# -----------------------------
# Helpers
# -----------------------------

def _get_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        logger.debug("ENV %s not set -> default=%s", name, default)
        return default
    normalized = raw.strip().lower()
    result = normalized in {"1", "true", "yes", "on"}
    logger.debug("ENV %s=%r normalized=%r -> %s", name, raw, normalized, result)
    return result


def _read_yaml(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        logger.error("YAML config not found: %s", path)
        raise FileNotFoundError(path)

    try:
        content = p.read_text(encoding="utf-8")
        logger.debug("YAML config read: %s bytes", len(content))
        return yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        logger.error("YAML parse error: %s", exc)
        raise


def _require_dict(data: dict, key: str) -> dict:
    v = data.get(key)
    if not isinstance(v, dict):
        logger.error("Config section '%s' is missing or not a dict", key)
        raise KeyError(f"missing section: {key}")
    return v


# -----------------------------
# Public API
# -----------------------------

def load_settings(default_yaml_path: str = "config.yaml") -> Settings:
    """
    Единая точка загрузки настроек.

    Runtime (ENV) — для Docker:
      DATABASE_URL, REDIS_URL, CELERY_BROKER_URL, CELERY_BACKEND_URL,
      APP_HOST, APP_PORT, CELERY_ALWAYS_EAGER, LOG_LEVEL

    App (YAML) — для логики приложения:
      rate_limit.rps, import.url_template, import.file_path, audit.*
    """
    # ---- runtime (ENV) ----
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        logger.error("DATABASE_URL is required (should be set in docker-compose)")
        raise RuntimeError("DATABASE_URL is required")

    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    celery_broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/1")
    celery_backend_url = os.getenv("CELERY_BACKEND_URL", "redis://redis:6379/2")
    app_host = os.getenv("APP_HOST", "0.0.0.0")
    app_port = int(os.getenv("APP_PORT", "8088"))
    celery_always_eager = _get_bool_env("CELERY_ALWAYS_EAGER", False)
    log_level = os.getenv("LOG_LEVEL", "INFO")

    runtime = RuntimeSettings(
        database_url=database_url,
        redis_url=redis_url,
        celery_broker_url=celery_broker_url,
        celery_backend_url=celery_backend_url,
        app_host=app_host,
        app_port=app_port,
        celery_always_eager=celery_always_eager,
        log_level=log_level,
    )

    # ---- app (YAML) ----
    yaml_path = os.getenv("APP_CONFIG_PATH", default_yaml_path)
    logger.info("Loading YAML config: %s", yaml_path)
    data = _read_yaml(yaml_path)

    rate = _require_dict(data, "rate_limit")
    imp = _require_dict(data, "import")
    audit = _require_dict(data, "audit")
    timeouts = _require_dict(audit, "timeouts")

    url_template = imp.get("url_template") or imp.get("api_url_template")
    if not url_template:
        logger.error("import.url_template is required in YAML")
        raise KeyError("import.url_template is required")

    persist_concurrency = int(audit.get("persist_concurrency", audit["concurrency"]))
    if persist_concurrency <= 0:
        logger.error("audit.persist_concurrency must be > 0")
        raise ValueError("audit.persist_concurrency must be > 0")

    app = AppSettings(
        rate_limit_rps=float(rate["rps"]),
        import_url_template=str(url_template),
        audit_concurrency=int(audit["concurrency"]),
        audit_timeout_total=int(timeouts["total"]),
        audit_persist_concurrency=persist_concurrency,
    )

    logger.info(
        "Settings loaded: audit_concurrency=%s, persist_concurrency=%s, timeout_total=%s, port=%s",
        app.audit_concurrency,
        app.audit_persist_concurrency,
        app.audit_timeout_total,
        runtime.app_port,
    )
    return Settings(runtime=runtime, app=app)
