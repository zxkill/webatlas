from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader

from src.settings.loader import load_settings
from src.settings.logging import configure_logging

from .routers.admin import router as admin_router
from .routers.ui import router as ui_router

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent           # /app/src/webapp
TEMPLATES_DIR = BASE_DIR / "templates"               # /app/src/webapp/templates
STATIC_DIR = BASE_DIR / "static"                     # /app/src/webapp/static

# Корень src: /app/src
SRC_DIR = BASE_DIR.parent

# Корень, где лежат модули аудита: /app/src/audit_modules
AUDIT_MODULES_DIR = SRC_DIR / "audit_modules"


def _build_templates() -> Jinja2Templates:
    """
    Создаёт Jinja2Templates с несколькими корнями поиска шаблонов.

    Идея:
      - Основные страницы и общие partials лежат в webapp/templates
      - Шаблоны конкретных модулей могут лежать внутри src/audit_modules/**

    Тогда в include можно писать, например:
      {% include "audit_modules/tls_certificate/tls_certificate.html" %}
    """

    # FileSystemLoader принимает список путей, но ChoiceLoader позволяет
    # прозрачно комбинировать несколько загрузчиков и расширять в будущем.
    loader = ChoiceLoader(
        [
            FileSystemLoader(str(TEMPLATES_DIR)),      # report.html, base.html, partials/*
            FileSystemLoader(str(SRC_DIR)),            # audit_modules/** (путь относительно /app/src)
        ]
    )

    env = Environment(
        loader=loader,
        autoescape=True,
        enable_async=False,
    )

    logger.info(
        "[ui] jinja loaders enabled: templates_dir=%s src_dir=%s audit_modules_dir=%s",
        TEMPLATES_DIR,
        SRC_DIR,
        AUDIT_MODULES_DIR,
    )

    return Jinja2Templates(env=env)


def create_app() -> FastAPI:
    """
    Главная фабрика FastAPI приложения.

    Важно:
    - Загружаем settings (ENV + YAML) один раз при старте.
    - Настраиваем логирование в stdout на уровне, заданном окружением.
    - Кладём settings и templates в app.state для доступа из роутеров/сервисов.
    """
    # 1) Settings (ENV + YAML)
    settings = load_settings()

    # 2) Logging (stdout, docker-friendly)
    configure_logging(settings.runtime.log_level)

    logger.info(
        "[ui] app starting with host=%s port=%s log_level=%s",
        settings.runtime.app_host,
        settings.runtime.app_port,
        settings.runtime.log_level,
    )

    app = FastAPI(title="WebAtlas UI", version="1.4.0")

    # 3) Shared state (settings/templates)
    app.state.settings = settings
    app.state.templates = _build_templates()

    # 4) Static files
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # 5) Routers
    app.include_router(ui_router)
    app.include_router(admin_router)

    logger.info("[ui] app created successfully")
    return app
