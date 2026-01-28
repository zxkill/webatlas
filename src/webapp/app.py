from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .routers.ui import router as ui_router
from .routers.admin import router as admin_router

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="WebAtlas UI", version="1.4.0")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app.include_router(ui_router)
    app.include_router(admin_router)

    return app
