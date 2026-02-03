from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from src.audit_modules.registry import list_modules
from ..deps import get_session
from ..services.domains import list_domains_svc, get_domain_report_svc

# Новый импорт (добавим функцию ниже в webapp_db.py)
from src.webapp_db import get_dashboard_data

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session=Depends(get_session)) -> HTMLResponse:
    """
    Новый главный экран (Dashboard).

    Здесь показываем агрегаты и top-списки.
    Полные таблицы и управление — в /domains и /report.
    """
    templates = request.app.state.templates

    dashboard_payload = get_dashboard_data(session, top_n=5, tls_soon_days=14)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "modules": list_modules(),
            "dashboard": dashboard_payload,
            "page": {"title": "WebAtlas — dashboard", "subtitle": "Ситуационный центр"},
        },
    )


@router.get("/domains", response_class=HTMLResponse)
def domains(request: Request, session=Depends(get_session)) -> HTMLResponse:
    """
    Старый экран со списком доменов перенесён на /domains.
    """
    templates = request.app.state.templates
    domains_rows = list_domains_svc(session)

    return templates.TemplateResponse(
        "domains.html",
        {
            "request": request,
            "domains": domains_rows,
            "modules": list_modules(),
            "page": {"title": "WebAtlas — домены", "subtitle": "Домены и действия"},
        },
    )


@router.get("/report", response_class=HTMLResponse)
def report_query(request: Request, domain: str, session=Depends(get_session)) -> HTMLResponse:
    return report_domain(request, domain, session)


@router.get("/report/{domain}", response_class=HTMLResponse)
def report_domain(request: Request, domain: str, session=Depends(get_session)) -> HTMLResponse:
    templates = request.app.state.templates
    report = get_domain_report_svc(session, domain)

    if report is None:
        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "report": None,
                "domain": domain,
                "page": {"title": "WebAtlas — отчёт не найден", "subtitle": "Отчёт"},
            },
            status_code=404,
        )

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "report": report,
            "domain": domain,
            "page": {"title": f"WebAtlas — отчёт {domain}", "subtitle": "Отчёт"},
        },
    )
