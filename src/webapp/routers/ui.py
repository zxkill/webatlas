from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from src.audit_modules.registry import list_modules
from ..deps import get_session
from ..services.domains import list_domains_svc, get_domain_report_svc

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, session=Depends(get_session)) -> HTMLResponse:
    settings = request.app.state.settings
    domains = list_domains_svc(session)
    templates = request.app.state.templates

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "domains": domains,
            "import_path": str(settings.app.import_file_path),
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
