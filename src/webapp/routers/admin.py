from __future__ import annotations

from fastapi import APIRouter, Form
from fastapi.responses import RedirectResponse

from ..services.tasks import (
    enqueue_domain,
    audit_all,
    audit_limit,
    audit_domain,
)

router = APIRouter()


@router.post("/enqueue")
def enqueue(domain: str = Form(...)) -> RedirectResponse:
    enqueue_domain(domain.strip(), source="ui")
    return RedirectResponse(url="/", status_code=303)


@router.post("/admin/audit-all")
def admin_audit_all(modules: list[str] | None = Form(None)) -> RedirectResponse:
    audit_all(modules)
    return RedirectResponse(url="/", status_code=303)


@router.post("/admin/audit-limit")
def admin_audit_limit(limit: int = Form(...), modules: list[str] | None = Form(None)) -> RedirectResponse:
    audit_limit(limit, modules)
    return RedirectResponse(url="/", status_code=303)


@router.post("/admin/audit-domain")
def admin_audit_domain(domain: str = Form(...), modules: list[str] | None = Form(None)) -> RedirectResponse:
    audit_domain(domain.strip(), modules)
    return RedirectResponse(url="/", status_code=303)
