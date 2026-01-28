from __future__ import annotations

from src.webapp_db import list_domains, get_domain_report


def list_domains_svc(session):
    return list_domains(session)


def get_domain_report_svc(session, domain: str):
    return get_domain_report(session, domain)
