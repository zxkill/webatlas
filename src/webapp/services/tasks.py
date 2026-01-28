from __future__ import annotations

from src.webapp_tasks import (
    add_domain_task,
    import_domains_from_file_task,
    audit_all_task,
    audit_limit_task,
    audit_domain_task,
)


def enqueue_domain(domain: str, source: str = "ui") -> None:
    add_domain_task.delay(domain, source=source)


def import_from_file(file_path: str) -> None:
    import_domains_from_file_task.delay(file_path)


def audit_all(modules: list[str] | None) -> None:
    audit_all_task.delay(modules)


def audit_limit(limit: int, modules: list[str] | None) -> None:
    audit_limit_task.delay(limit, modules)


def audit_domain(domain: str, modules: list[str] | None) -> None:
    task_headers = {"modules": modules} if modules else None
    audit_domain_task.apply_async(args=[domain], headers=task_headers)
