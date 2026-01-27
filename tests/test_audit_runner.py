import asyncio
from types import SimpleNamespace

import pytest

# Пропускаем тесты модульного runner-а, если SQLAlchemy недоступен.
pytest.importorskip("sqlalchemy")

from src.audit_modules.runner import run_modules_for_domain
from src.audit_modules.types import AuditContext, ModuleResult
from src.config import AppConfig, AuditConfig, AuditTimeouts, DbConfig, ImportConfig, RateLimitConfig
from src.http import HttpClient


def _make_config() -> AppConfig:
    # Минимальный конфиг для тестов runner-а.
    return AppConfig(
        db=DbConfig(url="postgresql://user:pass@localhost/db"),
        rate_limit=RateLimitConfig(rps=1.0),
        import_cfg=ImportConfig(
            api_url_template="https://example.test?page={page}&token={token}",
            token="token",
            max_domains=1,
            file_path="domains.txt",
        ),
        audit=AuditConfig(concurrency=1, timeouts=AuditTimeouts(total=1)),
    )


class _BaseModule:
    key = "base"
    name = "Base"
    description = "base"
    depends_on = ()

    async def run(self, context: AuditContext) -> ModuleResult:
        # Возвращаем дополнительный модуль для проверки динамического подключения.
        return ModuleResult(additional_modules=["extra"])


class _ExtraModule:
    key = "extra"
    name = "Extra"
    description = "extra"
    depends_on = ()

    async def run(self, context: AuditContext) -> ModuleResult:
        return ModuleResult()


def test_run_modules_for_domain_adds_dynamic_modules(monkeypatch) -> None:
    # Подменяем реестр модулей и план, чтобы исключить сетевые вызовы.
    import src.audit_modules.runner as runner

    registry = {"base": _BaseModule(), "extra": _ExtraModule()}
    monkeypatch.setattr(runner, "get_registry", lambda: registry)
    monkeypatch.setattr(runner, "resolve_module_plan", lambda selected: ["base"])

    context = AuditContext(
        domain="example.com",
        session=SimpleNamespace(),
        http=HttpClient(rps=1, total_timeout_s=1),
        config=_make_config(),
    )

    summary = asyncio.run(run_modules_for_domain(context, selected_modules=None))

    assert summary.executed_modules == ["base", "extra"]
