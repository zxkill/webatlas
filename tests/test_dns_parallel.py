import asyncio
from types import SimpleNamespace

import pytest

from src.audit_modules.dns.dns import DnsAuditModule
from src.audit_modules.types import AuditContext, ModuleResult
from src.http import HttpClient


@pytest.mark.usefixtures("monkeypatch")
def test_dns_run_offloads_to_thread(monkeypatch) -> None:
    """
    Проверяем, что DNS-аудит уходит в asyncio.to_thread,
    чтобы не блокировать event loop и сохранять параллельность.
    """
    called: dict[str, object] = {}

    async def fake_to_thread(func, *args, **kwargs):
        # Фиксируем вызов, чтобы убедиться в переносе блокирующей логики.
        called["func"] = func
        called["args"] = args
        return ModuleResult()

    monkeypatch.setattr("src.audit_modules.dns.dns.asyncio.to_thread", fake_to_thread)

    module = DnsAuditModule()
    context = AuditContext(
        domain="example.com",
        session=SimpleNamespace(),
        http=HttpClient(rps=1, total_timeout_s=1),
        config=SimpleNamespace(),
    )

    result = asyncio.run(module.run(context))

    assert isinstance(result, ModuleResult)
    assert called.get("func") == module._run_blocking_audit
    assert isinstance(called.get("args"), tuple)
    assert called.get("args")[0] == "example.com"
