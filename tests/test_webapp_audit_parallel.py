from __future__ import annotations

from types import SimpleNamespace

from src.audit_modules.types import ModuleRunSummary
from src.settings.loader import AppSettings, RuntimeSettings, Settings
from src.webapp_audit import run_audit_and_persist


async def _fake_audit_stream(domains, module_keys=None):
    # Возвращаем пару результатов, чтобы проверить планирование параллельных persist-задач.
    yield "first.example", ModuleRunSummary()
    yield "second.example", ModuleRunSummary()


def test_run_audit_and_persist_uses_threadpool(monkeypatch) -> None:
    """
    Проверяем, что синхронная запись результатов уходит в threadpool
    и не блокирует event loop в процессе массового аудита.
    """
    persisted_domains: list[str] = []

    def fake_persist(domain, summary, session_factory):
        # Имитация синхронной записи результата в БД.
        persisted_domains.append(domain)

    async def fake_to_thread(func, *args, **kwargs):
        # Имитируем asyncio.to_thread через прямой вызов функции.
        func(*args, **kwargs)
        return None

    fake_settings = Settings(
        runtime=RuntimeSettings(
            database_url="postgresql://user:pass@localhost/db",
            redis_url="redis://localhost:6379/0",
            celery_broker_url="redis://localhost:6379/1",
            celery_backend_url="redis://localhost:6379/2",
            app_host="0.0.0.0",
            app_port=8088,
            celery_always_eager=True,
            log_level="INFO",
        ),
        app=AppSettings(
            rate_limit_rps=1.0,
            import_url_template="https://example.test",
            audit_concurrency=2,
            audit_timeout_total=1,
            audit_persist_concurrency=2,
        ),
    )

    monkeypatch.setattr("src.webapp_audit._audit_stream", _fake_audit_stream)
    monkeypatch.setattr("src.webapp_audit._persist_summary", fake_persist)
    monkeypatch.setattr("src.webapp_audit.asyncio.to_thread", fake_to_thread)
    monkeypatch.setattr("src.webapp_audit.load_settings", lambda: fake_settings)

    processed = run_audit_and_persist(["ignored.example"], session_factory=lambda: SimpleNamespace())

    assert processed == 2
    assert persisted_domains == ["first.example", "second.example"]
