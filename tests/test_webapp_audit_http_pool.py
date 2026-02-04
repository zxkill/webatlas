import asyncio
from types import SimpleNamespace

from src.audit_modules.types import ModuleRunSummary
from src.settings.loader import AppSettings, RuntimeSettings, Settings
from src.webapp_audit import _audit_stream


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _FakeHttpClient:
    def __init__(self, *, rps, total_timeout_s, pool_limit, pool_limit_per_host):
        self.init_args = {
            "rps": rps,
            "total_timeout_s": total_timeout_s,
            "pool_limit": pool_limit,
            "pool_limit_per_host": pool_limit_per_host,
        }

    def create_session(self):
        return _FakeSession()


async def _fake_run_modules(context, normalized_module_keys):
    return ModuleRunSummary()


def test_audit_stream_uses_http_pool_limits(monkeypatch) -> None:
    """
    Проверяем, что настройки пулов соединений передаются в HttpClient.
    """
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
            audit_concurrency=1,
            audit_timeout_total=2,
            audit_persist_concurrency=1,
            audit_threadpool_workers=0,
            audit_http_pool_limit=777,
            audit_http_pool_limit_per_host=88,
        ),
    )

    created: dict[str, object] = {}

    def _fake_http_client(**kwargs):
        created["client"] = _FakeHttpClient(**kwargs)
        return created["client"]

    monkeypatch.setattr("src.webapp_audit.load_settings", lambda: fake_settings)
    monkeypatch.setattr("src.webapp_audit.HttpClient", _fake_http_client)
    monkeypatch.setattr("src.webapp_audit.run_modules_for_domain", _fake_run_modules)

    async def _runner():
        async for _domain, _summary in _audit_stream(["example.com"], module_keys=None):
            break

    asyncio.run(_runner())

    client = created["client"]
    assert client.init_args["pool_limit"] == 777
    assert client.init_args["pool_limit_per_host"] == 88
