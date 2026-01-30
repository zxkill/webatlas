import asyncio
import json
from types import SimpleNamespace
from urllib.parse import urlparse

from src.audit_modules.availability import AvailabilityModule
from src.audit_modules.types import AuditContext
from src.config import AppConfig, AuditConfig, AuditTimeouts, DbConfig, ImportConfig, RateLimitConfig
from src.http import HttpResponse


class _FakeHttpClient:
    """Фейковый HTTP-клиент для эмуляции разных ответов по схемам."""

    def __init__(self, responses: dict[str, HttpResponse | None]) -> None:
        # Храним маппинг ответов по схеме (http/https) для детерминированных тестов.
        self._responses = responses
        self.called: list[str] = []

    async def fetch(self, session, url: str, *, allow_redirects: bool = True, method: str = "GET"):
        # Фиксируем вызовы, чтобы было проще анализировать порядок и количество запросов.
        scheme = urlparse(url).scheme
        self.called.append(scheme)
        return self._responses.get(scheme)


def _make_config() -> AppConfig:
    # Минимальный конфиг для контекста модуля.
    return AppConfig(
        db=DbConfig(url="postgresql://user:pass@localhost/db"),
        rate_limit=RateLimitConfig(rps=1.0),
        import_cfg=ImportConfig(
            url_template="https://example.test?page={page}&token={token}",
            file_path="domains.txt",
        ),
        audit=AuditConfig(concurrency=1, timeouts=AuditTimeouts(total=1)),
    )


def test_availability_allows_http_200_when_https_fails() -> None:
    # HTTPS отдаёт ошибку, но HTTP возвращает 200 — домен должен считаться доступным.
    https_response = HttpResponse(
        status=500,
        final_url="https://example.com/",
        headers={},
        body=b"",
        charset="utf-8",
    )
    http_response = HttpResponse(
        status=200,
        final_url="http://example.com/",
        headers={"Set-Cookie": "sid=abc"},
        body=b"<html></html>",
        charset="utf-8",
    )
    context = AuditContext(
        domain="example.com",
        session=SimpleNamespace(),
        http=_FakeHttpClient({"https": https_response, "http": http_response}),
        config=_make_config(),
    )

    result = asyncio.run(AvailabilityModule().run(context))

    assert context.data["availability"]["reachable"] is True
    assert context.data["availability"]["used_scheme"] == "http"
    assert result.check_updates[0].row.status == "yes"
    evidence = json.loads(result.check_updates[0].row.evidence_json)
    assert evidence["checked"]["https"]["ok"] is False
    assert evidence["checked"]["http"]["ok"] is True


def test_availability_marks_unreachable_without_http_200() -> None:
    # Ни HTTP, ни HTTPS не вернули 200 — домен должен считаться недоступным.
    https_response = HttpResponse(
        status=503,
        final_url="https://example.com/",
        headers={},
        body=b"",
        charset="utf-8",
    )
    http_response = HttpResponse(
        status=404,
        final_url="http://example.com/",
        headers={},
        body=b"",
        charset="utf-8",
    )
    context = AuditContext(
        domain="example.com",
        session=SimpleNamespace(),
        http=_FakeHttpClient({"https": https_response, "http": http_response}),
        config=_make_config(),
    )

    result = asyncio.run(AvailabilityModule().run(context))

    assert context.data["availability"]["reachable"] is False
    assert context.data["availability"]["used_scheme"] is None
    assert result.check_updates[0].row.status == "no"
    evidence = json.loads(result.check_updates[0].row.evidence_json)
    assert evidence["error"] == "no_http_200"
