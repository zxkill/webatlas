from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


def _ensure_url(scheme: str, host: str, path: str) -> str:
    return urlunparse((scheme, host, path, "", "", ""))


def _pick_cache_headers(headers: dict[str, str]) -> dict[str, str | None]:
    # Собираем только то, что полезно для аудита, чтобы не хранить “всё подряд”
    def g(name: str) -> str | None:
        return headers.get(name) or headers.get(name.lower())

    return {
        "cache_control": g("Cache-Control"),
        "expires": g("Expires"),
        "etag": g("ETag"),
        "last_modified": g("Last-Modified"),
        "age": g("Age"),
        "vary": g("Vary"),
    }


@dataclass(frozen=True)
class EndpointInfo:
    path: str
    request_url: str
    final_url: str | None
    http_status: int | None
    ok: bool
    content_type: str | None
    response_bytes: int | None
    cache: dict[str, str | None]
    redirect_count: int | None


WELL_KNOWN_DEFAULT = (
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
)


async def fetch_endpoint_map(
    context,
    scheme: str,
    host: str,
    paths: list[str],
) -> list[EndpointInfo]:
    """
    Важно: эта карта НЕ влияет на вердикт доступности (это “диагностика/профиль”).
    Используем allow_redirects=True, метод GET.
    """

    out: list[EndpointInfo] = []

    for path in paths:
        url = _ensure_url(scheme, host, path)
        logger.info("[availability.endpoints] fetch scheme=%s host=%s path=%s url=%s", scheme, host, path, url)

        res = await context.http.fetch_ex(
            context.session,
            url,
            allow_redirects=True,
            method="GET",
        )

        if not res.ok or res.response is None:
            out.append(
                EndpointInfo(
                    path=path,
                    request_url=url,
                    final_url=None,
                    http_status=None,
                    ok=False,
                    content_type=None,
                    response_bytes=None,
                    cache={},
                    redirect_count=None,
                )
            )
            continue

        resp = res.response
        headers = dict(resp.headers) if resp.headers else {}
        cache = _pick_cache_headers(headers)

        out.append(
            EndpointInfo(
                path=path,
                request_url=url,
                final_url=resp.final_url,
                http_status=resp.status,
                ok=True,
                content_type=headers.get("Content-Type") or headers.get("content-type"),
                response_bytes=resp.response_bytes,
                cache=cache,
                redirect_count=len(resp.redirects),
            )
        )

    return out


def endpoint_map_kpis(items: list[EndpointInfo]) -> dict:
    """
    KPI/сводка по карте эндпоинтов.
    """
    total = len(items)
    ok2xx = 0
    redirects = 0
    missing_404 = 0

    for it in items:
        if it.http_status and 200 <= it.http_status <= 299:
            ok2xx += 1
        if it.http_status and 300 <= it.http_status <= 399:
            redirects += 1
        if it.http_status == 404:
            missing_404 += 1

    return {
        "total": total,
        "ok2xx": ok2xx,
        "redirects": redirects,
        "missing_404": missing_404,
    }


def endpoint_map_to_dict(items: list[EndpointInfo]) -> list[dict]:
    """
    Готовим сериализуемый вид для evidence/report.
    """
    rows: list[dict] = []
    for it in items:
        final_host = None
        final_scheme = None
        if it.final_url:
            try:
                p = urlparse(it.final_url)
                final_host = p.netloc or None
                final_scheme = p.scheme or None
            except Exception:
                pass

        rows.append(
            {
                "path": it.path,
                "request_url": it.request_url,
                "final_url": it.final_url,
                "final_scheme": final_scheme,
                "final_host": final_host,
                "http_status": it.http_status,
                "content_type": it.content_type,
                "response_bytes": it.response_bytes,
                "redirect_count": it.redirect_count,
                "cache": it.cache or {},
            }
        )
    return rows
