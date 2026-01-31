from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp
from aiolimiter import AsyncLimiter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HttpRedirectHop:
    """Один шаг цепочки редиректов."""
    url: str
    status: int
    location: Optional[str]


@dataclass(frozen=True)
class HttpResponse:
    """
    Ответ HTTP.
    Поля подобраны так, чтобы:
    - быть полезными для аудитов
    - не быть избыточными
    """
    status: int
    final_url: str
    headers: dict[str, str]
    body: bytes
    charset: Optional[str]

    # --- Дополнительные поля (не ломают совместимость) ---
    method: str = "GET"
    request_url: str = ""
    elapsed_ms: Optional[int] = None
    ttfb_ms: Optional[int] = None
    response_bytes: Optional[int] = None
    redirects: tuple[HttpRedirectHop, ...] = ()


@dataclass(frozen=True)
class HttpFetchResult:
    """
    Подробный результат запроса.
    Если ok=False, response=None и заполнены reason_code/error_text.
    """
    ok: bool
    response: Optional[HttpResponse]
    reason_code: Optional[str]
    error_text: Optional[str]
    elapsed_ms: Optional[int]


class HttpClient:
    """
    HTTP-клиент с глобальным ограничением RPS.
    """

    def __init__(self, rps: float, total_timeout_s: int) -> None:
        self._limiter = AsyncLimiter(max_rate=rps, time_period=1.0)
        self._timeout = aiohttp.ClientTimeout(total=total_timeout_s)

    async def get_json(self, session: aiohttp.ClientSession, url: str) -> dict:
        async with self._limiter:
            start = time.monotonic()
            async with session.get(
                url,
                timeout=self._timeout,
                headers={"User-Agent": "BitrixImport/1.0"},
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                logger.debug("GET JSON %s -> %s за %.2fs", url, resp.status, time.monotonic() - start)
                return data

    def _classify_error(self, exc: BaseException) -> tuple[str, str]:
        """
        Нормализация сетевых ошибок в стабильные коды.
        Эти коды дальше можно использовать в аналитике/фильтрах.
        """
        # Таймауты
        if isinstance(exc, asyncio.TimeoutError):
            return "timeout_total", str(exc)

        if isinstance(exc, aiohttp.ServerTimeoutError):
            return "timeout_server", str(exc)

        # TLS/SSL
        if isinstance(exc, aiohttp.ClientSSLError):
            return "tls_error", str(exc)

        if isinstance(exc, aiohttp.ClientConnectorSSLError):
            return "tls_connect_error", str(exc)

        # Ошибки подключения (DNS/Connect refused и т.п.)
        if isinstance(exc, aiohttp.ClientConnectorError):
            # Внутри может быть gaierror (DNS), ConnectionRefusedError и т.д.
            inner = getattr(exc, "os_error", None)
            if inner is not None:
                name = inner.__class__.__name__.lower()
                if "gaierror" in name:
                    return "dns_error", str(exc)
                if "connectionrefusederror" in name:
                    return "connection_refused", str(exc)
                if "networkunreachable" in name:
                    return "network_unreachable", str(exc)
            return "connect_error", str(exc)

        if isinstance(exc, aiohttp.TooManyRedirects):
            return "too_many_redirects", str(exc)

        if isinstance(exc, aiohttp.InvalidURL):
            return "invalid_url", str(exc)

        if isinstance(exc, aiohttp.ClientError):
            return "client_error", str(exc)

        return "unknown_error", str(exc)

    async def fetch_ex(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        allow_redirects: bool = True,
        method: str = "GET",
        read_limit_bytes: int = 2_000_000,
        headers: Optional[dict[str, str]] = None,
    ) -> HttpFetchResult:
        """
        Расширенный fetch:
        - reason_code/error_text при ошибках
        - ttfb_ms и total elapsed_ms
        - redirects цепочка
        - ограничение на чтение body, чтобы не съесть память на больших ответах
        """
        req_headers = {
            "User-Agent": "WebAtlasAudit/1.0 (+permissioned-audit)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            req_headers.update(headers)

        async with self._limiter:
            t0 = time.monotonic()
            try:
                async with session.request(
                    method,
                    url,
                    timeout=self._timeout,
                    allow_redirects=allow_redirects,
                    headers=req_headers,
                ) as resp:
                    # Редиректы по истории aiohttp
                    redirects: list[HttpRedirectHop] = []
                    for h in resp.history:
                        redirects.append(
                            HttpRedirectHop(
                                url=str(h.url),
                                status=h.status,
                                location=h.headers.get("Location"),
                            )
                        )

                    # TTFB: читаем 1 байт, фиксируем время
                    ttfb_ms: Optional[int] = None
                    first_byte = b""
                    try:
                        first_byte = await resp.content.read(1)
                        ttfb_ms = int((time.monotonic() - t0) * 1000)
                    except Exception as e:
                        # TTFB не критичен — продолжаем, но логируем.
                        logger.debug("TTFB measurement failed for %s: %s", url, e)

                    # Дочитываем остаток (с лимитом)
                    rest = await resp.content.read(read_limit_bytes)
                    body = first_byte + rest

                    elapsed_ms = int((time.monotonic() - t0) * 1000)

                    logger.debug(
                        "HTTP %s %s -> %s (redirects=%s) elapsed=%sms ttfb=%sms bytes=%s",
                        method,
                        url,
                        resp.status,
                        len(redirects),
                        elapsed_ms,
                        ttfb_ms,
                        len(body),
                    )

                    response = HttpResponse(
                        status=resp.status,
                        final_url=str(resp.url),
                        headers={k: v for k, v in resp.headers.items()},
                        body=body,
                        charset=getattr(resp, "charset", None),
                        method=method,
                        request_url=url,
                        elapsed_ms=elapsed_ms,
                        ttfb_ms=ttfb_ms,
                        response_bytes=len(body),
                        redirects=tuple(redirects),
                    )

                    return HttpFetchResult(
                        ok=True,
                        response=response,
                        reason_code=None,
                        error_text=None,
                        elapsed_ms=elapsed_ms,
                    )

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                reason_code, error_text = self._classify_error(exc)
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                logger.warning(
                    "HTTP %s %s failed reason=%s elapsed=%sms error=%s",
                    method,
                    url,
                    reason_code,
                    elapsed_ms,
                    error_text,
                )
                return HttpFetchResult(
                    ok=False,
                    response=None,
                    reason_code=reason_code,
                    error_text=error_text,
                    elapsed_ms=elapsed_ms,
                )

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        allow_redirects: bool = True,
        method: str = "GET",
    ) -> Optional[HttpResponse]:
        """
        Backward compatible fetch.
        Старые модули (bitrix_detect и т.п.) продолжат работать без изменений.
        """
        res = await self.fetch_ex(session, url, allow_redirects=allow_redirects, method=method)
        return res.response if res.ok else None
