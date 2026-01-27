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
class HttpResponse:
    status: int
    final_url: str
    headers: dict[str, str]
    body: bytes
    charset: Optional[str]


class HttpClient:
    """
    HTTP-клиент с глобальным ограничением RPS.
    Важно: лимитер общий для всех запросов — проще соблюдать 3 rps.
    """

    def __init__(self, rps: float, total_timeout_s: int) -> None:
        # Ограничиваем общий RPS, чтобы не перегружать внешние ресурсы.
        self._limiter = AsyncLimiter(max_rate=rps, time_period=1.0)
        # Единый таймаут на весь запрос.
        self._timeout = aiohttp.ClientTimeout(total=total_timeout_s)

    async def get_json(self, session: aiohttp.ClientSession, url: str) -> dict:
        # Получаем JSON, соблюдая ограничение RPS.
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

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        allow_redirects: bool = True,
        method: str = "GET",
    ) -> Optional[HttpResponse]:
        try:
            # Оборачиваем запрос в ограничитель RPS и логируем время выполнения.
            async with self._limiter:
                start = time.monotonic()
                async with session.request(
                    method,
                    url,
                    timeout=self._timeout,
                    allow_redirects=allow_redirects,
                    headers={
                        "User-Agent": "BitrixAudit/1.0 (+permissioned-audit)",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                ) as resp:
                    body = await resp.read()
                    elapsed = time.monotonic() - start
                    logger.debug(
                        "HTTP %s %s -> %s (redirects=%s) за %.2fs",
                        method,
                        url,
                        resp.status,
                        allow_redirects,
                        elapsed,
                    )
                    return HttpResponse(
                        status=resp.status,
                        final_url=str(resp.url),
                        headers={k: v for k, v in resp.headers.items()},
                        body=body,
                        charset=getattr(resp, "charset", None),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            # Логируем сетевые ошибки и таймауты для отладки.
            logger.warning("HTTP %s %s завершился ошибкой: %s", method, url, exc)
            return None
