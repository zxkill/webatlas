from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional, Tuple

import aiohttp
from aiolimiter import AsyncLimiter


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
        self._limiter = AsyncLimiter(max_rate=rps, time_period=1.0)
        self._timeout = aiohttp.ClientTimeout(total=total_timeout_s)

    async def get_json(self, session: aiohttp.ClientSession, url: str) -> dict:
        async with self._limiter:
            async with session.get(
                url,
                timeout=self._timeout,
                headers={"User-Agent": "BitrixImport/1.0"},
            ) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        allow_redirects: bool = True,
        method: str = "GET",
    ) -> Optional[HttpResponse]:
        try:
            async with self._limiter:
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
                    return HttpResponse(
                        status=resp.status,
                        final_url=str(resp.url),
                        headers={k: v for k, v in resp.headers.items()},
                        body=body,
                        charset=getattr(resp, "charset", None),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
