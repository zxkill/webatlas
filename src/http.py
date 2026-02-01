from __future__ import annotations

import asyncio
import logging
import random
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
    HTTP-клиент для аудитов.

    Основные особенности:
    - Глобальный лимит RPS (через AsyncLimiter).
    - Раздельные таймауты (connect/sock_connect/sock_read/total).
    - Пул соединений aiohttp (TCPConnector) с DNS cache и keepalive.
    - Мягкие ретраи для безопасных случаев (dns/connect/timeout_*).
    - Опциональное чтение body (read_body=False) для экономии CPU/трафика/памяти.

    Важно:
    - Для максимального эффекта создавайте session через create_session().
      Если вы создаёте ClientSession() снаружи, пул/таймауты будут зависеть от внешней конфигурации.
    """

    def __init__(
        self,
        rps: float,
        total_timeout_s: int,
        *,
        # --- Таймауты ---
        connect_timeout_s: Optional[float] = None,
        sock_connect_timeout_s: Optional[float] = None,
        sock_read_timeout_s: Optional[float] = None,
        # --- Пул соединений ---
        pool_limit: int = 200,
        pool_limit_per_host: int = 40,
        dns_cache_ttl_s: int = 300,
        keepalive_timeout_s: int = 20,
        # --- Ретраи ---
        retry_attempts: int = 1,
        retry_base_delay_s: float = 0.25,
        retry_max_delay_s: float = 2.0,
    ) -> None:
        self._limiter = AsyncLimiter(max_rate=rps, time_period=1.0)

        # Храним параметры — удобно логировать и переиспользовать.
        self._total_timeout_s = int(total_timeout_s)
        self._connect_timeout_s = connect_timeout_s
        self._sock_connect_timeout_s = sock_connect_timeout_s
        self._sock_read_timeout_s = sock_read_timeout_s

        self._pool_limit = int(pool_limit)
        self._pool_limit_per_host = int(pool_limit_per_host)
        self._dns_cache_ttl_s = int(dns_cache_ttl_s)
        self._keepalive_timeout_s = int(keepalive_timeout_s)

        # retry_attempts = сколько дополнительных попыток после первой (0 = без ретраев)
        self._retry_attempts = max(0, int(retry_attempts))
        self._retry_base_delay_s = float(retry_base_delay_s)
        self._retry_max_delay_s = float(retry_max_delay_s)

        # Собираем timeout (если часть параметров не задана — aiohttp использует дефолты)
        self._timeout = self._build_timeout()

        logger.info(
            "HttpClient init rps=%s total_timeout_s=%s connect=%s sock_connect=%s sock_read=%s "
            "pool_limit=%s per_host=%s dns_ttl=%ss keepalive=%ss retry_attempts=%s",
            rps,
            self._total_timeout_s,
            self._connect_timeout_s,
            self._sock_connect_timeout_s,
            self._sock_read_timeout_s,
            self._pool_limit,
            self._pool_limit_per_host,
            self._dns_cache_ttl_s,
            self._keepalive_timeout_s,
            self._retry_attempts,
        )

    def _build_timeout(self) -> aiohttp.ClientTimeout:
        """Строит раздельные таймауты aiohttp."""
        return aiohttp.ClientTimeout(
            total=self._total_timeout_s,
            connect=self._connect_timeout_s,
            sock_connect=self._sock_connect_timeout_s,
            sock_read=self._sock_read_timeout_s,
        )

    def build_connector(self) -> aiohttp.TCPConnector:
        """
        Создаёт TCPConnector для пула соединений.

        - limit: общий лимит одновременных коннектов
        - limit_per_host: лимит на один host
        - ttl_dns_cache: кэш DNS, чтобы не долбить резолвер
        - keepalive_timeout: время жизни keepalive соединения
        """
        return aiohttp.TCPConnector(
            limit=self._pool_limit,
            limit_per_host=self._pool_limit_per_host,
            ttl_dns_cache=self._dns_cache_ttl_s,
            keepalive_timeout=self._keepalive_timeout_s,
            enable_cleanup_closed=True,
        )

    def create_session(self) -> aiohttp.ClientSession:
        """
        Удобный фабричный метод для создания ClientSession с правильным пулом и таймаутами.

        Использование:
            async with http.create_session() as session:
                res = await http.fetch_ex(session, url, ...)

        Почему так:
        - Пул и таймауты должны быть согласованы с конкуррентностью движка.
        - Если session создаётся снаружи, вы теряете эти оптимизации.
        """
        connector = self.build_connector()
        return aiohttp.ClientSession(connector=connector, timeout=self._timeout)

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

    @staticmethod
    def _is_idempotent_method(method: str) -> bool:
        """Ретраи допустимы только для идемпотентных методов."""
        return method.upper() in {"GET", "HEAD", "OPTIONS"}

    @staticmethod
    def _retryable_reason(reason_code: str) -> bool:
        """Разрешаем ретрай только на безопасные классы ошибок."""
        return reason_code in {
            "dns_error",
            "connect_error",
            "timeout_total",
            "timeout_server",
            "network_unreachable",
            # connection_refused можно ретраить, но обычно это бесполезно; оставим выключенным
            # "connection_refused",
        }

    def _compute_backoff(self, attempt_index: int) -> float:
        """
        Экспоненциальный backoff + jitter.
        attempt_index: 0 для первого ретрая, 1 для второго и т.д.
        """
        base = self._retry_base_delay_s * (2 ** attempt_index)
        base = min(base, self._retry_max_delay_s)
        # Jitter: 0.5..1.5
        jitter = 0.5 + random.random()
        return base * jitter

    async def fetch_ex(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        allow_redirects: bool = True,
        method: str = "GET",
        read_limit_bytes: int = 2_000_000,
        read_body: bool = True,
        headers: Optional[dict[str, str]] = None,
    ) -> HttpFetchResult:
        """
        Расширенный fetch:
        - reason_code/error_text при ошибках
        - ttfb_ms и total elapsed_ms
        - redirects цепочка
        - ограничение на чтение body (read_limit_bytes)
        - режим без чтения body (read_body=False)
        - мягкие ретраи на безопасные ошибки
        """
        req_headers = {
            "User-Agent": "WebAtlasAudit/1.0 (+permissioned-audit)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            req_headers.update(headers)

        total_t0 = time.monotonic()
        attempts_total = 1 + self._retry_attempts

        for attempt in range(attempts_total):
            attempt_no = attempt + 1
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
                        redirects: list[HttpRedirectHop] = [
                            HttpRedirectHop(
                                url=str(h.url),
                                status=h.status,
                                location=h.headers.get("Location"),
                            )
                            for h in resp.history
                        ]

                        ttfb_ms: Optional[int] = None
                        body = b""

                        if read_body:
                            # TTFB: читаем 1 байт, фиксируем время
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
                        else:
                            # Важно вернуть соединение в пул, не читая тело.
                            # resp.release() сбрасывает оставшийся контент и возвращает коннект.
                            resp.release()

                        elapsed_ms = int((time.monotonic() - total_t0) * 1000)

                        logger.debug(
                            "HTTP %s %s -> %s (attempt=%s/%s redirects=%s) elapsed=%sms ttfb=%sms bytes=%s read_body=%s",
                            method,
                            url,
                            resp.status,
                            attempt_no,
                            attempts_total,
                            len(redirects),
                            elapsed_ms,
                            ttfb_ms,
                            len(body),
                            read_body,
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
                    elapsed_ms = int((time.monotonic() - total_t0) * 1000)

                    # Решаем, есть ли смысл ретраить
                    can_retry = (
                        attempt < attempts_total - 1
                        and self._is_idempotent_method(method)
                        and self._retryable_reason(reason_code)
                    )

                    logger.warning(
                        "HTTP %s %s failed reason=%s attempt=%s/%s elapsed=%sms retry=%s error=%s",
                        method,
                        url,
                        reason_code,
                        attempt_no,
                        attempts_total,
                        elapsed_ms,
                        can_retry,
                        error_text,
                    )

                    if not can_retry:
                        return HttpFetchResult(
                            ok=False,
                            response=None,
                            reason_code=reason_code,
                            error_text=error_text,
                            elapsed_ms=elapsed_ms,
                        )

                    # Backoff + jitter перед следующей попыткой
                    delay_s = self._compute_backoff(attempt)
                    logger.info(
                        "Retrying HTTP %s %s in %.2fs (reason=%s attempt=%s/%s)",
                        method,
                        url,
                        delay_s,
                        reason_code,
                        attempt_no,
                        attempts_total,
                    )
                    await asyncio.sleep(delay_s)

        # На практике сюда не попадём (return происходит внутри цикла),
        # но оставим как страховку.
        elapsed_ms = int((time.monotonic() - total_t0) * 1000)
        return HttpFetchResult(
            ok=False,
            response=None,
            reason_code="unknown_error",
            error_text="exhausted_retries_without_result",
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
        Старые модули продолжат работать без изменений.
        """
        res = await self.fetch_ex(session, url, allow_redirects=allow_redirects, method=method)
        return res.response if res.ok else None
