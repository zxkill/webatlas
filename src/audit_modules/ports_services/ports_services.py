from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from src.audit_modules.types import AuditContext, ModuleResult
from src.webapp_db import Base, Domain, create_domain

logger = logging.getLogger(__name__)


# -----------------------------
# Defaults
# -----------------------------

DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53,
    80, 110, 143,
    443, 465, 587,
    993, 995,
    1433, 1521, 2049, 2375,
    3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9000, 9200, 27017,
    11211,
]

# Порты, где разумно пытаться TLS “в лоб” (implicit TLS)
TLS_LIKELY_PORTS: set[int] = {443, 465, 993, 995, 8443}

# Протоколы для ALPN — полезно для HTTPS (h2/http1.1)
ALPN_PROTOCOLS: list[str] = ["h2", "http/1.1"]

# Ограничение чтения баннера (чтобы не тянуть мегабайты)
BANNER_READ_LIMIT = 4096

# Таймауты (сек)
CONNECT_TIMEOUT_S = 2.5
READ_TIMEOUT_S = 2.0

# Конкурентность по умолчанию (перекрывается профилем)
MAX_CONCURRENCY_DEFAULT = 80


# -----------------------------
# Profiles (ports + depth)
# -----------------------------

PROFILE_FAST_PORTS: list[int] = [80, 443, 22, 25, 587, 110, 143, 8080, 8443, 3389, 5432, 3306]

PROFILE_STANDARD_PORTS: list[int] = DEFAULT_PORTS

PROFILE_EXTENDED_PORTS: list[int] = sorted(set(DEFAULT_PORTS + [
    81, 82, 83, 88,
    3000, 5000, 5001, 7001, 8888,
    9443, 10443,
]))

PORTS_PROFILES: dict[str, dict[str, Any]] = {
    "fast": {
        "ports": PROFILE_FAST_PORTS,
        "enable_http_headers": True,
        "enable_starttls": False,
        "try_tls_on_http_like": False,
        "max_concurrency": 120,
    },
    "standard": {
        "ports": PROFILE_STANDARD_PORTS,
        "enable_http_headers": True,
        "enable_starttls": True,
        "try_tls_on_http_like": True,
        "max_concurrency": 80,
    },
    "extended": {
        "ports": PROFILE_EXTENDED_PORTS,
        "enable_http_headers": True,
        "enable_starttls": True,
        "try_tls_on_http_like": True,
        "max_concurrency": 60,
    },
}


def _load_cfg(context: AuditContext) -> dict[str, Any]:
    """
    Конфиг можно прокидывать через context.data["ports_services_cfg"].

    Пример:
      {
        "profile": "standard",
        "ports": [80,443,8080],
        "enable_starttls": true,
        "try_tls_on_http_like": true
      }
    """
    raw: dict[str, Any] = {}
    if isinstance(context.data, dict):
        maybe = context.data.get("ports_services_cfg") or {}
        if isinstance(maybe, dict):
            raw = maybe

    profile_name = str(raw.get("profile") or "standard").lower().strip()
    base = dict(PORTS_PROFILES.get(profile_name, PORTS_PROFILES["standard"]))

    # Явный список портов имеет приоритет
    ports = raw.get("ports")
    if isinstance(ports, list) and all(isinstance(x, int) for x in ports):
        base["ports"] = sorted(set(int(x) for x in ports if 1 <= x <= 65535))

    # Перекрытия глубины проб
    for k in ("enable_http_headers", "enable_starttls", "try_tls_on_http_like", "max_concurrency"):
        if k in raw:
            base[k] = raw[k]

    base["profile"] = profile_name
    return base


def _pick_ports(context: AuditContext) -> list[int]:
    cfg = _load_cfg(context)
    return list(cfg["ports"])


# -----------------------------
# Helpers
# -----------------------------

def _now_ts() -> int:
    return int(time.time())


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")


def _safe_decode(b: bytes) -> str:
    return _strip_nul(b.decode("utf-8", errors="replace")) or ""

def _strip_nul(s: str | None) -> str | None:
    """
    PostgreSQL не принимает NUL (0x00) внутри строк.
    Поэтому вычищаем его везде, где храним строки (banner/http headers/error/evidence_json).
    """
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "")


def _make_ssl_ctx(server_hostname: str) -> ssl.SSLContext:
    """
    TLS-контекст для “диагностического” рукопожатия.
    Верификацию оставляем включённой: это даёт полезный сигнал о проблемах цепочки/hostname.
    """
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(ALPN_PROTOCOLS)
    except Exception:
        pass
    return ctx


def _extract_tls_meta(writer: asyncio.StreamWriter) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    try:
        sslobj: ssl.SSLObject | None = writer.get_extra_info("ssl_object")
        if not sslobj:
            return meta

        meta["tls_version"] = sslobj.version()
        meta["cipher"] = (sslobj.cipher() or (None, None, None))[0]

        try:
            meta["alpn"] = sslobj.selected_alpn_protocol()
        except Exception:
            meta["alpn"] = None

        try:
            cert = sslobj.getpeercert()
            if cert:
                meta["cert_subject"] = cert.get("subject")
                meta["cert_issuer"] = cert.get("issuer")
                meta["cert_not_before"] = cert.get("notBefore")
                meta["cert_not_after"] = cert.get("notAfter")
                meta["cert_san"] = cert.get("subjectAltName")
        except Exception:
            pass

    except Exception:
        return meta

    return meta


async def _read_some(reader: asyncio.StreamReader, limit: int, timeout_s: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout=timeout_s)
    except asyncio.TimeoutError:
        return b""
    except Exception:
        return b""


async def _write_some(writer: asyncio.StreamWriter, data: bytes) -> None:
    try:
        writer.write(data)
        await writer.drain()
    except Exception:
        return


def _parse_http_headers(response: str) -> dict[str, str]:
    """
    Берём только статус-линию + заголовки. Никакого body.
    Возвращаем интересующие заголовки в нормализованном виде.
    """
    headers: dict[str, str] = {}

    lines = response.splitlines()
    if not lines:
        return {}

    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    picked: dict[str, str] = {}
    mapping = (
        ("server", "server"),
        ("location", "location"),
        ("x-powered-by", "powered_by"),
        ("via", "via"),
    )
    for src, dst in mapping:
        if src in headers:
            picked[dst] = headers[src]

    return picked


def _guess_service(*, port: int, is_tls: bool, banner: str, alpn: str | None) -> str:
    up = (banner or "").upper()

    if port == 22 or "SSH-" in up:
        return "ssh"
    if port in (80, 8080, 8000, 8888) or up.startswith("HTTP/"):
        return "http"
    if port in (443, 8443) or (is_tls and (alpn in ("h2", "http/1.1") or "HTTP/" in up)):
        return "https"
    if port in (25, 587, 465) or "ESMTP" in up or "SMTP" in up:
        return "smtp"
    if port in (110, 995) or up.startswith("+OK"):
        return "pop3"
    if port in (143, 993) or "* OK" in up or "IMAP" in up:
        return "imap"
    if port == 6379 or "REDIS" in up:
        return "redis"
    if port == 5432 or "POSTGRES" in up:
        return "postgres"
    if port == 3306 or "MYSQL" in up:
        return "mysql"
    if port == 11211 or "MEMCACHED" in up:
        return "memcached"

    return "unknown"


async def _start_tls_over_existing(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    server_hostname: str,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, dict[str, Any]]:
    """
    Переводит существующее соединение на TLS (STARTTLS/STLS).
    Возвращает новый (reader, writer) и tls_meta.

    Важно: используем asyncio.loop.start_tls() и корректно подменяем transport в writer.
    """
    loop = asyncio.get_running_loop()
    transport = writer.transport
    protocol = writer._protocol  # noqa: SLF001 (диагностический модуль)
    ctx = _make_ssl_ctx(server_hostname)

    tls_transport = await loop.start_tls(
        transport,
        protocol,
        ctx,
        server_side=False,
        server_hostname=server_hostname,
    )

    writer._transport = tls_transport  # noqa: SLF001
    tls_meta = _extract_tls_meta(writer)
    return reader, writer, tls_meta


# -----------------------------
# Data model (in-memory)
# -----------------------------

@dataclass
class PortCheckResult:
    port: int
    ok: bool
    is_open: bool
    is_tls: bool
    connect_ms: int | None
    read_ms: int | None
    error: str | None
    banner: str
    alpn: str | None
    tls_version: str | None
    cipher: str | None
    service: str

    http_server: str | None
    http_location: str | None
    http_powered_by: str | None
    http_via: str | None

    evidence: dict[str, Any]


# -----------------------------
# Module
# -----------------------------

class PortsServicesModule:
    """
    Аудит “Порты и сервисы”:
      - открыт ли порт
      - что за сервис (эвристика по баннеру/пробам)
      - TLS/ALPN (implicit TLS + optional TLS-on-http-like)
      - STARTTLS (опционально) для 25/587/143/110
      - HTTP headers (Server/Location/X-Powered-By/Via) на любых портах, если это HTTP(S)
    """

    key = "ports_services"
    name = "Порты и сервисы"
    description = "Проверка TCP-портов, баннеры, TLS/ALPN, STARTTLS (опционально) и краткие HTTP-заголовки."
    depends_on: tuple[str, ...] = ("availability",)

    async def run(self, context: AuditContext) -> ModuleResult:
        availability = context.data.get("availability", {}) if isinstance(context.data, dict) else {}
        if not availability or not availability.get("reachable"):
            logger.info("[ports_services] skip: domain unreachable: %s", context.domain)
            return ModuleResult()

        cfg = _load_cfg(context)
        domain = context.domain
        checked_ts = _now_ts()
        ports = _pick_ports(context)

        max_conc = int(cfg.get("max_concurrency") or MAX_CONCURRENCY_DEFAULT)
        sem = asyncio.Semaphore(max_conc)

        logger.info(
            "[ports_services] start domain=%s profile=%s ports=%s conc=%s",
            domain,
            cfg.get("profile"),
            len(ports),
            max_conc,
        )

        async def _check_one(port: int) -> PortCheckResult:
            start = time.perf_counter()

            banner = ""
            tls_meta: dict[str, Any] = {}
            is_open = False
            is_tls = False
            connect_ms: int | None = None
            read_ms: int | None = None
            error: str | None = None

            http_server: str | None = None
            http_location: str | None = None
            http_powered_by: str | None = None
            http_via: str | None = None

            evidence: dict[str, Any] = {
                "domain": domain,
                "port": port,
                "profile": cfg.get("profile"),
                "probes": [],
            }

            async with sem:
                # --- Plain TCP connect ---
                try:
                    t0 = time.perf_counter()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=domain, port=port),
                        timeout=CONNECT_TIMEOUT_S,
                    )
                    t1 = time.perf_counter()

                    connect_ms = int((t1 - t0) * 1000)
                    is_open = True
                    evidence["probes"].append({"type": "tcp_connect", "ok": True, "ms": connect_ms})

                    # Read immediate banner (SSH/SMTP/...)
                    r0 = time.perf_counter()
                    raw = await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)
                    r1 = time.perf_counter()
                    read_ms = int((r1 - r0) * 1000)
                    banner = _safe_decode(raw).strip()
                    evidence["probes"].append({"type": "banner_read", "bytes": len(raw), "ms": read_ms})

                    # --- Optional STARTTLS / STLS (over existing plain connection) ---
                    # Включается профилем; выполняется до HTTP-проверок, чтобы не мешать протоколам.
                    if cfg.get("enable_starttls") and is_open:
                        # SMTP: 25/587 (465 — implicit TLS, там STARTTLS не нужен)
                        if port in (25, 587):
                            try:
                                # Greeting уже прочитан; если пусто — читаем ещё раз
                                if not banner:
                                    banner = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)).strip()

                                await _write_some(writer, b"EHLO webatlas\r\n")
                                _ = await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)

                                await _write_some(writer, b"STARTTLS\r\n")
                                resp = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S))
                                if resp.startswith("220"):
                                    reader, writer, stls_meta = await _start_tls_over_existing(reader, writer, domain)
                                    is_tls = True
                                    tls_meta = tls_meta or stls_meta
                                    evidence["probes"].append({"type": "starttls_smtp", "ok": True, "meta": stls_meta})
                                else:
                                    evidence["probes"].append({"type": "starttls_smtp", "ok": False, "reply": resp[:160]})
                            except Exception as e:
                                evidence["probes"].append({"type": "starttls_smtp", "ok": False, "error": type(e).__name__})

                        # IMAP: 143
                        if port == 143:
                            try:
                                if not banner:
                                    banner = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)).strip()

                                await _write_some(writer, b"a1 STARTTLS\r\n")
                                resp = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S))
                                if "OK" in resp.upper():
                                    reader, writer, stls_meta = await _start_tls_over_existing(reader, writer, domain)
                                    is_tls = True
                                    tls_meta = tls_meta or stls_meta
                                    evidence["probes"].append({"type": "starttls_imap", "ok": True, "meta": stls_meta})
                                else:
                                    evidence["probes"].append({"type": "starttls_imap", "ok": False, "reply": resp[:160]})
                            except Exception as e:
                                evidence["probes"].append({"type": "starttls_imap", "ok": False, "error": type(e).__name__})

                        # POP3: 110 (STLS)
                        if port == 110:
                            try:
                                if not banner:
                                    banner = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)).strip()

                                await _write_some(writer, b"STLS\r\n")
                                resp = _safe_decode(await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S))
                                if resp.startswith("+OK"):
                                    reader, writer, stls_meta = await _start_tls_over_existing(reader, writer, domain)
                                    is_tls = True
                                    tls_meta = tls_meta or stls_meta
                                    evidence["probes"].append({"type": "starttls_pop3", "ok": True, "meta": stls_meta})
                                else:
                                    evidence["probes"].append({"type": "starttls_pop3", "ok": False, "reply": resp[:160]})
                            except Exception as e:
                                evidence["probes"].append({"type": "starttls_pop3", "ok": False, "error": type(e).__name__})

                    # --- Optional HTTP headers probe (plain) on ANY port ---
                    # Выполняем только если включено профилем.
                    if cfg.get("enable_http_headers"):
                        req = (
                            f"HEAD / HTTP/1.1\r\n"
                            f"Host: {domain}\r\n"
                            f"User-Agent: WebAtlas/ports_services\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode("utf-8", errors="ignore")

                        await _write_some(writer, req)
                        raw2 = await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)
                        if raw2:
                            txt = _safe_decode(raw2)
                            if txt.startswith("HTTP/"):
                                picked = _parse_http_headers(txt)
                                if picked:
                                    picked = {k: (_strip_nul(v) or "") for k, v in picked.items()}
                                http_server = picked.get("server") or None
                                http_location = picked.get("location") or None
                                http_powered_by = picked.get("powered_by") or None
                                http_via = picked.get("via") or None

                                first_line = txt.splitlines()[0].strip()
                                if first_line:
                                    banner = first_line

                                evidence["probes"].append({"type": "http_head_plain", "ok": True, "picked": picked})
                            else:
                                evidence["probes"].append({"type": "http_head_plain", "ok": False, "note": "not_http"})
                        else:
                            evidence["probes"].append({"type": "http_head_plain", "ok": False, "note": "empty"})

                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                except asyncio.TimeoutError:
                    error = "connect_timeout"
                    evidence["probes"].append({"type": "tcp_connect", "ok": False, "error": error})
                    is_open = False
                except (OSError, socket.gaierror) as e:
                    error = f"os_error:{type(e).__name__}"
                    evidence["probes"].append({"type": "tcp_connect", "ok": False, "error": error})
                    is_open = False
                except Exception as e:
                    error = f"error:{type(e).__name__}"
                    evidence["probes"].append({"type": "tcp_connect", "ok": False, "error": error})
                    is_open = False

            # --- TLS handshake attempt (implicit TLS ports) ---
            if is_open and (port in TLS_LIKELY_PORTS):
                try:
                    ctx = _make_ssl_ctx(domain)
                    t0 = time.perf_counter()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=domain, port=port, ssl=ctx, server_hostname=domain),
                        timeout=CONNECT_TIMEOUT_S,
                    )
                    t1 = time.perf_counter()
                    is_tls = True

                    tls_connect_ms = int((t1 - t0) * 1000)
                    tls_meta = _extract_tls_meta(writer)
                    evidence["probes"].append(
                        {"type": "tls_handshake", "ok": True, "ms": tls_connect_ms, "meta": tls_meta}
                    )

                    # HTTPS HEAD for 443/8443 (и вообще implicit TLS-порты)
                    if cfg.get("enable_http_headers"):
                        req = (
                            f"HEAD / HTTP/1.1\r\n"
                            f"Host: {domain}\r\n"
                            f"User-Agent: WebAtlas/ports_services\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode("utf-8", errors="ignore")
                        await _write_some(writer, req)
                        raw2 = await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)

                        if raw2:
                            txt = _safe_decode(raw2)
                            if txt.startswith("HTTP/"):
                                picked = _parse_http_headers(txt)
                                if picked:
                                    picked = {k: (_strip_nul(v) or "") for k, v in picked.items()}
                                http_server = picked.get("server") or None
                                http_location = picked.get("location") or None
                                http_powered_by = picked.get("powered_by") or None
                                http_via = picked.get("via") or None

                                first_line = txt.splitlines()[0].strip()
                                if first_line and not banner:
                                    banner = first_line

                                evidence["probes"].append({"type": "http_head_tls", "ok": True, "picked": picked})
                            else:
                                evidence["probes"].append({"type": "http_head_tls", "ok": False, "note": "not_http"})
                        else:
                            evidence["probes"].append({"type": "http_head_tls", "ok": False, "note": "empty"})

                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                except ssl.SSLError as e:
                    evidence["probes"].append({"type": "tls_handshake", "ok": False, "error": f"ssl:{type(e).__name__}"})
                except Exception as e:
                    evidence["probes"].append({"type": "tls_handshake", "ok": False, "error": type(e).__name__})

            # --- TLS-on-http-like (non-standard ports) ---
            need_try_tls = (
                is_open
                and bool(cfg.get("try_tls_on_http_like"))
                and (port not in TLS_LIKELY_PORTS)
                and cfg.get("enable_http_headers")
                and (http_server is None and http_location is None and http_powered_by is None and http_via is None)
            )
            if need_try_tls:
                try:
                    ctx = _make_ssl_ctx(domain)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=domain, port=port, ssl=ctx, server_hostname=domain),
                        timeout=CONNECT_TIMEOUT_S,
                    )
                    is_tls = True
                    tls_meta = tls_meta or _extract_tls_meta(writer)

                    req = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        f"User-Agent: WebAtlas/ports_services\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("utf-8", errors="ignore")

                    await _write_some(writer, req)
                    raw2 = await _read_some(reader, BANNER_READ_LIMIT, READ_TIMEOUT_S)

                    if raw2:
                        txt = _safe_decode(raw2)
                        if txt.startswith("HTTP/"):
                            picked = _parse_http_headers(txt)
                            if picked:
                                picked = {k: (_strip_nul(v) or "") for k, v in picked.items()}
                            http_server = picked.get("server") or None
                            http_location = picked.get("location") or None
                            http_powered_by = picked.get("powered_by") or None
                            http_via = picked.get("via") or None

                            first_line = txt.splitlines()[0].strip()
                            if first_line and not banner:
                                banner = first_line

                            evidence["probes"].append({"type": "http_head_tls_nonstd", "ok": True, "picked": picked})
                        else:
                            evidence["probes"].append({"type": "http_head_tls_nonstd", "ok": False, "note": "not_http"})
                    else:
                        evidence["probes"].append({"type": "http_head_tls_nonstd", "ok": False, "note": "empty"})

                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                except Exception as e:
                    evidence["probes"].append({"type": "http_head_tls_nonstd", "ok": False, "error": type(e).__name__})

            total_ms = int((time.perf_counter() - start) * 1000)

            alpn = tls_meta.get("alpn") if tls_meta else None
            tls_version = tls_meta.get("tls_version") if tls_meta else None
            cipher = tls_meta.get("cipher") if tls_meta else None

            service = _guess_service(
                port=port,
                is_tls=is_tls,
                banner=banner or "",
                alpn=alpn,
            )

            compact_banner = _strip_nul((banner or "").strip()) or ""
            if len(compact_banner) > 900:
                compact_banner = compact_banner[:900] + "…"

            evidence["timing"] = {
                "total_ms": total_ms,
                "connect_ms": connect_ms,
                "read_ms": read_ms,
            }

            return PortCheckResult(
                port=port,
                ok=True,
                is_open=is_open,
                is_tls=is_tls,
                connect_ms=connect_ms,
                read_ms=read_ms,
                error=error,
                banner=compact_banner,
                alpn=alpn,
                tls_version=tls_version,
                cipher=cipher,
                service=service,
                http_server=http_server,
                http_location=http_location,
                http_powered_by=http_powered_by,
                http_via=http_via,
                evidence=evidence,
            )

        results = await asyncio.gather(*[_check_one(p) for p in ports], return_exceptions=False)

        # Сначала open, затем closed; внутри — по порту
        results.sort(key=lambda r: (0 if r.is_open else 1, r.port))

        payload: list[dict[str, Any]] = []
        for r in results:
            evidence_json = json.dumps(r.evidence, ensure_ascii=False)
            evidence_json = _strip_nul(evidence_json) or ""
            payload.append(
                {
                    "checked_ts": checked_ts,
                    "port": r.port,
                    "is_open": int(r.is_open),
                    "service": _strip_nul(r.service) or "unknown",
                    "is_tls": int(r.is_tls),

                    "alpn": _strip_nul(r.alpn),
                    "tls_version": _strip_nul(r.tls_version),
                    "cipher": _strip_nul(r.cipher),

                    "connect_ms": r.connect_ms,
                    "read_ms": r.read_ms,

                    "banner": _strip_nul(r.banner) or "",
                    "error": _strip_nul(r.error),

                    "http_server": _strip_nul(r.http_server),
                    "http_location": _strip_nul(r.http_location),
                    "http_powered_by": _strip_nul(r.http_powered_by),
                    "http_via": _strip_nul(r.http_via),

                    "evidence_json": evidence_json,
                }
            )

        open_cnt = sum(1 for r in results if r.is_open)
        tls_cnt = sum(1 for r in results if r.is_open and r.is_tls)

        logger.info(
            "[ports_services] done domain=%s checked=%s open=%s tls=%s",
            domain,
            len(results),
            open_cnt,
            tls_cnt,
        )

        return ModuleResult(module_payload=payload)


    def persist(self, session: Session, domain: str, payload: list[dict]) -> None:
        if not payload:
            logger.debug("[ports_services] persist: no payload for %s", domain)
            return

        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            logger.info("[ports_services] persist: create domain=%s before save", domain)
            domain_record = create_domain(session, domain, source="audit")

        def _clean_item_str(v: Any) -> Any:
            if isinstance(v, str):
                return _strip_nul(v)
            return v

        for item in payload:
            item = {k: _clean_item_str(v) for k, v in item.items()}
            session.add(
                PortsServicesCheck(
                    domain_id=domain_record.id,
                    checked_ts=int(item.get("checked_ts", _now_ts())),
                    port=int(item.get("port", 0)),
                    is_open=int(item.get("is_open", 0)),
                    service=item.get("service") or "unknown",
                    is_tls=int(item.get("is_tls", 0)),

                    alpn=item.get("alpn"),
                    tls_version=item.get("tls_version"),
                    cipher=item.get("cipher"),

                    connect_ms=item.get("connect_ms"),
                    read_ms=item.get("read_ms"),

                    banner=item.get("banner") or "",
                    error=item.get("error"),

                    http_server=item.get("http_server"),
                    http_location=item.get("http_location"),
                    http_powered_by=item.get("http_powered_by"),
                    http_via=item.get("http_via"),

                    evidence_json=item.get("evidence_json"),
                )
            )

        session.commit()
        logger.info("[ports_services] persist: saved domain=%s count=%s", domain, len(payload))

    def build_report_block(self, session: Session, domain: str) -> dict:
        domain_record = session.query(Domain).filter(Domain.domain == domain).one_or_none()
        if domain_record is None:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Нет данных по домену",
                "kpis": {},
                "insights": [],
                "timeline": [],
                "open_ports": [],
                "entries_open": [],
                "entries_closed": [],
                "empty_message": "Данные о домене отсутствуют в базе.",
            }

        rows = (
            session.query(PortsServicesCheck)
            .filter(PortsServicesCheck.domain_id == domain_record.id)
            .order_by(PortsServicesCheck.checked_ts.desc(), PortsServicesCheck.port.asc())
            .limit(250)
            .all()
        )

        if not rows:
            return {
                "key": self.key,
                "name": self.name,
                "description": self.description,
                "headline": "Проверка портов ещё не выполнялась",
                "kpis": {},
                "insights": [],
                "timeline": [],
                "open_ports": [],
                "entries_open": [],
                "entries_closed": [],
                "empty_message": "Проверки портов ещё не выполнялись.",
            }

        latest_ts = rows[0].checked_ts
        latest = [r for r in rows if r.checked_ts == latest_ts]

        checked_ports = len(latest)
        open_ports = [r for r in latest if r.is_open == 1]
        open_cnt = len(open_ports)
        tls_ports = [r for r in open_ports if r.is_tls == 1]
        tls_cnt = len(tls_ports)

        def _rank(r: PortsServicesCheck) -> tuple[int, int]:
            prio = {"https": 0, "http": 1, "ssh": 2, "smtp": 3}.get((r.service or "").lower(), 10)
            return (prio, r.port)

        open_ports_sorted = sorted(open_ports, key=_rank)
        best = open_ports_sorted[0] if open_ports_sorted else None

        if open_cnt == 0:
            headline = "Открытые порты не обнаружены (в рамках заданного профиля/списка)"
        else:
            headline = f"Обнаружены открытые порты: {open_cnt} из {checked_ports}"

        kpis = {
            "checked_ports": checked_ports,
            "open_ports": open_cnt,
            "tls_ports": tls_cnt,
            "best_port": (best.port if best else None),
            "best_service": (best.service if best else None),
            "best_alpn": (best.alpn if best else None),
            "best_tls": (best.tls_version if best else None),
        }

        insights: list[str] = []
        if open_cnt == 0:
            insights.append("По проверенному набору портов признаков доступных сервисов не найдено.")
        else:
            if best:
                hints = []
                if best.is_tls == 1 and best.alpn:
                    hints.append(f"ALPN={best.alpn}")
                if best.is_tls == 1 and best.tls_version:
                    hints.append(f"TLS={best.tls_version}")
                if best.http_server:
                    hints.append(f"Server={best.http_server}")
                tail = f" ({', '.join(hints)})" if hints else ""
                insights.append(f"Ключевая находка: порт {best.port} · сервис {best.service}{tail}.")

            if tls_cnt > 0:
                insights.append("TLS-рукопожатие успешно выполнено на части портов — доступны negotiated параметры и ALPN.")
            if any((r.service or "").lower() == "unknown" for r in open_ports):
                insights.append("Некоторые сервисы не удалось уверенно определить по баннеру/пробам — проверьте вручную.")
            if any((r.error or "").startswith("connect_timeout") for r in latest):
                insights.append("Зафиксированы таймауты подключения — возможна фильтрация/замедление на части портов.")

        uniq_ts: list[int] = []
        for r in rows:
            if r.checked_ts not in uniq_ts:
                uniq_ts.append(r.checked_ts)
            if len(uniq_ts) >= 6:
                break

        timeline = []
        for ts in uniq_ts:
            group = [x for x in rows if x.checked_ts == ts]
            g_checked = len(group)
            g_open = sum(1 for x in group if x.is_open == 1)
            g_tls = sum(1 for x in group if x.is_open == 1 and x.is_tls == 1)
            title = f"проверено {g_checked} · open={g_open} · tls={g_tls}"
            timeline.append(
                {
                    "timestamp": _fmt_ts(ts),
                    "status": ("ok" if g_open == 0 else "warning"),
                    "title": title,
                    "meta": {},
                }
            )

        # v2: показываем только open (шум закрытых убран)
        open_ports_view: list[dict[str, Any]] = []
        for r in open_ports_sorted[:60]:
            open_ports_view.append(
                {
                    "port": r.port,
                    "service": r.service,
                    "tls": bool(r.is_tls),
                    "alpn": r.alpn,
                    "tls_version": r.tls_version,
                    "cipher": r.cipher,
                    "banner": (r.banner or ""),

                    "http_server": r.http_server,
                    "http_location": r.http_location,
                    "http_powered_by": r.http_powered_by,
                    "http_via": r.http_via,
                }
            )

        open_entries: list[dict[str, Any]] = []
        closed_entries: list[dict[str, Any]] = []

        for r in latest:
            st = "open" if r.is_open == 1 else "closed"
            msg = f"порт {r.port}: {st}"
            if r.service:
                msg += f" · {r.service}"
            if r.is_tls == 1 and r.tls_version:
                msg += f" · {r.tls_version}"

            item = {
                "timestamp": _fmt_ts(r.checked_ts),
                "status": st,
                "message": msg,
                "details": {
                    "port": r.port,
                    "service": r.service,
                    "tls": bool(r.is_tls),
                    "alpn": r.alpn,
                    "banner": r.banner,
                    "error": r.error,

                    "http_server": r.http_server,
                    "http_location": r.http_location,
                    "http_powered_by": r.http_powered_by,
                    "http_via": r.http_via,
                },
            }

            (open_entries if r.is_open == 1 else closed_entries).append(item)

        open_entries = open_entries[:25]
        closed_entries = closed_entries[:25]

        return {
            "key": self.key,
            "template": "audit_modules/ports_services/ports_services.html",
            "name": self.name,
            "description": self.description,
            "headline": headline,
            "kpis": kpis,
            "insights": insights,
            "timeline": timeline,
            "open_ports": open_ports_view,
            "entries_open": open_entries,
            "entries_closed": closed_entries,
            "empty_message": "Проверки портов ещё не выполнялись.",
        }


# -----------------------------
# DB model
# -----------------------------

class PortsServicesCheck(Base):
    """
    История проверок портов/сервисов.

    banner — короткий (для UI),
    evidence_json — подробные “доказательства” (пробы/тайминги/TLS meta).
    """

    __tablename__ = "ports_services_checks"

    id = Column(Integer, primary_key=True)

    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    checked_ts = Column(Integer, nullable=False)

    port = Column(Integer, nullable=False)
    is_open = Column(Integer, nullable=False)  # 0/1

    service = Column(String(64), nullable=False)  # ssh/http/https/smtp/unknown/...
    is_tls = Column(Integer, nullable=False)  # 0/1

    alpn = Column(String(32), nullable=True)
    tls_version = Column(String(32), nullable=True)
    cipher = Column(String(128), nullable=True)

    connect_ms = Column(Integer, nullable=True)
    read_ms = Column(Integer, nullable=True)

    banner = Column(Text, nullable=True)
    error = Column(String(128), nullable=True)

    # HTTP headers (коротко; если это реально HTTP(S))
    http_server = Column(String(256), nullable=True)
    http_location = Column(String(512), nullable=True)
    http_powered_by = Column(String(256), nullable=True)
    http_via = Column(String(256), nullable=True)

    evidence_json = Column(Text, nullable=True)
