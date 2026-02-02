from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    return host.strip().lower()


def _strip_www(host: str | None) -> str | None:
    host = _normalize_host(host)
    if not host:
        return None
    return host[4:] if host.startswith("www.") else host


def _trailing_slash(path: str | None) -> str | None:
    if path is None:
        return None
    if path == "":
        return ""
    return "with_slash" if path.endswith("/") else "no_slash"


@dataclass(frozen=True)
class CanonicalProfile:
    canonical_url: str | None
    canonical_scheme: str | None
    canonical_host: str | None
    www_mode: str | None          # "www" | "non_www" | None
    trailing_slash_mode: str | None  # "with_slash" | "no_slash" | None
    hsts_present: bool | None
    hsts_max_age: int | None
    hsts_includesubdomains: bool | None
    hsts_preload: bool | None


def parse_hsts(headers: dict[str, str]) -> tuple[bool, int | None, bool | None, bool | None]:
    """
    Парсим Strict-Transport-Security.
    Возвращаем: present, max_age, includeSubDomains, preload
    """
    raw = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
    if not raw:
        return False, None, None, None

    max_age = None
    include_sd = False
    preload = False

    parts = [p.strip() for p in raw.split(";") if p.strip()]
    for p in parts:
        pl = p.lower()
        if pl.startswith("max-age="):
            try:
                max_age = int(pl.split("=", 1)[1])
            except Exception:
                max_age = None
        elif pl == "includesubdomains":
            include_sd = True
        elif pl == "preload":
            preload = True

    return True, max_age, include_sd, preload


def build_canonical_profile(
    http_root: dict | None,
    https_root: dict | None,
) -> CanonicalProfile:
    """
    На вход получаем результаты запросов '/' для http и https в виде dict:
    {
      "request_url": "...",
      "final_url": "...",
      "redirects": [{"url":..., "status":..., "location":...}, ...],
      "status": 200,
      "headers": {...}
    }
    """

    # Выбор канонического: приоритет https (если есть финальный ответ), иначе http.
    chosen = https_root if (https_root and https_root.get("final_url")) else http_root

    canonical_url = chosen.get("final_url") if chosen else None
    canonical_scheme = None
    canonical_host = None
    trailing_mode = None
    www_mode = None

    hsts_present = None
    hsts_max_age = None
    hsts_includesubdomains = None
    hsts_preload = None

    if canonical_url:
        p = urlparse(canonical_url)
        canonical_scheme = p.scheme or None
        canonical_host = _normalize_host(p.netloc) or None
        trailing_mode = _trailing_slash(p.path)

        if canonical_host:
            www_mode = "www" if canonical_host.startswith("www.") else "non_www"

    # HSTS имеет смысл только для https-ветки
    if https_root and isinstance(https_root.get("headers"), dict):
        present, max_age, inc_sd, preload = parse_hsts(https_root["headers"])
        hsts_present = present
        hsts_max_age = max_age
        hsts_includesubdomains = inc_sd
        hsts_preload = preload

    return CanonicalProfile(
        canonical_url=canonical_url,
        canonical_scheme=canonical_scheme,
        canonical_host=canonical_host,
        www_mode=www_mode,
        trailing_slash_mode=trailing_mode,
        hsts_present=hsts_present,
        hsts_max_age=hsts_max_age,
        hsts_includesubdomains=hsts_includesubdomains,
        hsts_preload=hsts_preload,
    )


def compare_www_non_www(host_a: str | None, host_b: str | None) -> str | None:
    """
    Эвристика: если домен совпадает после удаления www., значит отличие — www/non-www.
    """
    a = _strip_www(host_a)
    b = _strip_www(host_b)
    if not a or not b:
        return None
    return "www_non_www" if a == b and _normalize_host(host_a) != _normalize_host(host_b) else None
