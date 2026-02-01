from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def decode_html(body: bytes, charset: Optional[str]) -> str:
    """
    Декодирование HTML с учётом charset из availability.
    """
    enc = charset or "utf-8"
    try:
        decoded = body.decode(enc, errors="replace")
        logger.debug("[cms_detect] HTML decoded with charset=%s", enc)
        return decoded
    except Exception as exc:
        logger.warning("[cms_detect] HTML decode failed charset=%s: %s; fallback to utf-8", enc, exc)
        return body.decode("utf-8", errors="replace")


def hget(headers: dict[str, str], key: str) -> str:
    """
    Заголовки у разных серверов могут отличаться регистром.
    Приводим к "best effort".
    """
    if key in headers:
        return headers.get(key, "")
    low = key.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return ""
