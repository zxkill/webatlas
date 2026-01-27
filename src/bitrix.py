from __future__ import annotations

import json
import re
import logging
from typing import Optional


BITRIX_PATH_HINTS = [
    "/bitrix/",
    "/bitrix/js/",
    "/bitrix/admin/",
    "/upload/iblock/",
]

BITRIX_HTML_PATTERNS = [
    re.compile(r"\bBX\.message\b", re.I),
    re.compile(r"\bBX\.", re.I),
    re.compile(r"/bitrix/(js|admin|components|templates)/", re.I),
    re.compile(r"/upload/iblock/", re.I),
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+bitrix", re.I),
]

BITRIX_COOKIE_HINT = re.compile(r"\bBITRIX_SM_", re.I)

logger = logging.getLogger(__name__)


def decode_html(body: bytes, charset: Optional[str]) -> str:
    # Пытаемся декодировать HTML с учётом кодировки, если она была указана сервером.
    enc = charset or "utf-8"
    try:
        decoded = body.decode(enc, errors="replace")
        logger.debug("HTML успешно декодирован с кодировкой: %s", enc)
        return decoded
    except Exception as exc:
        # Фолбэк на UTF-8, если указанная кодировка не подходит.
        logger.warning("Не удалось декодировать HTML с кодировкой %s: %s", enc, exc)
        return body.decode("utf-8", errors="replace")


def score_bitrix(headers: dict[str, str], set_cookie_raw: str, html: str) -> tuple[int, dict]:
    # Рассчитываем балл на основе нескольких источников: cookies, headers, HTML и статических путей.
    score = 0
    ev: dict[str, list[dict[str, str]]] = {"signals": []}

    if set_cookie_raw and BITRIX_COOKIE_HINT.search(set_cookie_raw):
        score += 50
        ev["signals"].append({"type": "cookie", "value": "BITRIX_SM_* in Set-Cookie"})
        logger.debug("Найдена cookie-сигнатура Bitrix.")

    x_powered = headers.get("X-Powered-By", "")
    if x_powered and "bitrix" in x_powered.lower():
        score += 30
        ev["signals"].append({"type": "header", "value": f"X-Powered-By: {x_powered}"})
        logger.debug("Найдена header-сигнатура Bitrix: %s", x_powered)

    for pat in BITRIX_HTML_PATTERNS:
        if pat.search(html):
            score += 15
            ev["signals"].append({"type": "html", "value": pat.pattern})
            logger.debug("HTML-сигнатура Bitrix: %s", pat.pattern)

    for h in BITRIX_PATH_HINTS:
        if h in html:
            score += 5
            ev["signals"].append({"type": "path", "value": h})
            logger.debug("Найден путь Bitrix в HTML: %s", h)

    final_score = min(score, 100)
    logger.debug("Итоговый score Bitrix=%s (raw=%s)", final_score, score)
    return final_score, ev


def classify(score: int) -> str:
    # Классифицируем домен по баллу уверенности.
    if score >= 70:
        return "yes"
    if score >= 35:
        return "maybe"
    return "no"
