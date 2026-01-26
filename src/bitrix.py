from __future__ import annotations

import json
import re
from dataclasses import dataclass
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


@dataclass(frozen=True)
class BitrixVerdict:
    status: str   # yes/maybe/no
    score: int
    evidence: dict


def decode_html(body: bytes, charset: Optional[str]) -> str:
    enc = charset or "utf-8"
    try:
        return body.decode(enc, errors="replace")
    except Exception:
        return body.decode("utf-8", errors="replace")


def score_bitrix(headers: dict[str, str], set_cookie_raw: str, html: str) -> tuple[int, dict]:
    score = 0
    ev = {"signals": []}

    if set_cookie_raw and BITRIX_COOKIE_HINT.search(set_cookie_raw):
        score += 50
        ev["signals"].append({"type": "cookie", "value": "BITRIX_SM_* in Set-Cookie"})

    x_powered = headers.get("X-Powered-By", "")
    if x_powered and "bitrix" in x_powered.lower():
        score += 30
        ev["signals"].append({"type": "header", "value": f"X-Powered-By: {x_powered}"})

    for pat in BITRIX_HTML_PATTERNS:
        if pat.search(html):
            score += 15
            ev["signals"].append({"type": "html", "value": pat.pattern})

    for h in BITRIX_PATH_HINTS:
        if h in html:
            score += 5
            ev["signals"].append({"type": "path", "value": h})

    return min(score, 100), ev


def classify(score: int) -> str:
    if score >= 70:
        return "yes"
    if score >= 35:
        return "maybe"
    return "no"
