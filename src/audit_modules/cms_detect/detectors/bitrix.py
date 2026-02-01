from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify
from .utils import hget

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


class BitrixDetector(CmsDetector):
    cms_key = "bitrix"
    cms_name = "1C-Bitrix"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        if set_cookie_raw and BITRIX_COOKIE_HINT.search(set_cookie_raw):
            score += 50
            signals.append({"type": "cookie", "value": "BITRIX_SM_* in Set-Cookie"})

        x_powered = hget(headers, "X-Powered-By")
        if x_powered and "bitrix" in x_powered.lower():
            score += 30
            signals.append({"type": "header", "value": f"X-Powered-By: {x_powered}"})

        for pat in BITRIX_HTML_PATTERNS:
            if pat.search(html):
                score += 15
                signals.append({"type": "html", "value": pat.pattern})

        for h in BITRIX_PATH_HINTS:
            if h in html:
                score += 5
                signals.append({"type": "path", "value": h})

        final = min(score, 100)
        return DetectorResult(
            cms_key=self.cms_key,
            cms_name=self.cms_name,
            score=final,
            status=classify(final),
            evidence=DetectorEvidence(signals=signals, used_url=used_url),
        )
