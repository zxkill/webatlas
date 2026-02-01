from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify
from .utils import hget

LARAVEL_HEADERS = [
    ("Set-Cookie", re.compile(r"\blaravel_session=", re.I)),
    ("X-Powered-By", re.compile(r"laravel", re.I)),
]
LARAVEL_HTML = [
    re.compile(r"csrf-token", re.I),
]


class LaravelDetector(CmsDetector):
    cms_key = "laravel"
    cms_name = "Laravel"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        # cookie (через raw set_cookie)
        if set_cookie_raw and re.search(r"\blaravel_session=", set_cookie_raw, re.I):
            score += 45
            signals.append({"type": "cookie", "value": "laravel_session in Set-Cookie"})

        for hk, rx in LARAVEL_HEADERS:
            hv = hget(headers, hk)
            if hv and rx.search(hv):
                score += 20
                signals.append({"type": "header", "value": f"{hk}: {hv}"})

        for pat in LARAVEL_HTML:
            if pat.search(html):
                score += 10
                signals.append({"type": "html", "value": pat.pattern})

        final = min(score, 100)
        return DetectorResult(
            cms_key=self.cms_key,
            cms_name=self.cms_name,
            score=final,
            status=classify(final),
            evidence=DetectorEvidence(signals=signals, used_url=used_url),
        )
