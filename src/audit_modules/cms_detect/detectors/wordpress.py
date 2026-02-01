from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify
from .utils import hget

WP_HTML = [
    re.compile(r"/wp-content/", re.I),
    re.compile(r"/wp-includes/", re.I),
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+wordpress", re.I),
    re.compile(r"wp-emoji-release\.min\.js", re.I),
]
WP_HEADERS = [
    ("X-Powered-By", re.compile(r"wordpress", re.I)),
]
WP_COOKIES = re.compile(r"\bwordpress_(logged_in|sec)_", re.I)


class WordPressDetector(CmsDetector):
    cms_key = "wordpress"
    cms_name = "WordPress"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        if set_cookie_raw and WP_COOKIES.search(set_cookie_raw):
            score += 40
            signals.append({"type": "cookie", "value": "wordpress_* cookie in Set-Cookie"})

        for hk, rx in WP_HEADERS:
            hv = hget(headers, hk)
            if hv and rx.search(hv):
                score += 20
                signals.append({"type": "header", "value": f"{hk}: {hv}"})

        for pat in WP_HTML:
            if pat.search(html):
                score += 20
                signals.append({"type": "html", "value": pat.pattern})

        final = min(score, 100)
        return DetectorResult(
            cms_key=self.cms_key,
            cms_name=self.cms_name,
            score=final,
            status=classify(final),
            evidence=DetectorEvidence(signals=signals, used_url=used_url),
        )
