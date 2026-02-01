from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify

OC_HTML = [
    re.compile(r"index\.php\?route=", re.I),
    re.compile(r"catalog/view/(theme|javascript)/", re.I),
    re.compile(r"/image/catalog/", re.I),
]


class OpenCartDetector(CmsDetector):
    cms_key = "opencart"
    cms_name = "OpenCart"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        for pat in OC_HTML:
            if pat.search(html):
                score += 30
                signals.append({"type": "html", "value": pat.pattern})

        final = min(score, 100)
        return DetectorResult(
            cms_key=self.cms_key,
            cms_name=self.cms_name,
            score=final,
            status=classify(final),
            evidence=DetectorEvidence(signals=signals, used_url=used_url),
        )
