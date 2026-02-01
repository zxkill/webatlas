from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify

JOOMLA_HTML = [
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+joomla", re.I),
    re.compile(r"/media/system/js/", re.I),
    re.compile(r"/components/com_", re.I),
    re.compile(r"/administrator/", re.I),
]


class JoomlaDetector(CmsDetector):
    cms_key = "joomla"
    cms_name = "Joomla!"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        for pat in JOOMLA_HTML:
            if pat.search(html):
                score += 25
                signals.append({"type": "html", "value": pat.pattern})

        final = min(score, 100)
        return DetectorResult(
            cms_key=self.cms_key,
            cms_name=self.cms_name,
            score=final,
            status=classify(final),
            evidence=DetectorEvidence(signals=signals, used_url=used_url),
        )
