from __future__ import annotations

import re

from .base import CmsDetector, DetectorEvidence, DetectorResult, classify

DRUPAL_HTML = [
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+drupal", re.I),
    re.compile(r"drupalSettings", re.I),
    re.compile(r"/sites/(default|all)/", re.I),
    re.compile(r"/core/(misc|modules|themes)/", re.I),
]


class DrupalDetector(CmsDetector):
    cms_key = "drupal"
    cms_name = "Drupal"

    def detect(self, *, headers: dict[str, str], set_cookie_raw: str, html: str, used_url: str | None) -> DetectorResult:
        score = 0
        signals: list[dict[str, str]] = []

        for pat in DRUPAL_HTML:
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
