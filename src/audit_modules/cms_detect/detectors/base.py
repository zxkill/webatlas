from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DetectorEvidence:
    """
    Детальное объяснение результата детектора.
    UI покажет это как "почему мы так решили".
    """
    signals: list[dict[str, Any]]  # [{"type": "html|header|cookie|path|meta", "value": "..."}]
    used_url: str | None = None


@dataclass(frozen=True)
class DetectorResult:
    """
    Результат детектора одной CMS/фреймворка.
    score: 0..100
    status:
      - "yes"    >= 70
      - "maybe"  >= 35
      - "no"     < 35
    """
    cms_key: str
    cms_name: str
    score: int
    status: str
    evidence: DetectorEvidence


class CmsDetector(abc.ABC):
    """
    Базовый класс детектора.
    Важно: детектор не делает сетевых запросов — работает по фактам из availability.
    """

    cms_key: str
    cms_name: str

    @abc.abstractmethod
    def detect(
        self,
        *,
        headers: dict[str, str],
        set_cookie_raw: str,
        html: str,
        used_url: str | None,
    ) -> DetectorResult:
        raise NotImplementedError


def classify(score: int) -> str:
    if score >= 70:
        return "yes"
    if score >= 35:
        return "maybe"
    return "no"
