from .base import CmsDetector, DetectorResult

from .bitrix import BitrixDetector
from .wordpress import WordPressDetector
from .joomla import JoomlaDetector
from .drupal import DrupalDetector
from .opencart import OpenCartDetector
from .laravel import LaravelDetector


def default_detectors() -> list[CmsDetector]:
    """
    Список детекторов “из коробки”.
    Расширение делается добавлением новых файлов-детекторов и включением здесь.
    """
    return [
        BitrixDetector(),
        WordPressDetector(),
        JoomlaDetector(),
        DrupalDetector(),
        OpenCartDetector(),
        LaravelDetector(),
    ]


__all__ = [
    "CmsDetector",
    "DetectorResult",
    "default_detectors",
]
