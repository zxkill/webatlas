from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """
    Настраивает единый формат логирования для всего приложения.

    Мы пишем логи в stdout, чтобы Docker и оркестраторы легко собирали их.
    """

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        stream=sys.stdout,
    )
