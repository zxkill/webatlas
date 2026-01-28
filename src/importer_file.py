from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Generator

from .db import Database
from .domain_utils import load_domains_from_file

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FileImportStats:
    total_lines: int
    normalized_domains: int
    unique_domains: int
    inserted_domains: int
    skipped_duplicates: int

def _chunks(items: list[str], size: int) -> Generator[list[str], Any, None]:
    for i in range(0, len(items), size):
        yield items[i:i+size]

class DomainFileImporter:
    """
    Импорт доменов из текстового файла.
    Каждая строка файла должна содержать один домен (или URL).
    """

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def run(self, path: str, source: str = "file", batch_size: int = 5000) -> FileImportStats:
        logger.info("Импорт доменов из файла: %s", path)
        domains = load_domains_from_file(path)
        unique_domains = sorted(set(domains))
        logger.info("Найдено доменов: всего=%s, уникальных=%s", len(domains), len(unique_domains))

        db = Database(self._db_url)

        inserted = 0
        already_in_db = 0

        for batch in _chunks(unique_domains, batch_size):
            existing = db.fetch_existing_domains(batch)  # пачкой
            to_insert = [d for d in batch if d not in existing]

            already_in_db += (len(batch) - len(to_insert))
            inserted += db.insert_domains(to_insert, source=source)  # пачкой

        db.commit()
        db.close()

        stats = FileImportStats(
            total_lines=_count_lines(path),
            normalized_domains=len(domains),
            unique_domains=len(unique_domains),
            inserted_domains=inserted,
            skipped_duplicates=(len(domains) - len(unique_domains)) + already_in_db,
        )
        logger.info(
            "Импорт завершён: lines=%s, normalized=%s, unique=%s, inserted=%s, skipped=%s",
            stats.total_lines,
            stats.normalized_domains,
            stats.unique_domains,
            stats.inserted_domains,
            stats.skipped_duplicates,
        )
        return stats


def _count_lines(path: str) -> int:
    """
    Вспомогательная функция: количество строк в файле, чтобы вести статистику.
    """

    with open(path, "r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)
