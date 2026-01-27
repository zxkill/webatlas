from __future__ import annotations

import logging
from dataclasses import dataclass

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


class DomainFileImporter:
    """
    Импорт доменов из текстового файла.
    Каждая строка файла должна содержать один домен (или URL).
    """

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url

    def run(self, path: str, source: str = "file") -> FileImportStats:
        """
        Загружает домены из файла, нормализует и сохраняет в БД.
        Возвращает подробную статистику импорта.
        """

        logger.info("Импорт доменов из файла: %s", path)
        domains = load_domains_from_file(path)
        # Сохраняем уникальные домены, чтобы избежать повторных вставок.
        unique_domains = sorted(set(domains))
        logger.info("Найдено доменов: всего=%s, уникальных=%s", len(domains), len(unique_domains))

        db = Database(self._db_url)
        inserted = 0
        for domain in unique_domains:
            # Добавляем домен с привязкой источника импорта.
            db.upsert_domain(domain, source=source)
            inserted += 1
        db.commit()
        db.close()

        stats = FileImportStats(
            total_lines=_count_lines(path),
            normalized_domains=len(domains),
            unique_domains=len(unique_domains),
            inserted_domains=inserted,
            skipped_duplicates=len(domains) - len(unique_domains),
        )
        logger.info(
            "Импорт завершён: lines=%s, normalized=%s, unique=%s, inserted=%s, duplicates=%s",
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
