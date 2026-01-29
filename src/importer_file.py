from __future__ import annotations

import logging
from dataclasses import dataclass

from .db import Database
from .domain_import import import_domains_via_copy

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

    def run(self, path: str, source: str = "file", batch_size: int = 5000) -> FileImportStats:  # noqa: ARG002
        logger.info("Импорт доменов из файла (ускоренный режим): %s", path)

        # Открываем БД через общий класс-обёртку, чтобы повторно использовать настройки.
        db = Database(self._db_url)
        # Берём сырой DB-API коннект, так как COPY работает быстрее всех ORM/SQLAlchemy подходов.
        raw_connection = db._state.engine.raw_connection()
        try:
            copy_stats = import_domains_via_copy(raw_connection, path, source, log=logger)
        finally:
            # Всегда закрываем соединение и освобождаем ресурсы.
            raw_connection.close()
            db.close()

        stats = FileImportStats(
            total_lines=copy_stats.total_lines,
            normalized_domains=copy_stats.normalized_domains,
            unique_domains=copy_stats.unique_domains,
            inserted_domains=copy_stats.inserted_domains,
            skipped_duplicates=copy_stats.skipped_duplicates,
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
