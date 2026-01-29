from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from src.domain_utils import normalize_domain

logger = logging.getLogger(__name__)


class SupportsCursor(Protocol):
    """
    Протокол для DB-API соединения, чтобы типизировать доступ к cursor().
    """

    def cursor(self):  # noqa: ANN001 - DB-API курсоры имеют гибкий интерфейс
        """Возвращает курсор для выполнения SQL и COPY."""


@dataclass(frozen=True)
class CopyImportStats:
    """
    Статистика импорта доменов через staging + COPY.
    """

    total_lines: int
    normalized_domains: int
    unique_domains: int
    inserted_domains: int
    skipped_duplicates: int


def import_domains_via_copy(
    raw_connection: SupportsCursor,
    path: str,
    source: str,
    *,
    log: logging.Logger | None = None,
) -> CopyImportStats:
    """
    Быстрый импорт доменов через staging-таблицу и COPY.

    Алгоритм:
    1) Нормализуем домены построчно в временный файл (без хранения всего списка в памяти).
    2) TRUNCATE staging-таблицы.
    3) COPY в staging.
    4) INSERT ... SELECT ... ON CONFLICT DO NOTHING.
    """

    log = log or logger
    log.info("Старт быстрого импорта доменов через COPY: %s", path)

    temp_path, total_lines, normalized_domains = _prepare_normalized_file(path, log=log)
    log.info(
        "Нормализация завершена: lines=%s normalized=%s temp=%s",
        total_lines,
        normalized_domains,
        temp_path,
    )

    try:
        unique_domains = 0
        inserted_domains = 0

        with raw_connection.cursor() as cursor:
            # Шаг 1. Очищаем staging-таблицу перед каждой загрузкой.
            cursor.execute("TRUNCATE domains_staging;")
            log.debug("staging таблица очищена")

            # Шаг 2. Быстро заливаем подготовленные домены через COPY.
            if normalized_domains > 0:
                with open(temp_path, "r", encoding="utf-8") as handle:
                    cursor.copy_from(handle, "domains_staging", columns=("domain",))
                log.info("COPY завершён, домены загружены в staging")
            else:
                log.warning("Нет доменов для COPY после нормализации")

            # Шаг 3. Считаем статистику по staging.
            cursor.execute("SELECT count(*) FROM domains_staging;")
            normalized_in_db = int(cursor.fetchone()[0])
            cursor.execute("SELECT count(DISTINCT domain) FROM domains_staging;")
            unique_domains = int(cursor.fetchone()[0])
            log.debug(
                "Статистика staging: rows=%s unique=%s",
                normalized_in_db,
                unique_domains,
            )

            # Шаг 4. Вставляем только новые домены.
            cursor.execute(
                """
                WITH inserted AS (
                    INSERT INTO domains (domain, source)
                    SELECT domain, %s FROM domains_staging
                    ON CONFLICT (domain) DO NOTHING
                    RETURNING 1
                )
                SELECT count(*) FROM inserted;
                """,
                (source,),
            )
            inserted_domains = int(cursor.fetchone()[0])
            log.info("INSERT завершён: inserted=%s", inserted_domains)

        raw_connection.commit()
    except Exception:  # noqa: BLE001 - подробный лог с роллбеком важен для мониторинга
        raw_connection.rollback()
        log.exception("Ошибка импорта доменов через COPY")
        raise
    finally:
        _safe_remove_temp_file(temp_path, log=log)

    skipped_duplicates = max(normalized_domains - inserted_domains, 0)
    return CopyImportStats(
        total_lines=total_lines,
        normalized_domains=normalized_domains,
        unique_domains=unique_domains,
        inserted_domains=inserted_domains,
        skipped_duplicates=skipped_duplicates,
    )


def _prepare_normalized_file(path: str, *, log: logging.Logger) -> tuple[Path, int, int]:
    """
    Построчно нормализуем домены и пишем их в временный файл, чтобы не держать
    миллионы строк в памяти.
    """

    input_path = Path(path)
    if not input_path.exists():
        log.error("Файл со списком доменов не найден: %s", path)
        raise FileNotFoundError(path)

    total_lines = 0
    normalized_domains = 0

    fd, temp_name = tempfile.mkstemp(prefix="webatlas_domains_", suffix=".txt")
    os.close(fd)
    temp_path = Path(temp_name)

    with open(input_path, "r", encoding="utf-8") as src, open(temp_path, "w", encoding="utf-8") as dst:
        for line_number, line in enumerate(src, start=1):
            total_lines += 1
            normalized = normalize_domain(line)
            if normalized is None:
                log.debug("Строка %s пропущена при нормализации", line_number)
                continue
            dst.write(f"{normalized}\n")
            normalized_domains += 1

    return temp_path, total_lines, normalized_domains


def _safe_remove_temp_file(path: Path, *, log: logging.Logger) -> None:
    """
    Аккуратно удаляем временный файл, чтобы не оставлять мусор на диске.
    """

    try:
        path.unlink(missing_ok=True)
        log.debug("Временный файл удалён: %s", path)
    except OSError:
        log.exception("Не удалось удалить временный файл: %s", path)
