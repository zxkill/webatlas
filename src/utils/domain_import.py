from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from src.utils.domains import normalize_domain

logger = logging.getLogger(__name__)


class SupportsCursor(Protocol):
    """
    Протокол для DB-API соединения, чтобы типизировать доступ к cursor().
    """

    def cursor(self):  # noqa: ANN001
        """Возвращает курсор DB-API."""


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
      1) Нормализуем домены построчно во временный файл (O(1) по памяти).
      2) TRUNCATE staging.
      3) COPY в staging.
      4) (метрики) считаем total rows и unique domains в staging.
      5) INSERT ... ON CONFLICT DO NOTHING.
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

    unique_domains = 0
    inserted_domains = 0

    try:
        with raw_connection.cursor() as cursor:
            cursor.execute("SET LOCAL synchronous_commit TO off;")

            cursor.execute("TRUNCATE domains_staging;")
            log.debug("staging таблица очищена")

            if normalized_domains > 0:
                with open(temp_path, "r", encoding="utf-8") as handle:
                    cursor.copy_from(handle, "domains_staging", columns=("domain",))
                log.info("COPY завершён, домены загружены в staging")

                try:
                    cursor.execute(
                        """
                        SELECT COUNT(*)::bigint AS rows_total, COUNT(DISTINCT domain) ::bigint AS unique_total
                        FROM domains_staging;
                        """
                    )
                    row = cursor.fetchone()
                    if row:
                        rows_total = int(row[0] or 0)
                        unique_domains = int(row[1] or 0)

                        # Это диагностически полезно: можно сравнивать с normalized_domains.
                        log.info(
                            "Staging статистика: rows=%s unique_domains=%s (normalized=%s, source=%s)",
                            rows_total,
                            unique_domains,
                            normalized_domains,
                            source,
                        )
                except Exception:  # noqa: BLE001
                    # Метрики не должны ломать импорт — фиксируем и продолжаем.
                    unique_domains = 0
                    log.exception("Не удалось посчитать unique_domains в staging (source=%s)", source)

            else:
                log.warning("Нет доменов для COPY после нормализации")

            cursor.execute(
                """
                INSERT INTO domains (domain, source)
                SELECT domain, %s
                FROM domains_staging
                ON CONFLICT (domain) DO NOTHING;
                """,
                (source,),
            )

            inserted_domains = int(getattr(cursor, "rowcount", 0) or 0)
            log.info("INSERT завершён: inserted=%s", inserted_domains)

        raw_connection.commit()

    except Exception:  # noqa: BLE001
        raw_connection.rollback()
        log.exception("Ошибка импорта доменов через COPY")
        raise

    finally:
        _safe_remove_temp_file(temp_path, log=log)

    # Если unique_domains не смогли посчитать (0), используем normalized_domains как безопасную подстановку,
    # чтобы статистика в UI не выглядела «пустой».
    if unique_domains <= 0 and normalized_domains > 0:
        log.warning(
            "unique_domains не определён (0). Используем normalized_domains=%s как fallback (source=%s)",
            normalized_domains,
            source,
        )
        unique_domains = normalized_domains

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
    Построчно нормализуем домены и пишем во временный файл.

    Память:
      - O(1) по входному файлу
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

    with input_path.open("r", encoding="utf-8") as src, temp_path.open("w", encoding="utf-8") as dst:
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
    try:
        path.unlink(missing_ok=True)
        log.debug("Временный файл удалён: %s", path)
    except OSError:
        log.exception("Не удалось удалить временный файл: %s", path)
