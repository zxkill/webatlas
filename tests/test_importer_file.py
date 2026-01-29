from pathlib import Path
import os

import pytest

# Пропускаем тест, если SQLAlchemy не установлен.
pytest.importorskip("sqlalchemy")

from src.db import Database
from src.importer_file import DomainFileImporter
from src.webapp_db import AdminPanel, Check, Cms, Domain, DomainCheck, DomainCms, domains_staging_table


# Проверяем импорт доменов из файла на PostgreSQL. Пропускаем без DSN.

def _get_test_dsn() -> str:
    dsn = os.getenv("POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("POSTGRES_TEST_DSN не задан, пропускаем интеграционный тест")
    return dsn


def _cleanup(db: Database) -> None:
    # Очищаем таблицы доменов для изоляции тестов.
    session = db._session
    session.execute(domains_staging_table.delete())
    session.query(DomainCheck).delete()
    session.query(DomainCms).delete()
    session.query(AdminPanel).delete()
    session.query(Check).delete()
    session.query(Cms).delete()
    session.query(Domain).delete()
    session.commit()


def test_importer_file_deduplicates_domains(tmp_path: Path) -> None:
    # Готовим тестовый файл с доменами, включая дубликаты и комментарии.
    file_path = tmp_path / "domains.txt"
    file_path.write_text(
        "\n".join(
            [
                "example.com",
                "https://example.com/any-path",
                "sub.example.com",
                "#comment",
                "invalid domain",
                "sub.example.com",
            ]
        ),
        encoding="utf-8",
    )

    # Импортируем домены в тестовую базу.
    dsn = _get_test_dsn()
    db = Database(dsn)
    _cleanup(db)
    stats = DomainFileImporter(dsn).run(str(file_path), source="file")

    # Проверяем статистику импорта.
    assert stats.total_lines == 6
    assert stats.normalized_domains == 4
    assert stats.unique_domains == 2
    assert stats.inserted_domains == 2
    assert stats.skipped_duplicates == 2

    # Проверяем, что в БД действительно 2 домена.
    domains = db.load_domains()
    db.close()
    assert sorted(domains) == ["example.com", "sub.example.com"]
