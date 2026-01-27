from pathlib import Path

from src.db import Database
from src.importer_file import DomainFileImporter


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
    db_path = tmp_path / "test.sqlite"
    stats = DomainFileImporter(str(db_path)).run(str(file_path), source="file")

    # Проверяем статистику импорта.
    assert stats.total_lines == 6
    assert stats.normalized_domains == 4
    assert stats.unique_domains == 2
    assert stats.inserted_domains == 2
    assert stats.skipped_duplicates == 2

    # Проверяем, что в БД действительно 2 домена.
    db = Database(str(db_path))
    domains = db.load_domains()
    db.close()
    assert sorted(domains) == ["example.com", "sub.example.com"]
