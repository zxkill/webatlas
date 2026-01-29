from __future__ import annotations

from pathlib import Path

from src.domain_import import CopyImportStats, import_domains_via_copy


class _FakeCursor:
    """Минимальный фейковый курсор для проверки COPY-импорта без реальной БД."""

    def __init__(self, connection: "_FakeConnection") -> None:
        self._connection = connection
        self.executed: list[tuple[str, tuple | None]] = []
        self.copied_payload: str | None = None

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        return None

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self.executed.append((sql, params))

    def copy_from(self, file_handle, table: str, columns: tuple[str, ...]) -> None:  # noqa: ANN001
        self._connection.copy_called = True
        self.copied_payload = file_handle.read()
        self._connection.copy_table = table
        self._connection.copy_columns = columns

    def fetchone(self) -> tuple[int]:
        return (self._connection.fetch_queue.pop(0),)


class _FakeConnection:
    """Простой фейковый DB-API коннект для проверки логики без PostgreSQL."""

    def __init__(self, fetch_queue: list[int]) -> None:
        self.fetch_queue = fetch_queue
        self.commit_called = False
        self.rollback_called = False
        self.copy_called = False
        self.copy_table: str | None = None
        self.copy_columns: tuple[str, ...] | None = None

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True


def test_import_domains_via_copy_normalizes_and_returns_stats(tmp_path: Path) -> None:
    # Готовим файл с доменами и мусорными строками.
    file_path = tmp_path / "domains.txt"
    file_path.write_text("example.com\n#comment\nhttps://sub.example.com/any\n", encoding="utf-8")

    # Настраиваем фейковое соединение: rows=2, unique=2, inserted=2.
    fake_connection = _FakeConnection(fetch_queue=[2, 2, 2])

    stats = import_domains_via_copy(fake_connection, str(file_path), source="file")

    assert isinstance(stats, CopyImportStats)
    assert stats.total_lines == 3
    assert stats.normalized_domains == 2
    assert stats.unique_domains == 2
    assert stats.inserted_domains == 2
    assert stats.skipped_duplicates == 0
    assert fake_connection.commit_called is True
    assert fake_connection.rollback_called is False
    assert fake_connection.copy_called is True
    assert fake_connection.copy_table == "domains_staging"
    assert fake_connection.copy_columns == ("domain",)
