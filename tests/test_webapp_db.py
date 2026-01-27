import pytest

# Пропускаем тест, если SQLAlchemy не установлен (например, в офлайн окружении).
pytest.importorskip("sqlalchemy")

from src.webapp_db import create_db_state, create_domain, init_db, list_domains


# Тестируем базовый CRUD для доменов на SQLite, чтобы не зависеть от PostgreSQL.

def test_webapp_db_create_and_list(tmp_path):
    db_path = tmp_path / "webapp.sqlite"
    state = create_db_state(f"sqlite:///{db_path}")
    init_db(state)

    with state.session_factory() as session:
        create_domain(session, "Example.COM", source="test")
        create_domain(session, "example.com", source="duplicate")
        domains = list_domains(session)

    assert len(domains) == 1
    assert domains[0].domain == "example.com"
    assert domains[0].source == "test"
