import os
import pytest

# Пропускаем тест, если SQLAlchemy не установлен (например, в офлайн окружении).
pytest.importorskip("sqlalchemy")

from src.webapp_db import (
    AdminPanel,
    AdminPanelRow,
    Check,
    CheckRow,
    Cms,
    CmsRow,
    Domain,
    DomainCheck,
    DomainCms,
    create_db_state,
    create_domain,
    get_domain_report,
    import_domains_from_file,
    init_db,
    list_domains,
    update_admin_panel,
    update_check,
    update_domain_cms,
)


# Тестируем базовый CRUD для доменов и отчёта на PostgreSQL.

def _get_test_dsn() -> str:
    dsn = os.getenv("POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("POSTGRES_TEST_DSN не задан, пропускаем интеграционный тест")
    return dsn


def _cleanup(session) -> None:
    # Очищаем таблицы, чтобы тесты не зависели друг от друга.
    session.query(DomainCheck).delete()
    session.query(DomainCms).delete()
    session.query(AdminPanel).delete()
    session.query(Check).delete()
    session.query(Cms).delete()
    session.query(Domain).delete()
    session.commit()


def test_webapp_db_create_and_report():
    state = create_db_state(_get_test_dsn())
    init_db(state)

    with state.session_factory() as session:
        _cleanup(session)
        create_domain(session, "Example.COM", source="test")
        update_check(session, "example.com", "bitrix", CheckRow(status="yes", score=90, evidence_json="{}"))
        update_admin_panel(
            session,
            "example.com",
            "bitrix_admin",
            AdminPanelRow(status="yes", http_status=200, final_url="/bitrix/admin/", evidence_json="{}"),
        )
        update_domain_cms(
            session,
            "example.com",
            "bitrix",
            "1C-Bitrix",
            CmsRow(status="yes", confidence=90, evidence_json="{}"),
        )
        report = get_domain_report(session, "example.com")

    assert report is not None
    assert report["domain"] == "example.com"
    assert report["checks"][0]["status"] == "yes"
    assert report["admin_panels"][0]["status"] == "yes"
    assert report["cms"][0]["key"] == "bitrix"


# Проверяем импорт доменов из файла.

def test_webapp_db_import_from_file(tmp_path):
    file_path = tmp_path / "domains.txt"
    file_path.write_text("example.com\nExample.com\nsecond.local\n", encoding="utf-8")

    state = create_db_state(_get_test_dsn())
    init_db(state)

    with state.session_factory() as session:
        _cleanup(session)
        stats = import_domains_from_file(session, str(file_path), source="file")
        domains = list_domains(session, limit=10)

    assert stats.total_lines == 3
    assert stats.unique_domains == 2
    assert len(domains) == 2
