import os
import time
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
    ModuleRun,
    ModuleRunRow,
    create_db_state,
    create_domain,
    domains_staging_table,
    get_dashboard_data,
    get_domains_focus_data,
    get_domain_report,
    import_domains_from_file,
    init_db,
    list_domains,
    update_admin_panel,
    update_check,
    update_domain_cms,
    update_module_run,
)
from src.audit_modules.availability.availability import AvailabilityCheck, AvailabilityModule
from src.audit_modules.admin_detect.admin_detect import BitrixAdminCheck
from src.audit_modules.cms_detect.bitrix_detect import BitrixDetectCheck
from src.audit_modules.tls_certificate.tls_certificate import TlsCertificateCheck


# Тестируем базовый CRUD для доменов и отчёта на PostgreSQL.

def _get_test_dsn() -> str:
    dsn = os.getenv("POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("POSTGRES_TEST_DSN не задан, пропускаем интеграционный тест")
    return dsn


def _cleanup(session) -> None:
    # Очищаем таблицы, чтобы тесты не зависели друг от друга.
    session.execute(domains_staging_table.delete())
    session.query(DomainCheck).delete()
    session.query(DomainCms).delete()
    session.query(AdminPanel).delete()
    session.query(ModuleRun).delete()
    session.query(AvailabilityCheck).delete()
    session.query(BitrixDetectCheck).delete()
    session.query(BitrixAdminCheck).delete()
    session.query(TlsCertificateCheck).delete()
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
        update_module_run(
            session,
            "example.com",
            ModuleRunRow(
                module_key="availability",
                module_name="Availability",
                status="success",
                started_ts=1,
                finished_ts=2,
                duration_ms=100,
                detail_json='{"check_updates": 1}',
            ),
        )
        # Добавляем модульные данные через модуль доступности, чтобы проверить отчёт блоками.
        AvailabilityModule().persist(
            session,
            "example.com",
            [
                {
                    "checked_ts": 1,
                    "scheme": "https",
                    "status": "yes",
                    "http_status": 200,
                    "final_url": "https://example.com/",
                    "evidence_json": "{}",
                }
            ],
        )
        report = get_domain_report(session, "example.com")

    assert report is not None
    assert report["domain"] == "example.com"
    assert report["checks"][0]["status"] == "yes"
    assert report["admin_panels"][0]["status"] == "yes"
    assert report["cms"][0]["key"] == "bitrix"
    assert report["module_runs"][0]["module_key"] == "availability"
    assert report["module_blocks"][0]["entries"]


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


def test_webapp_db_dashboard_and_focus_payloads():
    # Проверяем, что dashboard и focus-данные формируются согласованно.
    state = create_db_state(_get_test_dsn())
    init_db(state)

    with state.session_factory() as session:
        _cleanup(session)

        # Подготовка доменов для тестового набора.
        create_domain(session, "one.example", source="seed")
        create_domain(session, "two.example", source="seed")
        create_domain(session, "three.example", source="seed")

        now_ts = int(time.time())

        # TLS: один домен "скоро", второй — не входит в порог.
        update_module_run(
            session,
            "one.example",
            ModuleRunRow(
                module_key="tls_certificate",
                module_name="TLS",
                status="success",
                started_ts=now_ts - 60,
                finished_ts=now_ts - 30,
                duration_ms=100,
                detail_json='{"days_left": 2}',
            ),
        )
        update_module_run(
            session,
            "two.example",
            ModuleRunRow(
                module_key="tls_certificate",
                module_name="TLS",
                status="success",
                started_ts=now_ts - 120,
                finished_ts=now_ts - 90,
                duration_ms=100,
                detail_json='{"days_left": 30}',
            ),
        )

        # Критичное событие для третьего домена.
        update_module_run(
            session,
            "three.example",
            ModuleRunRow(
                module_key="availability",
                module_name="Availability",
                status="failed",
                started_ts=now_ts - 300,
                finished_ts=now_ts - 250,
                duration_ms=100,
                detail_json="{}",
                error_message="timeout",
            ),
        )

        # Добавляем аудит за 24 часа, чтобы проверить фокус recent_audits.
        update_module_run(
            session,
            "one.example",
            ModuleRunRow(
                module_key="availability",
                module_name="Availability",
                status="success",
                started_ts=now_ts - 10,
                finished_ts=now_ts - 5,
                duration_ms=50,
                detail_json="{}",
            ),
        )

        dashboard = get_dashboard_data(session, top_n=5, tls_soon_days=14)

        assert dashboard["kpis"]["total_domains"] == 3
        assert dashboard["kpis"]["critical_count"] == 1
        assert dashboard["kpis"]["tls_soon_count"] == 1
        assert dashboard["tls_soon"][0]["domain"] == "one.example"
        assert dashboard["critical_events"][0]["domain"] == "three.example"

        focus_critical = get_domains_focus_data(session, focus="critical", tls_soon_days=14)
        assert focus_critical["focus"]["key"] == "critical"
        assert focus_critical["focus"]["count"] == 1
        assert focus_critical["domains"][0]["domain"] == "three.example"

        focus_tls = get_domains_focus_data(session, focus="tls_soon", tls_soon_days=14)
        assert focus_tls["focus"]["key"] == "tls_soon"
        assert focus_tls["focus"]["count"] == 1
        assert focus_tls["domains"][0]["domain"] == "one.example"

        focus_audits = get_domains_focus_data(session, focus="recent_audits", tls_soon_days=14)
        assert focus_audits["focus"]["key"] == "recent_audits"
        assert focus_audits["focus"]["count"] >= 1
        assert focus_audits["domains"][0]["domain"] == "one.example"
