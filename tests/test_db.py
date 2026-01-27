import json
import os

import pytest

# Пропускаем тест, если SQLAlchemy не установлен.
pytest.importorskip("sqlalchemy")

from src.db import AdminPanelRow, CheckRow, Database
from src.webapp_db import AdminPanel, Check, Cms, Domain, DomainCheck, DomainCms


# Проверяем основные операции БД на PostgreSQL. Тест пропускается без DSN.

def _get_test_dsn() -> str:
    dsn = os.getenv("POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("POSTGRES_TEST_DSN не задан, пропускаем интеграционный тест")
    return dsn


def _cleanup(db: Database) -> None:
    # Очищаем таблицы в корректном порядке, чтобы не было конфликтов FK.
    session = db._session
    session.query(DomainCheck).delete()
    session.query(DomainCms).delete()
    session.query(AdminPanel).delete()
    session.query(Check).delete()
    session.query(Cms).delete()
    session.query(Domain).delete()
    session.commit()


def test_db_upsert_and_update_check() -> None:
    # Создаём подключение к тестовой БД и очищаем её.
    db = Database(_get_test_dsn())
    _cleanup(db)

    # Добавляем домен и проверяем дедупликацию.
    db.upsert_domain("example.com", source="file")
    db.upsert_domain("example.com", source="file")
    db.commit()

    # Обновляем результат проверки Bitrix.
    check_row = CheckRow(
        status="yes",
        score=10,
        evidence_json=json.dumps({"ok": True}, ensure_ascii=False),
    )
    db.update_check("example.com", "bitrix", check_row, description="Bitrix check")

    # Обновляем данные по админке.
    admin_row = AdminPanelRow(
        status="yes",
        http_status=200,
        final_url="https://example.com/bitrix/admin/",
        evidence_json=json.dumps({"status": 200}, ensure_ascii=False),
    )
    db.update_admin_panel("example.com", "bitrix_admin", admin_row)

    # Связываем домен с CMS.
    db.update_domain_cms(
        "example.com",
        "bitrix",
        "1C-Bitrix",
        "yes",
        10,
        json.dumps({"score": 10}, ensure_ascii=False),
    )
    db.commit()

    # Проверяем, что домен в БД присутствует и уникален.
    domains = db.load_domains()
    assert domains == ["example.com"]

    # Проверяем, что данные по проверке сохранились.
    check_record = db._session.query(DomainCheck).one()
    assert (check_record.status, check_record.score) == ("yes", 10)

    # Проверяем, что админка сохранена.
    admin_record = db._session.query(AdminPanel).one()
    assert (admin_record.status, admin_record.http_status) == ("yes", 200)

    # Проверяем связь домена с CMS.
    cms_record = db._session.query(DomainCms).one()
    assert (cms_record.status, cms_record.confidence) == ("yes", 10)

    db.close()
