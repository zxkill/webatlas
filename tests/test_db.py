import json
from pathlib import Path

from src.db import Database, CheckRow, AdminPanelRow


def test_db_upsert_and_update_check(tmp_path: Path) -> None:
    # Создаём временную БД и добавляем домен.
    db_path = tmp_path / "test.sqlite"
    db = Database(str(db_path))
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
    cur = db._conn.execute("SELECT status, score FROM domain_checks")
    assert cur.fetchone() == ("yes", 10)

    # Проверяем, что админка сохранена.
    cur = db._conn.execute("SELECT status, http_status FROM admin_panels")
    assert cur.fetchone() == ("yes", 200)

    # Проверяем связь домена с CMS.
    cur = db._conn.execute("SELECT status, confidence FROM domain_cms")
    assert cur.fetchone() == ("yes", 10)

    db.close()
