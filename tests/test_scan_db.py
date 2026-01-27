import json
import time

from src.db import Database, CheckRow


def test_scan_run_roundtrip(tmp_path) -> None:
    db_path = tmp_path / "scan.sqlite"
    db = Database(str(db_path))
    try:
        # Добавляем домен, чтобы был domain_id.
        db.upsert_domain("example.com", source="test")
        db.commit()

        scan_run_id = db.create_scan_run("example.com")
        assert scan_run_id is not None

        db.add_scan_finding(
            scan_run_id,
            category="headers",
            finding_key="missing_csp",
            severity="low",
            description="Отсутствует CSP",
            evidence_json=json.dumps({"header": "Content-Security-Policy"}),
        )

        summary = {"domain": "example.com", "finished_ts": int(time.time())}
        db.finish_scan_run(scan_run_id, status="completed", risk_score=1, summary_json=json.dumps(summary))
        db.commit()

        report = db.get_scan_report(scan_run_id)
        assert report is not None
        assert report["domain"] == "example.com"
        assert report["risk_score"] == 1
        assert report["findings"][0]["key"] == "missing_csp"
    finally:
        db.close()
