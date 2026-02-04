from pathlib import Path

import pytest
import yaml

from src.settings.loader import load_settings


@pytest.mark.usefixtures("monkeypatch")
def test_load_settings_reads_audit_tuning(monkeypatch, tmp_path: Path) -> None:
    """
    Проверяем, что параметры параллельности и пулов читаются из YAML.
    """
    config_path = tmp_path / "config.yaml"
    config_data = {
        "rate_limit": {"rps": 1.0},
        "import": {"url_template": "https://example.test"},
        "audit": {
            "concurrency": 5,
            "persist_concurrency": 3,
            "threadpool_workers": 16,
            "http_pool_limit": 500,
            "http_pool_limit_per_host": 100,
            "timeouts": {"total": 2},
        },
    }
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("APP_CONFIG_PATH", str(config_path))

    settings = load_settings()

    assert settings.app.audit_concurrency == 5
    assert settings.app.audit_persist_concurrency == 3
    assert settings.app.audit_threadpool_workers == 16
    assert settings.app.audit_http_pool_limit == 500
    assert settings.app.audit_http_pool_limit_per_host == 100
