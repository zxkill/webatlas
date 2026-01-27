from pathlib import Path

import yaml

from src.config import load_config


def test_load_config_reads_file_path(tmp_path: Path) -> None:
    # Подготавливаем минимальный конфиг для проверки загрузки file_path.
    config_path = tmp_path / "config.yaml"
    config_data = {
        "db": {"url": "postgresql+psycopg2://user:pass@localhost:5432/db"},
        "rate_limit": {"rps": 1},
        "import": {
            "api_url_template": "https://example.test?page={page}&token={token}",
            "token": "token",
            "max_domains": 10,
            "file_path": "domains.txt",
        },
        "audit": {"concurrency": 1, "timeouts": {"total": 5}},
    }
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    # Загружаем конфиг и проверяем, что путь корректно читается.
    cfg = load_config(str(config_path))
    assert cfg.import_cfg.file_path == "domains.txt"
    assert cfg.db.url.startswith("postgresql")


def test_load_config_env_override(monkeypatch, tmp_path: Path) -> None:
    # Проверяем, что переменная окружения APP_CONFIG_PATH переопределяет путь.
    config_path = tmp_path / "config.yaml"
    config_data = {
        "db": {"url": "postgresql+psycopg2://user:pass@localhost:5432/db"},
        "rate_limit": {"rps": 2},
        "import": {
            "api_url_template": "https://example.test?page={page}&token={token}",
            "token": "token",
            "max_domains": 5,
            "file_path": "domains.txt",
        },
        "audit": {"concurrency": 1, "timeouts": {"total": 5}},
    }
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    monkeypatch.setenv("APP_CONFIG_PATH", str(config_path))

    cfg = load_config()
    assert cfg.rate_limit.rps == 2
