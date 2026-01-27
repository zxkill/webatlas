from pathlib import Path

import yaml

from src.config import load_config


def test_load_config_reads_file_path(tmp_path: Path) -> None:
    # Подготавливаем минимальный конфиг для проверки загрузки file_path.
    config_path = tmp_path / "config.yaml"
    config_data = {
        "db": {"path": "test.sqlite"},
        "rate_limit": {"rps": 1},
        "import": {
            "api_url_template": "https://example.test?page={page}&token={token}",
            "token": "token",
            "max_domains": 10,
            "file_path": "domains.txt",
        },
        "audit": {"concurrency": 1, "timeouts": {"total": 5}},
        "scan": {
            "concurrency": 1,
            "request_limit": 10,
            "redirects_limit": 5,
            "tls_expiring_days": 30,
            "common_paths": ["/admin"],
            "ports": {"list": [80, 443], "timeout_s": 1.0, "concurrency": 5},
        },
    }
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    # Загружаем конфиг и проверяем, что путь корректно читается.
    cfg = load_config(str(config_path))
    assert cfg.import_cfg.file_path == "domains.txt"
