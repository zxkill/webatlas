from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import yaml


@dataclass(frozen=True)
class DbConfig:
    path: str


@dataclass(frozen=True)
class RateLimitConfig:
    rps: float


@dataclass(frozen=True)
class ImportConfig:
    api_url_template: str
    token: str
    max_domains: int


@dataclass(frozen=True)
class AuditTimeouts:
    total: int


@dataclass(frozen=True)
class AuditConfig:
    concurrency: int
    timeouts: AuditTimeouts


@dataclass(frozen=True)
class AppConfig:
    db: DbConfig
    rate_limit: RateLimitConfig
    import_cfg: ImportConfig
    audit: AuditConfig


def load_config(path: str = "config.yaml") -> AppConfig:
    """
    Загружает конфигурацию из YAML. Все параметры берём только из конфига,
    чтобы запуск был одинаковым и воспроизводимым.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    return AppConfig(
        db=DbConfig(path=data["db"]["path"]),
        rate_limit=RateLimitConfig(rps=float(data["rate_limit"]["rps"])),
        import_cfg=ImportConfig(
            api_url_template=data["import"]["api_url_template"],
            token=data["import"]["token"],
            max_domains=int(data["import"]["max_domains"]),
        ),
        audit=AuditConfig(
            concurrency=int(data["audit"]["concurrency"]),
            timeouts=AuditTimeouts(total=int(data["audit"]["timeouts"]["total"])),
        ),
    )
