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
    file_path: str


@dataclass(frozen=True)
class AuditTimeouts:
    total: int


@dataclass(frozen=True)
class AuditConfig:
    concurrency: int
    timeouts: AuditTimeouts


@dataclass(frozen=True)
class ScanPortsConfig:
    ports: list[int]
    timeout_s: float
    concurrency: int


@dataclass(frozen=True)
class ScanConfig:
    concurrency: int
    request_limit: int
    common_paths: list[str]
    ports: ScanPortsConfig
    tls_expiring_days: int
    redirects_limit: int


@dataclass(frozen=True)
class AppConfig:
    db: DbConfig
    rate_limit: RateLimitConfig
    import_cfg: ImportConfig
    audit: AuditConfig
    scan: ScanConfig


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
            file_path=data["import"]["file_path"],
        ),
        audit=AuditConfig(
            concurrency=int(data["audit"]["concurrency"]),
            timeouts=AuditTimeouts(total=int(data["audit"]["timeouts"]["total"])),
        ),
        scan=ScanConfig(
            concurrency=int(data["scan"]["concurrency"]),
            request_limit=int(data["scan"]["request_limit"]),
            common_paths=list(data["scan"]["common_paths"]),
            ports=ScanPortsConfig(
                ports=list(data["scan"]["ports"]["list"]),
                timeout_s=float(data["scan"]["ports"]["timeout_s"]),
                concurrency=int(data["scan"]["ports"]["concurrency"]),
            ),
            tls_expiring_days=int(data["scan"]["tls_expiring_days"]),
            redirects_limit=int(data["scan"]["redirects_limit"]),
        ),
    )
