from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Optional
import logging


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'new',
    created_ts INTEGER NOT NULL,
    updated_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_cms (
    domain_id INTEGER NOT NULL,
    cms_id INTEGER NOT NULL,
    status TEXT DEFAULT NULL,
    confidence INTEGER DEFAULT 0,
    evidence_json TEXT DEFAULT NULL,
    last_checked_ts INTEGER DEFAULT NULL,
    PRIMARY KEY (domain_id, cms_id),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (cms_id) REFERENCES cms(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS domain_checks (
    domain_id INTEGER NOT NULL,
    check_id INTEGER NOT NULL,
    status TEXT DEFAULT NULL,
    score INTEGER DEFAULT 0,
    evidence_json TEXT DEFAULT NULL,
    last_checked_ts INTEGER DEFAULT NULL,
    PRIMARY KEY (domain_id, check_id),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (check_id) REFERENCES checks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admin_panels (
    domain_id INTEGER NOT NULL,
    panel_key TEXT NOT NULL,
    status TEXT DEFAULT NULL,
    http_status INTEGER DEFAULT NULL,
    final_url TEXT DEFAULT NULL,
    evidence_json TEXT DEFAULT NULL,
    last_checked_ts INTEGER DEFAULT NULL,
    PRIMARY KEY (domain_id, panel_key),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    severity TEXT DEFAULT NULL,
    description TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS domain_vulnerabilities (
    domain_id INTEGER NOT NULL,
    vulnerability_id INTEGER NOT NULL,
    status TEXT DEFAULT NULL,
    evidence_json TEXT DEFAULT NULL,
    last_checked_ts INTEGER DEFAULT NULL,
    PRIMARY KEY (domain_id, vulnerability_id),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domain_checks_status ON domain_checks(status);
CREATE INDEX IF NOT EXISTS idx_domain_admin_panels_status ON admin_panels(status);
"""

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckRow:
    status: str
    score: int
    evidence_json: str


@dataclass(frozen=True)
class AdminPanelRow:
    status: Optional[str]
    http_status: Optional[int]
    final_url: Optional[str]
    evidence_json: str


class Database:
    """Мини-обёртка над SQLite: схема, upsert доменов, обновление результатов."""

    def __init__(self, path: str) -> None:
        # Инициализируем подключение и включаем оптимизации для параллельных чтений/записей.
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        # Схема создаётся при первом запуске — считаем, что БД пустая.
        self._conn.executescript(DB_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def upsert_domain(self, domain: str, source: str = "manual") -> None:
        """
        Добавляет домен в БД или обновляет метаданные, если он уже есть.
        """
        # Фиксируем timestamps, чтобы понимать историю обновлений.
        ts = int(time.time())
        self._conn.execute(
            """
            INSERT INTO domains(domain, source, created_ts, updated_ts)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                source=excluded.source,
                updated_ts=excluded.updated_ts
            """,
            (domain, source, ts, ts),
        )

    def _get_domain_id(self, domain: str) -> Optional[int]:
        # Получаем id домена — это ключ для всех связанных таблиц.
        cur = self._conn.execute(
            "SELECT id FROM domains WHERE domain=?",
            (domain,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def _ensure_check(self, key: str, description: str | None = None) -> int:
        """
        Регистрирует тип проверки (например, bitrix) и возвращает её id.
        """
        # Храним справочник проверок, чтобы структура была масштабируемой.
        self._conn.execute(
            """
            INSERT INTO checks(key, description)
            VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET description=COALESCE(?, description)
            """,
            (key, description, description),
        )
        cur = self._conn.execute("SELECT id FROM checks WHERE key=?", (key,))
        return int(cur.fetchone()[0])

    def _ensure_cms(self, key: str, name: str) -> int:
        """
        Регистрирует CMS и возвращает её id.
        """
        # Справочник CMS — пригодится для расширения на другие движки.
        self._conn.execute(
            """
            INSERT INTO cms(key, name)
            VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET name=excluded.name
            """,
            (key, name),
        )
        cur = self._conn.execute("SELECT id FROM cms WHERE key=?", (key,))
        return int(cur.fetchone()[0])

    def commit(self) -> None:
        self._conn.commit()

    def update_check(self, domain: str, check_key: str, row: CheckRow, description: str | None = None) -> None:
        """
        Обновляет результаты конкретной проверки (например, bitrix).
        """
        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении проверки: %s", domain)
            return

        # Каждая проверка хранится как отдельная сущность, чтобы дополнять набор без изменений схемы.
        check_id = self._ensure_check(check_key, description)
        self._conn.execute(
            """
            INSERT INTO domain_checks(domain_id, check_id, status, score, evidence_json, last_checked_ts)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, check_id) DO UPDATE SET
                status=excluded.status,
                score=excluded.score,
                evidence_json=excluded.evidence_json,
                last_checked_ts=excluded.last_checked_ts
            """,
            (
                domain_id,
                check_id,
                row.status,
                row.score,
                row.evidence_json,
                int(time.time()),
            ),
        )

    def update_admin_panel(self, domain: str, panel_key: str, row: AdminPanelRow) -> None:
        """
        Обновляет статус доступности админки (для разных CMS/фреймворков).
        """
        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении админки: %s", domain)
            return

        # panel_key позволяет хранить несколько типов админок для одного домена.
        self._conn.execute(
            """
            INSERT INTO admin_panels(domain_id, panel_key, status, http_status, final_url, evidence_json, last_checked_ts)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, panel_key) DO UPDATE SET
                status=excluded.status,
                http_status=excluded.http_status,
                final_url=excluded.final_url,
                evidence_json=excluded.evidence_json,
                last_checked_ts=excluded.last_checked_ts
            """,
            (
                domain_id,
                panel_key,
                row.status,
                row.http_status,
                row.final_url,
                row.evidence_json,
                int(time.time()),
            ),
        )

    def update_domain_cms(self, domain: str, cms_key: str, cms_name: str, status: str, confidence: int, evidence_json: str) -> None:
        """
        Фиксирует принадлежность домена к CMS (например, bitrix).
        """
        domain_id = self._get_domain_id(domain)
        if domain_id is None:
            logger.warning("Домен не найден при обновлении CMS: %s", domain)
            return

        # CMS регистрируем в справочнике, затем связываем с доменом.
        cms_id = self._ensure_cms(cms_key, cms_name)
        self._conn.execute(
            """
            INSERT INTO domain_cms(domain_id, cms_id, status, confidence, evidence_json, last_checked_ts)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain_id, cms_id) DO UPDATE SET
                status=excluded.status,
                confidence=excluded.confidence,
                evidence_json=excluded.evidence_json,
                last_checked_ts=excluded.last_checked_ts
            """,
            (
                domain_id,
                cms_id,
                status,
                confidence,
                evidence_json,
                int(time.time()),
            ),
        )

    def load_domains(self, limit: int | None = None) -> list[str]:
        """
        Возвращает домены
        """
        if limit is None:
            cur = self._conn.execute(
                "SELECT domain FROM domains ORDER BY id"
            )
        else:
            cur = self._conn.execute(
                "SELECT domain FROM domains ORDER BY id LIMIT ?",
                (limit,),
            )
        return [r[0] for r in cur.fetchall()]
