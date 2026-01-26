from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Optional


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source TEXT DEFAULT '2ip',
    bitrix_status TEXT DEFAULT NULL,      -- yes | maybe | no | NULL
    bitrix_score INTEGER DEFAULT 0,
    bitrix_evidence TEXT DEFAULT NULL,    -- JSON

    admin_status TEXT DEFAULT NULL,       -- yes | no | NULL
    admin_http_status INTEGER DEFAULT NULL,
    admin_final_url TEXT DEFAULT NULL,

    last_checked_ts INTEGER DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);
CREATE INDEX IF NOT EXISTS idx_targets_bitrix_status ON targets(bitrix_status);
CREATE INDEX IF NOT EXISTS idx_targets_admin_status ON targets(admin_status);
"""


@dataclass(frozen=True)
class CheckRow:
    bitrix_status: str
    bitrix_score: int
    bitrix_evidence_json: str
    admin_status: Optional[str]
    admin_http_status: Optional[int]
    admin_final_url: Optional[str]


class Database:
    """Мини-обёртка над SQLite: схема, upsert доменов, обновление результатов."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(DB_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def upsert_domain(self, domain: str, source: str = "2ip") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO targets(domain, source) VALUES(?, ?)",
            (domain, source),
        )

    def commit(self) -> None:
        self._conn.commit()

    def load_domains_in_allowlist(self, allow: set[str]) -> list[str]:
        if not allow:
            return []
        placeholders = ",".join(["?"] * len(allow))
        cur = self._conn.execute(
            f"SELECT domain FROM targets WHERE domain IN ({placeholders}) ORDER BY id",
            tuple(allow),
        )
        return [r[0] for r in cur.fetchall()]

    def update_check(self, domain: str, row: CheckRow) -> None:
        self._conn.execute(
            """
            UPDATE targets
               SET bitrix_status=?,
                   bitrix_score=?,
                   bitrix_evidence=?,
                   admin_status=?,
                   admin_http_status=?,
                   admin_final_url=?,
                   last_checked_ts=?
             WHERE domain=?
            """,
            (
                row.bitrix_status,
                row.bitrix_score,
                row.bitrix_evidence_json,
                row.admin_status,
                row.admin_http_status,
                row.admin_final_url,
                int(time.time()),
                domain,
            ),
        )

    def load_domains(self, limit: int | None = None) -> list[str]:
        """
        Возвращает домены
        """
        if limit is None:
            cur = self._conn.execute(
                "SELECT domain FROM targets"
            )
        else:
            cur = self._conn.execute(
                "SELECT domain FROM targets LIMIT ?",
                (limit,),
            )
        return [r[0] for r in cur.fetchall()]
