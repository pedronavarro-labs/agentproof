"""Local durable decision journal for the experimental MCP server.

The SQLite file is not an immutable or independently anchored audit log.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class SQLiteAudit:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(path)
        self.connection.execute("""CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at_utc TEXT NOT NULL,
            subject TEXT NOT NULL,
            revision TEXT NOT NULL,
            tool TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL
        )""")
        self.connection.commit()

    def __call__(self, event: dict[str, str]) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO decisions(at_utc, subject, revision, tool, decision, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), event["subject"], event["revision"],
                 event["tool"], event["decision"], event["reason"]),
            )

    def close(self) -> None:
        self.connection.close()
