"""One-use, exact-operation human approvals in a separate SQLite journal."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path

from .auth import Principal


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path: str | Path, *, clock=time.time):
        path = Path(path)
        if not path.exists():
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError("approval database must be a private regular file")
        self.connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY, subject TEXT NOT NULL, tool TEXT NOT NULL,
            arguments TEXT NOT NULL, arguments_digest TEXT NOT NULL,
            policy_digest TEXT NOT NULL, expires_at REAL NOT NULL,
            state TEXT NOT NULL, reviewer TEXT)""")
        self.clock = clock

    def request_or_consume(self, subject: str, tool: str, args: dict,
                           policy_digest: str, expires_at: float) -> tuple[bool, str]:
        args_json, args_digest = canonical(args), digest(args)
        now = self.clock()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                """SELECT id, state FROM requests WHERE subject=? AND tool=?
                AND arguments_digest=? AND policy_digest=? AND expires_at>?
                AND state IN ('pending','approved') ORDER BY rowid LIMIT 1""",
                (subject, tool, args_digest, policy_digest, now)).fetchone()
            if row and row[1] == "approved":
                self.connection.execute("UPDATE requests SET state='consumed' WHERE id=?", (row[0],))
                result = (True, row[0])
            elif row:
                result = (False, row[0])
            else:
                request_id = secrets.token_urlsafe(24)
                self.connection.execute(
                    "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,NULL)",
                    (request_id, subject, tool, args_json, args_digest, policy_digest,
                     min(now + 300, expires_at), "pending"))
                result = (False, request_id)
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise

    def get(self, request_id: str) -> dict:
        row = self.connection.execute(
            "SELECT id,subject,tool,arguments,policy_digest,expires_at,state FROM requests WHERE id=?",
            (request_id,)).fetchone()
        if not row:
            raise ValueError("unknown request")
        return dict(zip(("id", "subject", "tool", "arguments", "policy_digest", "expires_at", "state"), row))

    def review(self, request_id: str, reviewer: Principal, approve: bool,
               required_scope: str = "agentproof:approve") -> None:
        if required_scope not in reviewer.scopes:
            raise PermissionError("reviewer lacks approval grant")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT subject,expires_at,state FROM requests WHERE id=?",
                                          (request_id,)).fetchone()
            if (row is None or row[2] != "pending" or row[1] <= self.clock()
                    or reviewer.expires_at <= self.clock() or reviewer.subject == row[0]):
                raise PermissionError("approval unavailable or self-approval")
            self.connection.execute("UPDATE requests SET state=?,reviewer=?,expires_at=? WHERE id=?",
                                    ("approved" if approve else "denied", reviewer.subject,
                                     min(row[1], reviewer.expires_at), request_id))
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def close(self) -> None:
        self.connection.close()
