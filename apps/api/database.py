"""SQLite persistence for ARGUS assessments, findings, checkpoints, and live events.

Uses Write-Ahead Logging (PRAGMA journal_mode=WAL) and foreign keys (PRAGMA foreign_keys=ON)
with a busy timeout so request handlers, SSE streams, and background LangGraph workers
execute concurrently without blocking.
"""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

TERMINAL_STATUSES = frozenset({"SUCCESS", "FAILED", "PARTIAL_SUCCESS", "CANCELLED", "COMPLETED"})

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'web',
    target_value TEXT NOT NULL DEFAULT '',
    target_json TEXT NOT NULL,
    objective TEXT NOT NULL DEFAULT '',
    objective_json TEXT NOT NULL,
    scope_yaml TEXT NOT NULL DEFAULT '',
    scope_json TEXT NOT NULL,
    scope_raw TEXT NOT NULL,
    simulation INTEGER NOT NULL DEFAULT 0,
    max_iterations INTEGER NOT NULL DEFAULT 10,
    outcome TEXT,
    summary TEXT,
    error TEXT,
    report_markdown TEXT,
    report_path_md TEXT,
    report_path_pdf TEXT,
    state_json TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    pause_requested INTEGER NOT NULL DEFAULT 0,
    langfuse_trace_id TEXT,
    langfuse_session_id TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    node TEXT,
    data_json TEXT NOT NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessment_events (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    verification_method TEXT,
    affected_asset TEXT NOT NULL,
    impact TEXT,
    remediation TEXT,
    finding_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_path TEXT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS graph_checkpoints (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    thread_id TEXT NOT NULL,
    checkpoint_blob BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_assessment_id
    ON events (assessment_id, id);

CREATE INDEX IF NOT EXISTS idx_assessment_events_id
    ON assessment_events (assessment_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_findings_assessment_id
    ON findings (assessment_id);

CREATE INDEX IF NOT EXISTS idx_evidence_assessment_id
    ON evidence_artifacts (assessment_id);

CREATE INDEX IF NOT EXISTS idx_checkpoints_assessment_id
    ON graph_checkpoints (assessment_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True)


class Database:
    """Thread-safe-by-connection SQLite store for assessment lifecycle data."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def init_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            # Schema evolution: ensure optional columns exist if migrating existing DB
            cursor = connection.execute("PRAGMA table_info(assessments)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            for col, col_def in [
                ("name", "TEXT NOT NULL DEFAULT ''"),
                ("completed_at", "TEXT"),
                ("target_type", "TEXT NOT NULL DEFAULT 'web'"),
                ("target_value", "TEXT NOT NULL DEFAULT ''"),
                ("objective", "TEXT NOT NULL DEFAULT ''"),
                ("scope_yaml", "TEXT NOT NULL DEFAULT ''"),
                ("pause_requested", "INTEGER NOT NULL DEFAULT 0"),
                ("langfuse_trace_id", "TEXT"),
                ("langfuse_session_id", "TEXT"),
            ]:
                if col not in existing_cols:
                    connection.execute(f"ALTER TABLE assessments ADD COLUMN {col} {col_def}")

    # ------------------------------------------------------------------
    # Assessment lifecycle
    # ------------------------------------------------------------------
    def create(
        self,
        assessment_id: str,
        *,
        name: str = "",
        status: str = "READY",
        target: dict[str, Any],
        objective: dict[str, Any] | str,
        scope: dict[str, Any],
        scope_raw: str,
        simulation: bool,
        max_iterations: int,
        langfuse_trace_id: str | None = None,
        langfuse_session_id: str | None = None,
    ) -> None:
        now = _now()
        target_type = target.get("type", "web")
        target_val = target.get("value") or str(target)
        obj_str = (
            objective if isinstance(objective, str) else objective.get("type", "discover_services")
        )
        obj_dict = objective if isinstance(objective, dict) else {"type": str(objective)}

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessments (
                    id, name, created_at, updated_at, status,
                    target_type, target_value, target_json,
                    objective, objective_json,
                    scope_yaml, scope_json, scope_raw,
                    simulation, max_iterations,
                    langfuse_trace_id, langfuse_session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    name or f"Assessment-{target_val}",
                    now,
                    now,
                    status,
                    target_type,
                    target_val,
                    _dumps(target),
                    obj_str,
                    _dumps(obj_dict),
                    scope_raw,
                    _dumps(scope),
                    scope_raw,
                    int(simulation),
                    max_iterations,
                    langfuse_trace_id,
                    langfuse_session_id,
                ),
            )

    def update_assessment(self, assessment_id: str, **fields: Any) -> None:
        allowed = {
            "name",
            "status",
            "outcome",
            "summary",
            "error",
            "report_markdown",
            "report_path_md",
            "report_path_pdf",
            "state_json",
            "completed_at",
            "cancel_requested",
            "pause_requested",
            "langfuse_trace_id",
            "langfuse_session_id",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unsupported assessment fields: {sorted(unknown)}")
        if not fields:
            return
        assignments = ", ".join(f"{name} = ?" for name in fields)
        values = [fields[name] for name in fields]
        with self._connect() as connection:
            connection.execute(
                f"UPDATE assessments SET {assignments}, updated_at = ? WHERE id = ?",
                (*values, _now(), assessment_id),
            )

    def get(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assessments ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_assessment(self, assessment_id: str) -> bool:
        """Hard-delete an assessment and every persisted child record."""
        child_tables = (
            "events",
            "assessment_events",
            "findings",
            "evidence_artifacts",
            "graph_checkpoints",
        )
        with self._connect() as connection:
            for table in child_tables:
                connection.execute(
                    f"DELETE FROM {table} WHERE assessment_id = ?", (assessment_id,)
                )
            cursor = connection.execute(
                "DELETE FROM assessments WHERE id = ?", (assessment_id,)
            )
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("target_json", "objective_json", "scope_json"):
            if data.get(key):
                data[key.removesuffix("_json")] = json.loads(data.pop(key))
            else:
                data.pop(key, None)
        data["simulation"] = bool(data.get("simulation", 0))
        if data.get("state_json"):
            data["state"] = json.loads(data["state_json"])
        else:
            data["state"] = None
        return data

    def request_cancel(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE assessments SET cancel_requested = 1, updated_at = ? WHERE id = ?",
                (_now(), assessment_id),
            )
            return cursor.rowcount > 0

    def is_cancel_requested(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def request_pause(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE assessments SET pause_requested = 1, updated_at = ? WHERE id = ?",
                (_now(), assessment_id),
            )
            return cursor.rowcount > 0

    def clear_pause(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE assessments SET pause_requested = 0, updated_at = ? WHERE id = ?",
                (_now(), assessment_id),
            )
            return cursor.rowcount > 0

    def is_pause_requested(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT pause_requested FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return bool(row and row["pause_requested"])

    # ------------------------------------------------------------------
    # Checkpoints
    # ------------------------------------------------------------------
    def save_checkpoint(
        self,
        checkpoint_id: str,
        assessment_id: str,
        thread_id: str,
        checkpoint_blob: bytes,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO graph_checkpoints (
                    id, assessment_id, thread_id, checkpoint_blob, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (checkpoint_id, assessment_id, thread_id, checkpoint_blob, _now()),
            )

    def get_latest_checkpoint(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, assessment_id, thread_id, checkpoint_blob, created_at
                FROM graph_checkpoints
                WHERE assessment_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (assessment_id,),
            ).fetchone()
        if not row:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Findings & Evidence
    # ------------------------------------------------------------------
    def save_finding(self, assessment_id: str, finding: dict[str, Any]) -> None:
        finding_id = finding.get("finding_id") or finding.get("id") or f"find-{uuid4().hex[:8]}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, assessment_id, title, severity, confidence,
                    verification_method, affected_asset, impact, remediation,
                    finding_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    assessment_id,
                    finding.get("title", "Untitled Finding"),
                    finding.get("severity", "MEDIUM"),
                    finding.get("confidence", "POTENTIAL"),
                    finding.get("verification_method", ""),
                    finding.get("affected_asset", ""),
                    finding.get("impact", ""),
                    finding.get("remediation", ""),
                    _dumps(finding),
                    finding.get("created_at") or _now(),
                ),
            )

    def get_findings(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE assessment_id = ? ORDER BY created_at ASC",
                (assessment_id,),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            if data.get("finding_json"):
                parsed = json.loads(data["finding_json"])
                results.append(parsed)
            else:
                results.append(data)
        return results

    def save_evidence_artifact(
        self,
        assessment_id: str,
        tool_name: str,
        sha256: str,
        file_path: str,
        artifact_id: str | None = None,
    ) -> None:
        art_id = artifact_id or f"ev-{uuid4().hex[:8]}"
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO evidence_artifacts (
                    id, assessment_id, tool_name, sha256, file_path, captured_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (art_id, assessment_id, tool_name, sha256, file_path, _now()),
            )

    def get_evidence_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_artifacts WHERE assessment_id = ? ORDER BY captured_at ASC",
                (assessment_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Event stream
    # ------------------------------------------------------------------
    def append_event(
        self,
        assessment_id: str,
        event_type: str,
        *,
        node: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> int:
        now = _now()
        payload = _dumps(data or {})
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (assessment_id, created_at, event_type, node, data_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (assessment_id, now, event_type, node, payload),
            )
            event_id = int(cursor.lastrowid or 0)
            connection.execute(
                """
                INSERT INTO assessment_events (id, assessment_id, event_type, payload, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (f"evt-{event_id}", assessment_id, event_type, payload, now),
            )
            return event_id

    def events_after(
        self, assessment_id: str, event_id: int = 0, limit: int = 200
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, event_type, node, data_json
                FROM events
                WHERE assessment_id = ? AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (assessment_id, event_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "node": row["node"],
                "data": json.loads(row["data_json"]),
            }
            for row in rows
        ]
