"""Workspace management for PwnReport."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from .library import _get_db_path, _init_db


def _init_workspace_db(conn: sqlite3.Connection) -> None:
    _init_db(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            path TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client TEXT NOT NULL,
            findings_count INTEGER DEFAULT 0,
            last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()


def register_project(report_path: Path, library_dir: Path | None = None) -> None:
    """Register or update a project in the global workspace."""
    resolved_path = report_path.expanduser().resolve()
    
    if not resolved_path.exists():
        return
        
    try:
        data = json.loads(resolved_path.read_text(encoding="utf-8"))
        project_name = data.get("project", {}).get("name", "Unknown")
        client = data.get("project", {}).get("client", "Unknown")
        findings_count = len(data.get("findings", []))
    except Exception:
        return

    db_path = _get_db_path(library_dir)
    with sqlite3.connect(db_path) as conn:
        _init_workspace_db(conn)
        conn.execute(
            """
            INSERT INTO projects (path, name, client, findings_count, last_accessed)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(path) DO UPDATE SET
                name=excluded.name,
                client=excluded.client,
                findings_count=excluded.findings_count,
                last_accessed=CURRENT_TIMESTAMP
            """,
            (str(resolved_path), project_name, client, findings_count),
        )


def list_projects(library_dir: Path | None = None) -> List[Dict[str, Any]]:
    """List all registered projects, ordered by recently accessed."""
    db_path = _get_db_path(library_dir)
    if not db_path.exists():
        return []

    with sqlite3.connect(db_path) as conn:
        _init_workspace_db(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM projects ORDER BY last_accessed DESC")
        
        results = []
        for row in cur.fetchall():
            # Verify it still exists before returning
            if Path(row["path"]).exists():
                results.append(dict(row))
            else:
                # Cleanup dead paths
                conn.execute("DELETE FROM projects WHERE path = ?", (row["path"],))
                
        return results
