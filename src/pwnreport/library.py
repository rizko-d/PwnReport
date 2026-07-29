"""Reusable finding library management using SQLite."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from .core import PwnReportError, validate_report

DEFAULT_LIBRARY_DIR = Path("~/.pwnreport").expanduser()


def _get_db_path(library_dir: Path | None = None) -> Path:
    if library_dir is None:
        library_dir = DEFAULT_LIBRARY_DIR
    else:
        library_dir = library_dir.expanduser()
    library_dir.mkdir(parents=True, exist_ok=True)
    return library_dir / "library.db"


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            impact TEXT NOT NULL,
            remediation TEXT NOT NULL,
            reproduction_steps TEXT,
            references_json TEXT,
            cvss_vector TEXT,
            cvss_score REAL,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # FTS for fast searching
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
            title, description, impact, remediation, tags,
            content='findings', content_rowid='id'
        )
        """
    )
    # Triggers to keep FTS in sync
    conn.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid, title, description, impact, remediation, tags)
            VALUES (new.id, new.title, new.description, new.impact, new.remediation, new.tags);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, impact, remediation, tags)
            VALUES('delete', old.id, old.title, old.description, old.impact, old.remediation, old.tags);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, impact, remediation, tags)
            VALUES('delete', old.id, old.title, old.description, old.impact, old.remediation, old.tags);
            INSERT INTO findings_fts(rowid, title, description, impact, remediation, tags)
            VALUES (new.id, new.title, new.description, new.impact, new.remediation, new.tags);
        END;
        """
    )
    conn.commit()


def save_to_library(finding: Dict[str, Any], library_dir: Path | None = None) -> str:
    """Save a finding to the reusable library, stripping asset-specific data."""
    # Ensure it's valid structurally (wrap in dummy report context)
    dummy_report = {
        "project": {"name": "T", "client": "C", "assessment_type": "A", "classification": "C", "author": "A"},
        "scope": [],
        "executive_summary": "S",
        "findings": [finding],
    }
    validate_report(dummy_report)

    db_path = _get_db_path(library_dir)
    with sqlite3.connect(db_path) as conn:
        _init_db(conn)
        
        # Check if title already exists to avoid exact duplicates
        cur = conn.execute("SELECT id FROM findings WHERE title = ?", (finding["title"],))
        if cur.fetchone():
            raise PwnReportError(f"A finding titled '{finding['title']}' already exists in the library.")

        refs_json = json.dumps(finding.get("references", [])) if finding.get("references") else None
        steps_json = json.dumps(finding.get("reproduction_steps", [])) if finding.get("reproduction_steps") else None
        
        cur = conn.execute(
            """
            INSERT INTO findings (
                title, severity, description, impact, remediation, 
                reproduction_steps, references_json, cvss_vector, cvss_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding["title"],
                finding["severity"],
                finding["description"],
                finding["impact"],
                finding["remediation"],
                steps_json,
                refs_json,
                finding.get("cvss_vector"),
                finding.get("cvss_score"),
            ),
        )
        lib_id = f"LIB-{cur.lastrowid:03d}"
        return lib_id


def search_library(query: str = "", library_dir: Path | None = None) -> List[Dict[str, Any]]:
    """Search the finding library using FTS5."""
    db_path = _get_db_path(library_dir)
    if not db_path.exists():
        return []

    with sqlite3.connect(db_path) as conn:
        _init_db(conn)
        conn.row_factory = sqlite3.Row
        
        if query.strip():
            # Basic FTS query matching
            safe_query = query.replace("\"", "").replace("'", "")
            cur = conn.execute(
                """
                SELECT f.* FROM findings f
                JOIN findings_fts fts ON f.id = fts.rowid
                WHERE findings_fts MATCH ?
                ORDER BY rank
                """,
                (f'"{safe_query}"*',)
            )
        else:
            cur = conn.execute("SELECT * FROM findings ORDER BY id DESC")
            
        results = []
        for row in cur.fetchall():
            finding = {
                "lib_id": f"LIB-{row['id']:03d}",
                "title": row["title"],
                "severity": row["severity"],
                "description": row["description"],
                "impact": row["impact"],
                "remediation": row["remediation"],
            }
            if row["reproduction_steps"]:
                finding["reproduction_steps"] = json.loads(row["reproduction_steps"])
            if row["references_json"]:
                finding["references"] = json.loads(row["references_json"])
            if row["cvss_vector"]:
                finding["cvss_vector"] = row["cvss_vector"]
            if row["cvss_score"] is not None:
                finding["cvss_score"] = row["cvss_score"]
            results.append(finding)
        return results


def get_from_library(lib_id: str, library_dir: Path | None = None) -> Dict[str, Any]:
    """Retrieve a specific finding from the library by ID."""
    db_path = _get_db_path(library_dir)
    if not db_path.exists():
        raise PwnReportError("Library database does not exist yet.")

    try:
        numeric_id = int(lib_id.lower().replace("lib-", ""))
    except ValueError:
        raise PwnReportError(f"Invalid library ID format: {lib_id}")

    with sqlite3.connect(db_path) as conn:
        _init_db(conn)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM findings WHERE id = ?", (numeric_id,))
        row = cur.fetchone()
        
        if not row:
            raise PwnReportError(f"Finding {lib_id} not found in library.")
            
        finding = {
            "title": row["title"],
            "severity": row["severity"],
            "description": row["description"],
            "impact": row["impact"],
            "remediation": row["remediation"],
        }
        if row["reproduction_steps"]:
            finding["reproduction_steps"] = json.loads(row["reproduction_steps"])
        if row["references_json"]:
            finding["references"] = json.loads(row["references_json"])
        if row["cvss_vector"]:
            finding["cvss_vector"] = row["cvss_vector"]
        if row["cvss_score"] is not None:
            finding["cvss_score"] = row["cvss_score"]
            
        return finding
