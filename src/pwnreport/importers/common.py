"""Shared helpers for scanner importers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

MAX_IMPORT_BYTES = 25 * 1024 * 1024

SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
    "unknown": "info",
}


class ImporterError(Exception):
    """Raised when scanner output cannot be parsed safely."""


def read_import_bytes(path: Path) -> bytes:
    """Read an import source with a conservative size limit."""
    source = path.expanduser().resolve()
    try:
        size = source.stat().st_size
    except FileNotFoundError as exc:
        raise ImporterError(f"Import source not found: {source}") from exc
    except OSError as exc:
        raise ImporterError(f"Could not inspect import source: {exc}") from exc
    if not source.is_file():
        raise ImporterError(f"Import source is not a regular file: {source}")
    if size == 0:
        raise ImporterError(f"Import source is empty: {source}")
    if size > MAX_IMPORT_BYTES:
        raise ImporterError(
            f"Import source exceeds the {MAX_IMPORT_BYTES // (1024 * 1024)} MiB limit"
        )
    try:
        return source.read_bytes()
    except OSError as exc:
        raise ImporterError(f"Could not read import source: {exc}") from exc


def clean_text(value: Any, default: str = "") -> str:
    """Return normalized plain text without collapsing intentional newlines."""
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(item) for item in value if item is not None)
    text = str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
    return text or default


def compact_text(value: Any, default: str = "") -> str:
    """Return single-line normalized text."""
    return re.sub(r"\s+", " ", clean_text(value, default)).strip()


def normalize_severity(value: Any) -> str:
    """Map common scanner severity labels and numeric values."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = int(value)
        return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(
            numeric, "info"
        )
    label = compact_text(value, "info").lower()
    if label.isdigit():
        return normalize_severity(int(label))
    return SEVERITY_ALIASES.get(label, "info")


def string_list(value: Any) -> List[str]:
    """Normalize a scalar or sequence to a unique list of non-empty strings."""
    if value is None:
        return []
    values: Iterable[Any]
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = (value,)
    result: List[str] = []
    seen = set()
    for item in values:
        text = compact_text(item)
        if text and text.casefold() not in seen:
            result.append(text)
            seen.add(text.casefold())
    return result


def optional_score(value: Any) -> Optional[float]:
    """Parse an optional CVSS score without accepting invalid ranges."""
    if value in (None, ""):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def normalized_finding(
    *,
    title: Any,
    severity: Any,
    affected_asset: Any,
    description: Any,
    evidence: Any,
    remediation: Any,
    impact: Any = None,
    references: Any = None,
    cvss_vector: Any = None,
    cvss_score: Any = None,
    source_tool: str,
    source_id: Any = None,
) -> Dict[str, Any]:
    """Build one valid PwnReport finding without assigning its final ID."""
    finding: Dict[str, Any] = {
        "title": compact_text(title, "Untitled imported finding"),
        "severity": normalize_severity(severity),
        "affected_asset": compact_text(affected_asset, "Unspecified asset"),
        "description": clean_text(
            description, "No description was provided by the source scanner."
        ),
        "impact": clean_text(
            impact,
            "The potential impact requires manual validation and risk assessment.",
        ),
        "evidence": clean_text(
            evidence, "No scanner evidence was included in the source export."
        ),
        "remediation": clean_text(
            remediation,
            "Review the scanner result and apply an appropriate remediation.",
        ),
        "remediation_status": "open",
        "source": {
            "tool": source_tool,
            "source_id": compact_text(source_id),
        },
    }
    refs = string_list(references)
    if refs:
        finding["references"] = refs
    vector = compact_text(cvss_vector)
    if vector:
        finding["cvss_vector"] = vector
    score = optional_score(cvss_score)
    if score is not None:
        finding["cvss_score"] = score
    return finding


def require_findings(findings: List[Dict[str, Any]], tool: str) -> List[Dict[str, Any]]:
    """Reject syntactically valid exports that contain no importable findings."""
    if not findings:
        raise ImporterError(f"No importable {tool} findings were found")
    return findings
