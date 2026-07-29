"""Shared presentation helpers for report exporters."""

from __future__ import annotations

import base64
import mimetypes
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import REPORT_TEMPLATES, REPORT_THEMES, SEVERITIES

MAX_LOGO_BYTES = 2 * 1024 * 1024

DEFAULT_REPORT_CONFIG: Dict[str, Any] = {
    "date": "",
    "version": "1.0",
    "template": "technical",
    "theme": "dark",
    "branding": {
        "company_name": "",
        "logo": "",
        "primary_color": "#7EE787",
        "secondary_color": "#79C0FF",
    },
}


class PresentationError(Exception):
    """Raised when report presentation settings cannot be applied."""


def effective_report_config(
    data: Dict[str, Any],
    template: Optional[str] = None,
    theme: Optional[str] = None,
) -> Dict[str, Any]:
    """Merge optional report config with defaults and CLI overrides."""
    raw_source = data.get("report")
    source: Dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
    raw_branding = source.get("branding")
    branding_source: Dict[str, Any] = (
        raw_branding if isinstance(raw_branding, dict) else {}
    )
    config = {
        "date": source.get("date", DEFAULT_REPORT_CONFIG["date"]),
        "version": source.get("version", DEFAULT_REPORT_CONFIG["version"]),
        "template": template or source.get("template", "technical"),
        "theme": theme or source.get("theme", "dark"),
        "branding": {
            **DEFAULT_REPORT_CONFIG["branding"],
            **branding_source,
        },
    }
    if config["template"] not in REPORT_TEMPLATES:
        raise PresentationError(f"Unsupported report template: {config['template']}")
    if config["theme"] not in REPORT_THEMES:
        raise PresentationError(f"Unsupported report theme: {config['theme']}")
    return config


def report_sections(data: Dict[str, Any], template: str) -> List[Dict[str, str]]:
    """Return deterministic table-of-contents entries for a template."""
    sections = [
        {"id": "engagement", "title": "Engagement"},
        {"id": "scope", "title": "Scope"},
        {"id": "executive-summary", "title": "Executive Summary"},
    ]
    if template == "technical" and str(data.get("methodology", "")).strip():
        sections.append({"id": "methodology", "title": "Methodology"})
    if template == "technical" and str(data.get("limitations", "")).strip():
        sections.append({"id": "limitations", "title": "Limitations"})
    sections.append({"id": "severity-summary", "title": "Severity Summary"})
    sections.append({"id": "findings", "title": "Findings"})
    return sections


def section_number(sections: List[Dict[str, str]], section_id: str) -> str:
    for index, section in enumerate(sections, 1):
        if section["id"] == section_id:
            return f"{index:02d}"
    return "00"


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def slugify(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return text or "section"


def embedded_logo(project_root: Path, config: Dict[str, Any]) -> str:
    """Read and encode a configured logo as a self-contained data URI."""
    logo = str(config["branding"].get("logo", "")).strip()
    if not logo:
        return ""
    root = project_root.expanduser().resolve()
    candidate = (root / logo).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PresentationError("Branding logo escapes the project directory") from exc
    if not candidate.is_file():
        raise PresentationError(f"Branding logo not found: {candidate}")
    size = candidate.stat().st_size
    if size == 0:
        raise PresentationError(f"Branding logo is empty: {candidate}")
    if size > MAX_LOGO_BYTES:
        raise PresentationError("Branding logo exceeds the 2 MiB limit")
    mime, _ = mimetypes.guess_type(candidate.name)
    if mime not in ("image/png", "image/jpeg", "image/gif", "image/svg+xml"):
        raise PresentationError("Unsupported branding logo format")
    encoded = base64.b64encode(candidate.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def plain_text(value: Any) -> str:
    """Normalize arbitrary values to readable text for text/PDF exports."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def ascii_pdf_text(value: Any) -> str:
    """Convert text to characters representable by PDF built-in fonts."""
    text = plain_text(value)
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
    }
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    return text.encode("cp1252", errors="replace").decode("cp1252")


def color_rgb(hex_color: str) -> tuple[float, float, float]:
    value = hex_color.lstrip("#")
    return (
        int(value[0:2], 16) / 255,
        int(value[2:4], 16) / 255,
        int(value[4:6], 16) / 255,
    )
