"""Project initialization, report loading, validation, and building."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import (
    FINDING_FIELDS,
    PROJECT_FIELDS,
    SEVERITIES,
    SEVERITY_RANK,
)
from .renderer import render_report


class PwnReportError(Exception):
    """Base exception for errors that should be shown to CLI users."""


class ValidationError(PwnReportError):
    """Raised when report data does not match the minimal schema."""

    def __init__(self, errors: List[str]) -> None:
        self.errors = errors
        super().__init__("Report validation failed:\n  - " + "\n  - ".join(errors))


def _default_report(project_name: str) -> Dict[str, Any]:
    return {
        "project": {
            "name": project_name,
            "client": "Client Name",
            "assessment_type": "Web Application",
            "classification": "CONFIDENTIAL",
            "author": "Rizko Febri Rachmayadi",
        },
        "scope": [],
        "executive_summary": "No executive summary has been provided.",
        "findings": [],
    }


def initialize_project(destination: Path) -> Path:
    """Create a minimal PwnReport workspace and return its report path."""
    destination = destination.expanduser().resolve()
    report_path = destination / "report.json"

    if report_path.exists():
        raise PwnReportError(f"Refusing to overwrite existing report: {report_path}")

    try:
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "output").mkdir(exist_ok=True)
        project_name = destination.name.replace("-", " ").replace("_", " ").title()
        report_path.write_text(
            json.dumps(_default_report(project_name), indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise PwnReportError(f"Could not initialize project: {exc}") from exc

    return report_path


def load_report(report_path: Path) -> Dict[str, Any]:
    """Load a JSON report file with user-friendly errors."""
    report_path = report_path.expanduser().resolve()
    try:
        raw_data = report_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PwnReportError(f"Report file not found: {report_path}") from exc
    except OSError as exc:
        raise PwnReportError(f"Could not read report file: {exc}") from exc

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise PwnReportError(
            f"Invalid JSON in {report_path} at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ValidationError(["report root must be a JSON object"])
    return data


def _validate_text(container: Dict[str, Any], field: str, location: str, errors: List[str]) -> None:
    value = container.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{location}.{field} must be a non-empty string")


def validate_report(data: Dict[str, Any]) -> None:
    """Validate the minimal v0.1 report schema."""
    errors: List[str] = []

    project = data.get("project")
    if not isinstance(project, dict):
        errors.append("project must be an object")
    else:
        for field in PROJECT_FIELDS:
            _validate_text(project, field, "project", errors)

    scope = data.get("scope")
    if not isinstance(scope, list):
        errors.append("scope must be an array")
    else:
        for index, asset in enumerate(scope):
            if not isinstance(asset, str) or not asset.strip():
                errors.append(f"scope[{index}] must be a non-empty string")

    _validate_text(data, "executive_summary", "report", errors)

    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
    else:
        seen_ids = set()
        for index, finding in enumerate(findings):
            location = f"findings[{index}]"
            if not isinstance(finding, dict):
                errors.append(f"{location} must be an object")
                continue

            for field in FINDING_FIELDS:
                _validate_text(finding, field, location, errors)

            finding_id = finding.get("id")
            if isinstance(finding_id, str) and finding_id.strip():
                normalized_id = finding_id.strip().casefold()
                if normalized_id in seen_ids:
                    errors.append(f"{location}.id duplicates finding ID {finding_id!r}")
                seen_ids.add(normalized_id)

            severity = finding.get("severity")
            if isinstance(severity, str) and severity not in SEVERITIES:
                errors.append(
                    f"{location}.severity must be one of: {', '.join(SEVERITIES)}"
                )

    if errors:
        raise ValidationError(errors)


def build_report(report_path: Path, output_path: Optional[Path] = None) -> Path:
    """Validate report JSON, sort findings, and render a self-contained HTML file."""
    source_path = report_path.expanduser().resolve()
    data = load_report(source_path)
    validate_report(data)

    render_data = copy.deepcopy(data)
    render_data["findings"] = sorted(
        render_data["findings"], key=lambda item: SEVERITY_RANK[item["severity"]]
    )

    if output_path is None:
        destination = source_path.parent / "output" / "report.html"
    else:
        destination = output_path.expanduser().resolve()
        if destination.suffix.lower() != ".html":
            raise PwnReportError("Output path must use the .html extension")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render_report(render_data), encoding="utf-8")
    except OSError as exc:
        raise PwnReportError(f"Could not write HTML report: {exc}") from exc

    return destination
