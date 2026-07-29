"""Project initialization, validation, finding operations, and building."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import (
    FINDING_FIELDS,
    PROJECT_FIELDS,
    REMEDIATION_STATUSES,
    REQUIRED_FINDING_FIELDS,
    SEVERITIES,
    SEVERITY_RANK,
)
from .importers import ImporterError, parse_import
from .renderer import render_report

FINDING_ID_PATTERN = re.compile(r"^FIND-(\d+)$", re.IGNORECASE)


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
        "methodology": "",
        "limitations": "",
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


def _validate_text(
    container: Dict[str, Any], field: str, location: str, errors: List[str]
) -> None:
    value = container.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{location}.{field} must be a non-empty string")


def validate_report(data: Dict[str, Any]) -> None:
    """Validate the PwnReport JSON schema."""
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

            for field in REQUIRED_FINDING_FIELDS:
                _validate_text(finding, field, location, errors)

            # Validate optional finding fields when present
            steps = finding.get("reproduction_steps")
            if steps is not None:
                if not isinstance(steps, list):
                    errors.append(f"{location}.reproduction_steps must be an array")
                else:
                    for i, step in enumerate(steps):
                        if not isinstance(step, str):
                            errors.append(
                                f"{location}.reproduction_steps[{i}] must be a string"
                            )

            refs = finding.get("references")
            if refs is not None:
                if not isinstance(refs, list):
                    errors.append(f"{location}.references must be an array")
                else:
                    for i, ref in enumerate(refs):
                        if not isinstance(ref, str):
                            errors.append(
                                f"{location}.references[{i}] must be a string"
                            )

            cvss_score = finding.get("cvss_score")
            if cvss_score is not None:
                try:
                    score = float(cvss_score)
                    if score < 0.0 or score > 10.0:
                        errors.append(
                            f"{location}.cvss_score must be between 0.0 and 10.0"
                        )
                except (TypeError, ValueError):
                    errors.append(
                        f"{location}.cvss_score must be a numeric value"
                    )

            rem_status = finding.get("remediation_status")
            if rem_status is not None:
                if not isinstance(rem_status, str) or not rem_status.strip():
                    errors.append(
                        f"{location}.remediation_status must be a non-empty string"
                    )
                elif rem_status.strip().lower() not in REMEDIATION_STATUSES:
                    errors.append(
                        f"{location}.remediation_status must be one of: "
                        + ", ".join(REMEDIATION_STATUSES)
                    )

            source = finding.get("source")
            if source is not None:
                if not isinstance(source, dict):
                    errors.append(f"{location}.source must be an object")
                else:
                    tool = source.get("tool")
                    if not isinstance(tool, str) or not tool.strip():
                        errors.append(f"{location}.source.tool must be a non-empty string")
                    for key in ("source_id", "file"):
                        value = source.get(key)
                        if value is not None and not isinstance(value, str):
                            errors.append(f"{location}.source.{key} must be a string")

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


def save_report(report_path: Path, data: Dict[str, Any]) -> Path:
    """Validate and atomically replace a report JSON file.

    The temporary file is created beside the destination so ``os.replace`` is
    atomic on the same filesystem. Unknown schema keys are retained because the
    complete loaded document is written back after the requested change.
    """
    destination = report_path.expanduser().resolve()
    validate_report(data)

    if not destination.is_file():
        raise PwnReportError(f"Report file not found: {destination}")

    temporary_path: Optional[Path] = None
    try:
        original_mode = stat.S_IMODE(destination.stat().st_mode)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(destination.parent),
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, destination)
    except OSError as exc:
        raise PwnReportError(f"Could not safely update report: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return destination


def next_finding_id(findings: List[Dict[str, Any]]) -> str:
    """Return the next monotonically increasing ``FIND-NNN`` identifier."""
    highest = 0
    for finding in findings:
        finding_id = finding.get("id")
        if not isinstance(finding_id, str):
            continue
        match = FINDING_ID_PATTERN.fullmatch(finding_id.strip())
        if match:
            highest = max(highest, int(match.group(1)))
    return f"FIND-{highest + 1:03d}"


def add_finding(report_path: Path, finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """Append a validated finding and atomically save the report."""
    source_path = report_path.expanduser().resolve()
    data = load_report(source_path)
    validate_report(data)

    finding: Dict[str, Any] = {
        "id": next_finding_id(data["findings"]),
        "title": finding_data.get("title", "").strip(),
        "severity": finding_data.get("severity", "").strip().lower(),
        "affected_asset": finding_data.get("affected_asset", "").strip(),
        "description": finding_data.get("description", "").strip(),
        "impact": finding_data.get("impact", "").strip(),
        "evidence": finding_data.get("evidence", "").strip(),
        "remediation": finding_data.get("remediation", "").strip(),
    }

    # Optional v0.3 fields
    if "reproduction_steps" in finding_data:
        steps = finding_data["reproduction_steps"]
        if isinstance(steps, list):
            finding["reproduction_steps"] = steps
    if "references" in finding_data:
        refs = finding_data["references"]
        if isinstance(refs, list):
            finding["references"] = refs
    if "cvss_vector" in finding_data:
        vector = finding_data["cvss_vector"]
        if isinstance(vector, str) and vector.strip():
            finding["cvss_vector"] = vector.strip()
    if "cvss_score" in finding_data:
        score = finding_data["cvss_score"]
        if score is not None:
            finding["cvss_score"] = float(score)
    if "remediation_status" in finding_data:
        status = finding_data["remediation_status"]
        if isinstance(status, str) and status.strip():
            finding["remediation_status"] = status.strip().lower()

    updated_data = copy.deepcopy(data)
    updated_data["findings"].append(finding)
    save_report(source_path, updated_data)
    return finding


def _import_archive_path(report_path: Path, tool: str, source: Path) -> Path:
    """Return a non-overwriting path under imports/<tool>/ for the source export."""
    directory = report_path.parent / "imports" / tool
    directory.mkdir(parents=True, exist_ok=True)
    name = source.name or f"{tool}-import"
    candidate = directory / name
    counter = 2
    while candidate.exists():
        candidate = directory / f"{source.stem}-{counter}{source.suffix}"
        counter += 1
    return candidate


def _atomic_copy_import(source: Path, destination: Path) -> Path:
    """Copy an import source atomically without overwriting an existing archive."""
    temporary: Optional[Path] = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(destination.parent),
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        shutil.copyfile(source, temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except OSError as exc:
        raise PwnReportError(f"Could not preserve import source: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
    return destination


def import_findings(report_path: Path, tool: str, source_path: Path) -> Dict[str, Any]:
    """Parse, normalize, archive, and atomically append scanner findings."""
    report = report_path.expanduser().resolve()
    source = source_path.expanduser().resolve()
    data = load_report(report)
    validate_report(data)

    try:
        parsed = parse_import(tool, source)
    except ImporterError as exc:
        raise PwnReportError(str(exc)) from exc

    updated = copy.deepcopy(data)
    assigned: List[Dict[str, Any]] = []
    next_number = int(next_finding_id(updated["findings"]).split("-")[1])
    for offset, raw_finding in enumerate(parsed):
        finding = copy.deepcopy(raw_finding)
        finding["id"] = f"FIND-{next_number + offset:03d}"
        assigned.append(finding)
        updated["findings"].append(finding)

    # Validate the entire combined report before any side effect occurs.
    validate_report(updated)
    archive = _import_archive_path(report, tool, source)
    relative_archive = archive.relative_to(report.parent).as_posix()
    for finding in assigned:
        source_meta = finding.setdefault("source", {"tool": tool})
        source_meta["file"] = relative_archive

    # Validate provenance added above before publishing files.
    validate_report(updated)
    _atomic_copy_import(source, archive)
    try:
        save_report(report, updated)
    except Exception:
        try:
            archive.unlink()
        except OSError:
            pass
        raise

    return {
        "tool": tool,
        "count": len(assigned),
        "findings": assigned,
        "source": archive,
    }


def list_findings(report_path: Path) -> List[Dict[str, Any]]:
    """Return validated findings in report severity order."""
    data = load_report(report_path)
    validate_report(data)
    return sorted(
        copy.deepcopy(data["findings"]),
        key=lambda item: (SEVERITY_RANK[item["severity"]], item["id"].casefold()),
    )


def get_finding(report_path: Path, finding_id: str) -> Dict[str, Any]:
    """Return one finding by case-insensitive identifier."""
    data = load_report(report_path)
    validate_report(data)
    requested_id = finding_id.strip().casefold()
    for finding in data["findings"]:
        if finding["id"].casefold() == requested_id:
            return copy.deepcopy(finding)
    raise PwnReportError(f"Finding not found: {finding_id}")


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
