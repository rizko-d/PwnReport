"""Command-line interface for PwnReport."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, List, Optional

from . import __version__
from .constants import FINDING_FIELDS, REMEDIATION_STATUSES, SEVERITIES
from .core import (
    PwnReportError,
    add_finding,
    build_report,
    get_finding,
    initialize_project,
    list_findings,
    load_report,
    validate_report,
)

FIELD_LABELS = {
    "id": "ID",
    "title": "Title",
    "severity": "Severity",
    "affected_asset": "Affected asset",
    "description": "Description",
    "impact": "Impact",
    "evidence": "Evidence",
    "remediation": "Remediation",
    "reproduction_steps": "Reproduction steps",
    "references": "References",
    "cvss_vector": "CVSS vector",
    "cvss_score": "CVSS score",
    "remediation_status": "Remediation status",
}


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnreport",
        description="Manage JSON findings and build a self-contained HTML pentest report.",
    )
    parser.add_argument("--version", action="version", version=f"PwnReport {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create a minimal report workspace")
    init_parser.add_argument("destination", type=Path, help="directory to create")

    build_parser = subparsers.add_parser("build", help="validate JSON and build HTML")
    build_parser.add_argument("report", type=Path, help="path to report.json")
    build_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="HTML output path (default: <project>/output/report.html)",
    )

    validate_parser = subparsers.add_parser(
        "validate", help="validate a report without building HTML"
    )
    validate_parser.add_argument("report", type=Path, help="path to report.json")

    finding_parser = subparsers.add_parser("finding", help="manage report findings")
    finding_subparsers = finding_parser.add_subparsers(
        dest="finding_command", required=True
    )

    add_parser = finding_subparsers.add_parser("add", help="add a finding")
    add_parser.add_argument("report", type=Path, help="path to report.json")
    add_parser.add_argument("--title", help="finding title")
    add_parser.add_argument("--severity", choices=SEVERITIES, help="finding severity")
    add_parser.add_argument("--affected-asset", help="affected URL, host, or asset")
    add_parser.add_argument("--description", help="technical description")
    add_parser.add_argument("--impact", help="security or business impact")
    add_parser.add_argument("--evidence", help="concise supporting evidence")
    add_parser.add_argument("--remediation", help="recommended remediation")
    add_parser.add_argument("--reproduction-steps", help="comma-separated reproduction steps")
    add_parser.add_argument("--references", help="comma-separated references (CWE, CVE, URL)")
    add_parser.add_argument("--cvss-vector", help="CVSS vector string")
    add_parser.add_argument("--cvss-score", type=float, help="CVSS base score (0.0-10.0)")
    add_parser.add_argument("--remediation-status", choices=REMEDIATION_STATUSES, help="remediation status")

    list_parser = finding_subparsers.add_parser("list", help="list findings")
    list_parser.add_argument("report", type=Path, help="path to report.json")

    show_parser = finding_subparsers.add_parser("show", help="show one finding")
    show_parser.add_argument("report", type=Path, help="path to report.json")
    show_parser.add_argument("finding_id", help="finding ID, for example FIND-001")

    return parser


def _required_value(label: str, supplied: Optional[str]) -> str:
    if supplied is not None:
        value = supplied.strip()
    else:
        try:
            value = input(f"{label}: ").strip()
        except (EOFError, KeyboardInterrupt) as exc:
            raise PwnReportError(f"Input cancelled while reading {label.lower()}") from exc
    if not value:
        raise PwnReportError(f"{label} is required")
    return value


def _finding_input(args: argparse.Namespace) -> dict:
    finding = {
        "title": _required_value("Title", args.title),
        "severity": _required_value(
            f"Severity ({'/'.join(SEVERITIES)})", args.severity
        ).lower(),
        "affected_asset": _required_value("Affected asset", args.affected_asset),
        "description": _required_value("Description", args.description),
        "impact": _required_value("Impact", args.impact),
        "evidence": _required_value("Evidence", args.evidence),
        "remediation": _required_value("Remediation", args.remediation),
    }

    # Optional v0.3 fields from flags
    if args.reproduction_steps:
        finding["reproduction_steps"] = [
            s.strip() for s in args.reproduction_steps.split(",") if s.strip()
        ]
    if args.references:
        finding["references"] = [
            r.strip() for r in args.references.split(",") if r.strip()
        ]
    if args.cvss_vector:
        finding["cvss_vector"] = args.cvss_vector.strip()
    if args.cvss_score is not None:
        finding["cvss_score"] = args.cvss_score
    if args.remediation_status:
        finding["remediation_status"] = args.remediation_status

    return finding


def _print_field(label: str, value: Any) -> None:
    lines = str(value).splitlines() or [""]
    print(f"{label}: {lines[0]}")
    indentation = " " * (len(label) + 2)
    for line in lines[1:]:
        print(f"{indentation}{line}")


def _print_finding(finding: dict) -> None:
    for field in FINDING_FIELDS:
        if field in finding:
            _print_field(FIELD_LABELS[field], finding[field])


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            report_path = initialize_project(args.destination)
            print(f"Initialized PwnReport project: {report_path.parent}")
            print(f"Report data: {report_path}")
            print(f"Output directory: {report_path.parent / 'output'}")
            return 0

        if args.command == "build":
            data = load_report(args.report)
            validate_report(data)
            output_path = build_report(args.report, args.output)
            count = len(data["findings"])
            noun = "finding" if count == 1 else "findings"
            print(f"Validated {count} {noun}.")
            print(f"Built report: {output_path}")
            return 0

        if args.command == "validate":
            data = load_report(args.report)
            validate_report(data)
            count = len(data["findings"])
            noun = "finding" if count == 1 else "findings"
            print(f"Valid report: {args.report.expanduser().resolve()}")
            print(f"Findings: {count} {noun}")
            return 0

        if args.command == "finding":
            if args.finding_command == "add":
                finding = add_finding(args.report, _finding_input(args))
                print(f"Added finding {finding['id']}: {finding['title']}")
                return 0

            if args.finding_command == "list":
                findings = list_findings(args.report)
                if not findings:
                    print("No findings.")
                    return 0
                print(f"{'ID':<12} {'SEVERITY':<10} TITLE")
                for finding in findings:
                    print(
                        f"{finding['id']:<12} "
                        f"{finding['severity'].upper():<10} "
                        f"{finding['title']}"
                    )
                print(f"Total: {len(findings)}")
                return 0

            if args.finding_command == "show":
                _print_finding(get_finding(args.report, args.finding_id))
                return 0
    except PwnReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2
