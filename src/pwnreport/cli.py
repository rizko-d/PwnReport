"""Command-line interface for PwnReport."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .core import PwnReportError, build_report, initialize_project, load_report, validate_report


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnreport",
        description="Build a self-contained HTML pentest report from JSON.",
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

    return parser


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
    except PwnReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2
