import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from pwnreport.core import (  # noqa: E402
    PwnReportError,
    build_exports,
    build_report,
    initialize_project,
    load_report,
)
from pwnreport.presentation import PresentationError, embedded_logo  # noqa: E402


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.report = initialize_project(self.workdir / "project")
        data = load_report(self.report)
        data["project"]["name"] = "Export Test"
        data["project"]["client"] = "Test Client"
        data["project"]["classification"] = "CONFIDENTIAL"
        data["project"]["assessment_type"] = "Web App"
        data["project"]["author"] = "Tester"
        data["scope"] = ["app.test", "api.test"]
        data["executive_summary"] = "A short summary."
        data["methodology"] = "A short methodology."
        data["limitations"] = "A short limitation."
        data["report"] = {
            "date": "2026-10-10",
            "version": "1.0",
            "template": "technical",
            "theme": "dark",
            "branding": {
                "company_name": "Test Company",
                "logo": "logo.png",
                "primary_color": "#ff0000",
                "secondary_color": "#00ff00",
            }
        }
        data["findings"] = [
            {
                "id": "FIND-001",
                "title": "Low Issue",
                "severity": "low",
                "affected_asset": "app.test",
                "description": "Low desc",
                "impact": "Low impact",
                "evidence": "Low evidence",
                "remediation": "Low remediation",
                "cvss_score": 3.0,
                "remediation_status": "open",
            },
            {
                "id": "FIND-002",
                "title": "Critical Issue",
                "severity": "critical",
                "affected_asset": "api.test",
                "description": "Crit desc",
                "impact": "Crit impact",
                "evidence": "Crit evidence",
                "remediation": "Crit remediation",
                "reproduction_steps": ["Step 1", "Step 2"],
                "references": ["CWE-1"],
                "source": {"tool": "nuclei", "source_id": "test", "file": "test.json"},
            }
        ]
        self.report.write_text(json.dumps(data), encoding="utf-8")
        
        # Create dummy logo
        logo_path = self.workdir / "project" / "logo.png"
        logo_path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRdummydata")

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, *arguments):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        return subprocess.run(
            [sys.executable, "-m", "pwnreport", *map(str, arguments)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )

    def test_build_all_formats(self):
        artifacts = build_exports(self.report, ["html", "pdf", "markdown"])
        self.assertEqual(len(artifacts), 3)
        self.assertTrue(artifacts["html"].is_file())
        self.assertTrue(artifacts["pdf"].is_file())
        self.assertTrue(artifacts["markdown"].is_file())

        html = artifacts["html"].read_text()
        self.assertIn("Export Test", html)
        self.assertIn("Test Company", html)
        self.assertIn("data:image/png;base64", html)
        self.assertIn("Table of Contents", html)
        self.assertIn("Methodology", html)

        md = artifacts["markdown"].read_text()
        self.assertIn("# Export Test", md)
        self.assertIn("## Table of Contents", md)
        self.assertIn("- [FIND-002: Critical Issue](#find-002-critical-issue)", md)

        pdf = artifacts["pdf"].read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"Table of Contents", pdf)
        self.assertIn(b"/Title (Export Test)", pdf)

    def test_executive_template_omits_details(self):
        artifacts = build_exports(self.report, ["html", "markdown"], template="executive")
        html = artifacts["html"].read_text()
        self.assertNotIn("Reproduction Steps", html)
        self.assertNotIn("Evidence", html)
        self.assertNotIn("Methodology", html)
        
        md = artifacts["markdown"].read_text()
        self.assertNotIn("Reproduction Steps", md)
        self.assertNotIn("Evidence", md)
        self.assertNotIn("Methodology", md)

    def test_light_theme_applies_colors(self):
        artifacts = build_exports(self.report, ["html"], theme="light")
        html = artifacts["html"].read_text()
        self.assertIn("color-scheme: light;", html)
        self.assertIn("--bg: #FFFFFF;", html)
        self.assertIn("--green: #ff0000;", html)

    def test_cli_build_all_outputs_multiple(self):
        result = self.run_cli("build", self.report, "--format", "all")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Built html:", result.stdout)
        self.assertIn("Built pdf:", result.stdout)
        self.assertIn("Built markdown:", result.stdout)

    def test_cli_build_template_override(self):
        result = self.run_cli("build", self.report, "--format", "markdown", "--template", "executive")
        self.assertEqual(result.returncode, 0)
        md_file = self.report.parent / "output" / "report.md"
        md = md_file.read_text()
        self.assertNotIn("Evidence", md)

    def test_missing_logo_fails_cleanly(self):
        logo_path = self.workdir / "project" / "logo.png"
        logo_path.unlink()
        data = load_report(self.report)
        data.setdefault("report", {})["branding"] = {"logo": "logo.png"}
        from pwnreport.presentation import effective_report_config
        with self.assertRaises(PresentationError):
            embedded_logo(self.workdir / "project", effective_report_config(data))

    def test_output_path_is_validated(self):
        with self.assertRaises(PwnReportError) as ctx:
            build_exports(self.report, ["html", "pdf"], output_path=self.report.parent / "custom.html")
        self.assertIn("can only be used with one", str(ctx.exception))

        with self.assertRaises(PwnReportError) as ctx:
            build_exports(self.report, ["pdf"], output_path=self.report.parent / "custom.txt")
        self.assertIn("must use the .pdf", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
