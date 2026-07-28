import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from pwnreport.core import (  # noqa: E402
    PwnReportError,
    ValidationError,
    build_report,
    initialize_project,
    load_report,
    validate_report,
)


class PwnReportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_report(self, findings=None):
        report = {
            "project": {
                "name": "Assessment <2026>",
                "client": "ACME & Co.",
                "assessment_type": "Web Application",
                "classification": "CONFIDENTIAL",
                "author": "Rizko Febri Rachmayadi",
            },
            "scope": ["https://app.example.test"],
            "executive_summary": "Summary with <unsafe> text.",
            "findings": findings or [],
        }
        path = self.workdir / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def finding(self, finding_id, severity, title):
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "affected_asset": "https://app.example.test/login",
            "description": "Description",
            "impact": "Impact",
            "evidence": "Evidence",
            "remediation": "Remediation",
        }

    def test_initialize_project_creates_minimal_workspace(self):
        report_path = initialize_project(self.workdir / "demo-report")

        self.assertTrue(report_path.is_file())
        self.assertTrue((report_path.parent / "output").is_dir())
        data = load_report(report_path)
        validate_report(data)
        self.assertEqual(data["project"]["name"], "Demo Report")
        self.assertEqual(data["findings"], [])

    def test_initialize_project_refuses_to_overwrite_report(self):
        destination = self.workdir / "existing"
        destination.mkdir()
        (destination / "report.json").write_text("{}", encoding="utf-8")

        with self.assertRaises(PwnReportError):
            initialize_project(destination)

    def test_build_sorts_findings_and_escapes_html(self):
        path = self.make_report(
            [
                self.finding("FIND-002", "low", "Low issue"),
                self.finding("FIND-001", "critical", "Critical <issue>"),
                self.finding("FIND-003", "high", "High issue"),
            ]
        )

        output = build_report(path)
        html = output.read_text(encoding="utf-8")

        self.assertTrue(output.is_file())
        self.assertLess(html.index("Critical &lt;issue&gt;"), html.index("High issue"))
        self.assertLess(html.index("High issue"), html.index("Low issue"))
        self.assertIn("Assessment &lt;2026&gt;", html)
        self.assertIn("ACME &amp; Co.", html)
        self.assertIn('<meta name="generator" content="PwnReport 0.1.0">', html)
        self.assertIn('<span class="metric-value">1</span>', html)

    def test_build_empty_report_renders_empty_state(self):
        output = build_report(self.make_report())
        html = output.read_text(encoding="utf-8")
        self.assertIn("No findings", html)
        self.assertIn("0 findings recorded", html)

    def test_validation_rejects_missing_fields_invalid_severity_and_duplicate_ids(self):
        data = {
            "project": {},
            "scope": [""],
            "executive_summary": "",
            "findings": [
                {"id": "FIND-001", "severity": "urgent"},
                {"id": "find-001", "severity": "high"},
            ],
        }

        with self.assertRaises(ValidationError) as context:
            validate_report(data)

        message = str(context.exception)
        self.assertIn("project.name", message)
        self.assertIn("scope[0]", message)
        self.assertIn("findings[0].severity", message)
        self.assertIn("duplicates finding ID", message)

    def test_load_report_rejects_invalid_json(self):
        path = self.workdir / "broken.json"
        path.write_text('{"project":', encoding="utf-8")

        with self.assertRaises(PwnReportError) as context:
            load_report(path)

        self.assertIn("Invalid JSON", str(context.exception))

    def test_build_rejects_non_html_output(self):
        path = self.make_report()
        with self.assertRaises(PwnReportError):
            build_report(path, self.workdir / "report.txt")

    def test_module_cli_init_and_build(self):
        project_dir = self.workdir / "cli-demo"
        env = {"PYTHONPATH": str(SRC)}

        init = subprocess.run(
            [sys.executable, "-m", "pwnreport", "init", str(project_dir)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertIn("Initialized PwnReport project", init.stdout)

        build = subprocess.run(
            [sys.executable, "-m", "pwnreport", "build", str(project_dir / "report.json")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        self.assertTrue((project_dir / "output" / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()
