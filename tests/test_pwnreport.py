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
    ValidationError,
    add_finding,
    build_report,
    get_finding,
    initialize_project,
    list_findings,
    load_report,
    next_finding_id,
    save_report,
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

    def finding(self, finding_id="FIND-001", severity="medium", title="Issue"):
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

    def finding_input(self, **overrides):
        data = self.finding()
        data.pop("id")
        data.update(overrides)
        return data

    def run_cli(self, *arguments, input_text=None):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC)
        return subprocess.run(
            [sys.executable, "-m", "pwnreport", *map(str, arguments)],
            cwd=ROOT,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
        )

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
        self.assertIn('<meta name="generator" content="PwnReport 0.2.0">', html)
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

    def test_next_finding_id_uses_highest_numeric_identifier(self):
        findings = [
            self.finding("FIND-001"),
            self.finding("CUSTOM-99"),
            self.finding("find-010"),
            self.finding("FIND-003"),
        ]
        self.assertEqual(next_finding_id(findings), "FIND-011")
        self.assertEqual(next_finding_id([]), "FIND-001")

    def test_add_finding_assigns_id_and_preserves_unknown_fields(self):
        path = self.make_report([self.finding("FIND-004")])
        data = load_report(path)
        data["custom_metadata"] = {"ticket": "SEC-42"}
        path.write_text(json.dumps(data), encoding="utf-8")

        added = add_finding(path, self.finding_input(title="New issue", severity="HIGH"))
        saved = load_report(path)

        self.assertEqual(added["id"], "FIND-005")
        self.assertEqual(added["severity"], "high")
        self.assertEqual(saved["findings"][-1], added)
        self.assertEqual(saved["custom_metadata"], {"ticket": "SEC-42"})
        self.assertTrue(path.read_text(encoding="utf-8").endswith("\n"))
        self.assertEqual(list(path.parent.glob(".report.json.*.tmp")), [])

    def test_add_invalid_finding_does_not_change_report(self):
        path = self.make_report()
        original = path.read_bytes()

        with self.assertRaises(ValidationError):
            add_finding(path, self.finding_input(title=""))

        self.assertEqual(path.read_bytes(), original)

    def test_atomic_save_failure_preserves_original_report(self):
        path = self.make_report()
        original = path.read_bytes()
        data = load_report(path)
        data["executive_summary"] = "Updated summary"

        with mock.patch("pwnreport.core.os.replace", side_effect=OSError("simulated")):
            with self.assertRaises(PwnReportError):
                save_report(path, data)

        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(list(path.parent.glob(".report.json.*.tmp")), [])

    def test_atomic_save_preserves_file_permissions(self):
        path = self.make_report()
        path.chmod(0o640)
        data = load_report(path)
        data["executive_summary"] = "Updated summary"

        save_report(path, data)

        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_list_findings_uses_severity_order_without_mutating_file(self):
        original_findings = [
            self.finding("FIND-002", "low", "Low issue"),
            self.finding("FIND-003", "critical", "Critical issue"),
            self.finding("FIND-001", "high", "High issue"),
        ]
        path = self.make_report(original_findings)

        listed = list_findings(path)

        self.assertEqual(
            [finding["id"] for finding in listed],
            ["FIND-003", "FIND-001", "FIND-002"],
        )
        self.assertEqual(load_report(path)["findings"], original_findings)

    def test_get_finding_is_case_insensitive_and_reports_missing_id(self):
        path = self.make_report([self.finding("FIND-007", title="Target finding")])
        self.assertEqual(get_finding(path, "find-007")["title"], "Target finding")
        with self.assertRaises(PwnReportError) as context:
            get_finding(path, "FIND-999")
        self.assertIn("Finding not found", str(context.exception))

    def test_cli_init_validate_and_build(self):
        project_dir = self.workdir / "cli-demo"

        init = self.run_cli("init", project_dir)
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertIn("Initialized PwnReport project", init.stdout)

        validate = self.run_cli("validate", project_dir / "report.json")
        self.assertEqual(validate.returncode, 0, validate.stderr)
        self.assertIn("Valid report", validate.stdout)
        self.assertIn("Findings: 0 findings", validate.stdout)

        build = self.run_cli("build", project_dir / "report.json")
        self.assertEqual(build.returncode, 0, build.stderr)
        self.assertTrue((project_dir / "output" / "report.html").is_file())

    def test_cli_finding_add_list_and_show_with_flags(self):
        report_path = initialize_project(self.workdir / "cli-findings")
        add = self.run_cli(
            "finding",
            "add",
            report_path,
            "--title",
            "Missing CSP",
            "--severity",
            "high",
            "--affected-asset",
            "https://app.example.test",
            "--description",
            "Header is missing",
            "--impact",
            "Client-side protections are reduced",
            "--evidence",
            "Response omitted Content-Security-Policy",
            "--remediation",
            "Deploy a restrictive CSP",
        )
        self.assertEqual(add.returncode, 0, add.stderr)
        self.assertIn("Added finding FIND-001: Missing CSP", add.stdout)

        list_result = self.run_cli("finding", "list", report_path)
        self.assertEqual(list_result.returncode, 0, list_result.stderr)
        self.assertIn("FIND-001", list_result.stdout)
        self.assertIn("HIGH", list_result.stdout)
        self.assertIn("Missing CSP", list_result.stdout)
        self.assertIn("Total: 1", list_result.stdout)

        show = self.run_cli("finding", "show", report_path, "find-001")
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertIn("ID: FIND-001", show.stdout)
        self.assertIn("Title: Missing CSP", show.stdout)
        self.assertIn("Severity: high", show.stdout)

    def test_cli_finding_add_prompts_for_missing_fields(self):
        report_path = initialize_project(self.workdir / "interactive")
        input_text = "\n".join(
            [
                "Interactive issue",
                "medium",
                "api.example.test",
                "Description",
                "Impact",
                "Evidence",
                "Remediation",
            ]
        ) + "\n"

        result = self.run_cli("finding", "add", report_path, input_text=input_text)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Added finding FIND-001", result.stdout)
        self.assertEqual(load_report(report_path)["findings"][0]["severity"], "medium")

    def test_cli_validate_invalid_report_returns_nonzero(self):
        path = self.workdir / "invalid.json"
        path.write_text("{}", encoding="utf-8")

        result = self.run_cli("validate", path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Report validation failed", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_cli_list_empty_and_show_missing(self):
        report_path = initialize_project(self.workdir / "empty")

        listed = self.run_cli("finding", "list", report_path)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(listed.stdout.strip(), "No findings.")

        shown = self.run_cli("finding", "show", report_path, "FIND-001")
        self.assertEqual(shown.returncode, 1)
        self.assertIn("Finding not found", shown.stderr)


if __name__ == "__main__":
    unittest.main()
