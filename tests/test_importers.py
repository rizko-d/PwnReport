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
FIXTURES = ROOT / "tests" / "fixtures" / "importers"
sys.path.insert(0, str(SRC))

from pwnreport.core import (  # noqa: E402
    PwnReportError,
    build_report,
    import_findings,
    initialize_project,
    load_report,
)
from pwnreport.importers import ImporterError, parse_import  # noqa: E402


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.report = initialize_project(self.workdir / "project")

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

    def test_nuclei_jsonl_parser(self):
        findings = parse_import("nuclei", FIXTURES / "nuclei.jsonl")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["title"], "Missing CSP Header")
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["cvss_score"], 6.1)
        self.assertIn("CWE-693", findings[0]["references"])
        self.assertEqual(findings[0]["source"]["tool"], "nuclei")
        self.assertIn("Request:", findings[1]["evidence"])

    def test_burp_xml_parser_decodes_request_response(self):
        findings = parse_import("burp", FIXTURES / "burp.xml")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["title"], "Reflected cross-site scripting")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(
            finding["affected_asset"], "https://app.example.test/search?q=test"
        )
        self.assertIn("GET /search?q=test HTTP/1.1", finding["evidence"])
        self.assertIn("HTTP/1.1 200 OK", finding["evidence"])

    def test_burp_parser_accepts_wrapped_base64(self):
        source = self.workdir / "wrapped-burp.xml"
        source.write_text(
            "<issues><issue><name>Issue</name><severity>Low</severity>"
            "<host>https://example.test</host><issueDetail>Detail</issueDetail>"
            "<remediationDetail>Fix</remediationDetail><requestresponse>"
            '<request base64="true">R0VUIC8g\nSFRUUC8xLjE=</request>'
            "</requestresponse></issue></issues>",
            encoding="utf-8",
        )
        finding = parse_import("burp", source)[0]
        self.assertIn("GET / HTTP/1.1", finding["evidence"])

    def test_nmap_xml_parser_imports_only_open_ports(self):
        findings = parse_import("nmap", FIXTURES / "nmap.xml")
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            [finding["affected_asset"] for finding in findings],
            ["web.example.test:22/tcp", "web.example.test:443/tcp"],
        )
        self.assertTrue(all(finding["severity"] == "info" for finding in findings))
        self.assertIn("OpenSSH 9.6", findings[0]["evidence"])
        self.assertIn("http-title: Example App", findings[1]["evidence"])

    def test_nessus_parser_preserves_cvss_and_references(self):
        findings = parse_import("nessus", FIXTURES / "nessus.xml")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["affected_asset"], "db.example.test:5432/tcp")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["cvss_score"], 8.1)
        self.assertIn("CVE-2024-0001", finding["references"])
        self.assertIn("CWE-1104", finding["references"])
        self.assertIn("PostgreSQL 10 detected", finding["evidence"])

    def test_custom_parser_supports_aliases_and_v03_fields(self):
        findings = parse_import("custom", FIXTURES / "custom.json")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["title"], "Default credentials")
        self.assertEqual(finding["affected_asset"], "router.example.test")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["reproduction_steps"][0], "Open login page")
        self.assertEqual(finding["cvss_score"], 9.8)
        self.assertEqual(finding["remediation_status"], "open")

    def test_custom_parser_preserves_zero_cvss_score(self):
        source = self.workdir / "zero-score.json"
        source.write_text(
            json.dumps({
                "title": "Informational check",
                "severity": "info",
                "affected_asset": "host",
                "description": "Description",
                "evidence": "Evidence",
                "remediation": "Review",
                "cvss_score": 0,
            }),
            encoding="utf-8",
        )
        finding = parse_import("custom", source)[0]
        self.assertEqual(finding["cvss_score"], 0.0)

    def test_import_transaction_assigns_ids_and_preserves_source(self):
        result = import_findings(self.report, "nuclei", FIXTURES / "nuclei.jsonl")
        data = load_report(self.report)
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            [finding["id"] for finding in data["findings"]],
            ["FIND-001", "FIND-002"],
        )
        archived = Path(result["source"])
        self.assertTrue(archived.is_file())
        self.assertEqual(archived.read_bytes(), (FIXTURES / "nuclei.jsonl").read_bytes())
        for finding in data["findings"]:
            self.assertEqual(finding["source"]["tool"], "nuclei")
            self.assertEqual(finding["source"]["file"], "imports/nuclei/nuclei.jsonl")

    def test_second_import_continues_ids_and_does_not_overwrite_archive(self):
        first = import_findings(self.report, "custom", FIXTURES / "custom.json")
        second = import_findings(self.report, "custom", FIXTURES / "custom.json")
        data = load_report(self.report)
        self.assertEqual([item["id"] for item in data["findings"]], ["FIND-001", "FIND-002"])
        self.assertEqual(Path(first["source"]).name, "custom.json")
        self.assertEqual(Path(second["source"]).name, "custom-2.json")
        self.assertTrue(Path(first["source"]).is_file())
        self.assertTrue(Path(second["source"]).is_file())

    def test_imported_findings_build_into_html(self):
        import_findings(self.report, "nessus", FIXTURES / "nessus.xml")
        html = build_report(self.report).read_text(encoding="utf-8")
        self.assertIn("Outdated PostgreSQL", html)
        self.assertIn("8.1", html)
        self.assertIn("CVE-2024-0001", html)
        self.assertIn("Source Tool", html)
        self.assertIn("nessus", html)
        self.assertIn("imports/nessus/nessus.xml", html)

    def test_invalid_source_does_not_change_report_or_create_archive(self):
        invalid = self.workdir / "invalid.json"
        invalid.write_text('{"broken":', encoding="utf-8")
        before = hashlib.sha256(self.report.read_bytes()).hexdigest()
        with self.assertRaises(PwnReportError):
            import_findings(self.report, "custom", invalid)
        after = hashlib.sha256(self.report.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertFalse((self.report.parent / "imports").exists())

    def test_report_save_failure_removes_new_archive(self):
        before = self.report.read_bytes()
        with mock.patch("pwnreport.core.save_report", side_effect=PwnReportError("fail")):
            with self.assertRaises(PwnReportError):
                import_findings(self.report, "custom", FIXTURES / "custom.json")
        self.assertEqual(self.report.read_bytes(), before)
        archives = list((self.report.parent / "imports" / "custom").glob("*.json"))
        self.assertEqual(archives, [])

    def test_xml_doctype_is_rejected(self):
        malicious = self.workdir / "doctype.xml"
        malicious.write_text(
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<issues><issue><name>&xxe;</name></issue></issues>",
            encoding="utf-8",
        )
        with self.assertRaises(ImporterError) as context:
            parse_import("burp", malicious)
        self.assertIn("DOCTYPE", str(context.exception))

    def test_empty_export_is_rejected(self):
        empty = self.workdir / "empty.json"
        empty.write_text("", encoding="utf-8")
        with self.assertRaises(ImporterError):
            parse_import("custom", empty)

    def test_cli_import_custom(self):
        result = self.run_cli("import", "custom", self.report, FIXTURES / "custom.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Imported 1 findings from custom (FIND-001)", result.stdout)
        self.assertIn("Preserved source:", result.stdout)
        self.assertEqual(len(load_report(self.report)["findings"]), 1)
        shown = self.run_cli("finding", "show", self.report, "FIND-001")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("Source tool: custom", shown.stdout)
        self.assertIn("Source ID: scanner-42", shown.stdout)
        self.assertIn("Source file: imports/custom/custom.json", shown.stdout)

    def test_cli_import_nmap_reports_id_range(self):
        result = self.run_cli("import", "nmap", self.report, FIXTURES / "nmap.xml")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FIND-001..FIND-002", result.stdout)
        self.assertEqual(len(load_report(self.report)["findings"]), 2)

    def test_cli_import_invalid_returns_one(self):
        invalid = self.workdir / "bad.json"
        invalid.write_text("not-json", encoding="utf-8")
        result = self.run_cli("import", "custom", self.report, invalid)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid custom JSON", result.stderr)
        self.assertEqual(load_report(self.report)["findings"], [])


if __name__ == "__main__":
    unittest.main()
