import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from pwnreport.core import add_finding, initialize_project, load_report
from pwnreport.library import _get_db_path, get_from_library, save_to_library, search_library
from pwnreport.workspace import list_projects


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workdir = Path(self.temp_dir.name)
        self.lib_dir = self.workdir / ".pwnreport"
        
        # Override default library dir for tests
        self.patcher1 = mock.patch('pwnreport.library.DEFAULT_LIBRARY_DIR', self.lib_dir)
        self.patcher3 = mock.patch('pwnreport.webui._get_db_path', return_value=self.lib_dir / "library.db")
        self.patcher1.start()
        self.patcher3.start()

    def tearDown(self):
        self.patcher1.stop()
        self.patcher3.stop()
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

    def test_workspace_project_registration(self):
        # Creating a project should register it
        proj1 = self.workdir / "proj1"
        report1 = initialize_project(proj1)
        
        projects = list_projects(self.lib_dir)
        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0]["name"], "Proj1")
        self.assertEqual(projects[0]["findings_count"], 0)

        # Adding a finding should update the count
        add_finding(report1, {
            "title": "SQLi", "severity": "high", "affected_asset": "host",
            "description": "D", "impact": "I", "evidence": "E", "remediation": "R"
        })
        
        projects = list_projects(self.lib_dir)
        self.assertEqual(projects[0]["findings_count"], 1)

    def test_workspace_cleans_up_deleted_projects(self):
        proj1 = self.workdir / "proj1"
        initialize_project(proj1)
        self.assertEqual(len(list_projects(self.lib_dir)), 1)
        
        import shutil
        shutil.rmtree(proj1)
        
        # Should be empty now
        self.assertEqual(len(list_projects(self.lib_dir)), 0)

    def test_library_save_and_retrieve(self):
        proj1 = self.workdir / "proj1"
        report1 = initialize_project(proj1)
        f = add_finding(report1, {
            "title": "SQLi", "severity": "high", "affected_asset": "host",
            "description": "D", "impact": "I", "evidence": "E", "remediation": "R",
            "cvss_score": 9.0
        })
        
        lib_id = save_to_library(f, self.lib_dir)
        self.assertEqual(lib_id, "LIB-001")
        
        # Retrieve it back
        retrieved = get_from_library("LIB-001", self.lib_dir)
        self.assertEqual(retrieved["title"], "SQLi")
        self.assertEqual(retrieved["cvss_score"], 9.0)

    def test_library_search(self):
        f1 = {
            "id": "FIND-001", "title": "Cross-Site Scripting", "severity": "medium", 
            "affected_asset": "host", "description": "Stored XSS", "impact": "I", 
            "evidence": "E", "remediation": "R"
        }
        f2 = {
            "id": "FIND-002", "title": "SQL Injection", "severity": "critical", 
            "affected_asset": "host", "description": "Blind SQLi", "impact": "I", 
            "evidence": "E", "remediation": "R"
        }
        save_to_library(f1, self.lib_dir)
        save_to_library(f2, self.lib_dir)
        
        # Search by exact word
        res = search_library("Cross-Site", self.lib_dir)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["title"], "Cross-Site Scripting")
        
        # Search by partial
        res = search_library("SQL*", self.lib_dir)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["title"], "SQL Injection")

    def test_cli_library_save_and_import(self):
        import uuid
        test_title = f"Test Vuln {uuid.uuid4()}"
        proj1 = self.workdir / "proj1"
        report1 = initialize_project(proj1)
        self.run_cli("finding", "add", report1, "--title", test_title, "--severity", "low", "--affected-asset", "h", "--description", "d", "--impact", "i", "--evidence", "e", "--remediation", "r")
        
        # CLI commands run in a subprocess and don't see the mock, 
        # but this unique title avoids the "already exists" error in ~/.pwnreport
        save = self.run_cli("library", "save", report1, "FIND-001")
        self.assertEqual(save.returncode, 0, save.stderr)
        self.assertIn("Saved FIND-001 to library as LIB-", save.stdout)
        
        # Extract the saved library ID from stdout (e.g. "Saved FIND-001 to library as LIB-001.")
        lib_id = save.stdout.strip().split()[-1].strip(".")
        
        proj2 = self.workdir / "proj2"
        report2 = initialize_project(proj2)
        
        imp = self.run_cli("library", "import", report2, lib_id, "--affected-asset", "new-host.com")
        self.assertEqual(imp.returncode, 0, imp.stderr)
        self.assertIn(f"Imported {lib_id} as FIND-001", imp.stdout)
        
        data = load_report(report2)
        self.assertEqual(data["findings"][0]["title"], test_title)
        self.assertEqual(data["findings"][0]["affected_asset"], "new-host.com")
        self.assertEqual(data["findings"][0]["evidence"], "Verified manually.")


    def test_cli_project_list(self):
        report = initialize_project(self.workdir / "projX")
        self.run_cli("finding", "add", report, "--title", "V", "--severity", "low", "--affected-asset", "h", "--description", "d", "--impact", "i", "--evidence", "e", "--remediation", "r")
        
        ls = self.run_cli("project", "list")
        self.assertEqual(ls.returncode, 0)
        self.assertIn("Projx", ls.stdout)
        self.assertIn("1", ls.stdout)  # findings count


if __name__ == "__main__":
    unittest.main()
