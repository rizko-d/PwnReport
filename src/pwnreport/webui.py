"""Lightweight local web interface for PwnReport."""

from __future__ import annotations

import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List

from .library import _get_db_path, _init_db
from .workspace import _init_workspace_db


def _get_html_template() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PwnReport Workspace</title>
    <style>
        :root {
            --bg: #0d1117;
            --panel: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --muted: #8b949e;
            --primary: #58a6ff;
            --critical: #ff7b72;
            --high: #d29922;
            --medium: #d2a8ff;
            --low: #a5d6ff;
            --info: #8b949e;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.5;
        }
        header {
            background-color: var(--panel);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        h1, h2, h3 { color: #fff; }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px;
        }
        .grid {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 32px;
        }
        .card {
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .nav-link {
            display: block;
            padding: 8px 12px;
            color: var(--text);
            text-decoration: none;
            border-radius: 6px;
        }
        .nav-link:hover { background-color: var(--border); }
        .nav-link.active {
            background-color: var(--primary);
            color: #fff;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            border: 1px solid currentColor;
        }
        .badge.critical { color: var(--critical); }
        .badge.high { color: var(--high); }
        .badge.medium { color: var(--medium); }
        .badge.low { color: var(--low); }
        .badge.info { color: var(--info); }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
        
        .finding-detail { margin-top: 16px; padding-top: 16px; border-top: 1px dashed var(--border); }
        .finding-detail pre { 
            background: #0a0c10; 
            padding: 12px; 
            border-radius: 6px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <header>
        <h2>PwnReport Workspace</h2>
    </header>
    <div class="container">
        <div class="grid">
            <nav>
                <div class="card">
                    <a href="/" class="nav-link {nav_projects}">Projects</a>
                    <a href="/library" class="nav-link {nav_library}">Finding Library</a>
                </div>
            </nav>
            <main>
                {content}
            </main>
        </div>
    </div>
</body>
</html>
"""


class WebUIHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass  # Quiet mode

    def do_GET(self) -> None:
        if self.path == "/":
            self._render_projects()
        elif self.path == "/library":
            self._render_library()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def _render_projects(self) -> None:
        db_path = _get_db_path()
        content = "<h2>Recent Projects</h2>"
        
        if not db_path.exists():
            content += "<p>No projects registered yet. Run <code>pwnreport init</code> to start.</p>"
        else:
            with sqlite3.connect(db_path) as conn:
                _init_workspace_db(conn)
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT * FROM projects ORDER BY last_accessed DESC LIMIT 50")
                rows = cur.fetchall()
                
                if not rows:
                    content += "<p>No projects registered yet.</p>"
                else:
                    content += "<table><tr><th>Project</th><th>Client</th><th>Findings</th><th>Path</th></tr>"
                    for row in rows:
                        content += f"""
                        <tr>
                            <td><strong>{html.escape(row['name'])}</strong></td>
                            <td>{html.escape(row['client'])}</td>
                            <td>{row['findings_count']}</td>
                            <td><code style="font-size:12px;color:var(--muted)">{html.escape(row['path'])}</code></td>
                        </tr>
                        """
                    content += "</table>"

        html_out = _get_html_template().replace("{nav_projects}", "active").replace("{nav_library}", "").replace("{content}", content)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html_out.encode("utf-8"))

    def _render_library(self) -> None:
        db_path = _get_db_path()
        content = "<h2>Finding Library</h2>"
        
        if not db_path.exists():
            content += "<p>Library is empty. Use <code>pwnreport library save</code> to add reusable findings.</p>"
        else:
            with sqlite3.connect(db_path) as conn:
                _init_db(conn)
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 100")
                rows = cur.fetchall()
                
                if not rows:
                    content += "<p>Library is empty.</p>"
                else:
                    for row in rows:
                        sev = row["severity"].lower()
                        content += f"""
                        <div class="card">
                            <div style="display:flex;justify-content:space-between;align-items:center;">
                                <h3 style="margin:0">LIB-{row['id']:03d}: {html.escape(row['title'])}</h3>
                                <span class="badge {sev}">{sev.upper()}</span>
                            </div>
                            <div class="finding-detail">
                                <p style="color:var(--muted);font-size:13px;margin:0 0 8px 0"><strong>Description:</strong></p>
                                <p style="margin:0 0 16px 0;font-size:14px">{html.escape(row['description']).replace(chr(10), '<br>')}</p>
                                
                                <p style="color:var(--muted);font-size:13px;margin:0 0 8px 0"><strong>Remediation:</strong></p>
                                <p style="margin:0;font-size:14px">{html.escape(row['remediation']).replace(chr(10), '<br>')}</p>
                            </div>
                        </div>
                        """

        html_out = _get_html_template().replace("{nav_projects}", "").replace("{nav_library}", "active").replace("{content}", content)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html_out.encode("utf-8"))


def start_server(port: int = 8080) -> None:
    """Start the local UI server."""
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, WebUIHandler)
    print(f"PwnReport Web UI running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()
