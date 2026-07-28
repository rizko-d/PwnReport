# PwnReport

PwnReport is a lightweight command-line tool for turning penetration testing
results into a consistent, client-readable security assessment report.

It is designed for security consultants, penetration testers, and developers
who already have assessment notes or findings and need a simple way to format,
validate, and publish them. PwnReport keeps the source data structured in JSON
and produces an offline HTML report with a professional dark theme.

PwnReport is a reporting tool, not a vulnerability scanner. It does not scan
targets, exploit vulnerabilities, collect credentials, or replace tools such
as Nmap, Burp Suite, Nessus, Nuclei, or Metasploit. Those tools can remain in
the assessment workflow while PwnReport becomes the final reporting layer.

The v0.1 workflow is intentionally small:

```text
init workspace -> edit report.json -> build report.html
```

It uses only the Python standard library and generates a self-contained HTML
report that can be opened offline. The generated HTML includes a print
stylesheet, so it can also be saved as PDF from a browser without adding a PDF
library to the project.

## What PwnReport Does

The initial release provides a small, predictable reporting pipeline:

1. Create a report workspace with `pwnreport init`.
2. Store engagement information and findings in `report.json`.
3. Validate required fields, severity values, and unique finding IDs.
4. Sort findings by severity.
5. Build a self-contained HTML report with:
   - Cover page
   - Engagement information
   - Assessment scope
   - Executive summary
   - Finding severity summary
   - Finding descriptions, impact, evidence, and remediation

This approach is useful when the priority is a stable report format rather
than a large platform. The JSON file remains easy to review in Git, generate
from another script, or use as the input for future importers.

## What PwnReport Does Not Do Yet

The v0.1 release does not include scanner importers, a web interface, a
database, authentication, CVSS calculation, or native PDF generation. These
are intentionally deferred until the core JSON-to-HTML workflow is stable.

## Requirements

- Python 3.9 or newer
- No runtime dependencies

## Quick start

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

pwnreport init demo-report
pwnreport build demo-report/report.json
```

Open `demo-report/output/report.html` in a browser. The generated report also
includes a print stylesheet, so the browser's print dialog can be used to save
it as PDF without a PDF dependency.

Without installing the package, use the module directly:

```bash
PYTHONPATH=src python3 -m pwnreport --help
PYTHONPATH=src python3 -m pwnreport init demo-report
PYTHONPATH=src python3 -m pwnreport build demo-report/report.json
```

## Commands

```bash
pwnreport --version
pwnreport init <directory>
pwnreport build <report.json>
pwnreport build <report.json> --output <report.html>
```

`init` creates:

```text
<directory>/
├── report.json
└── output/
```

The command never overwrites an existing `report.json`.

## Report schema

The initial template is intentionally small:

```json
{
  "project": {
    "name": "Web Application Penetration Test",
    "client": "ACME Corporation",
    "assessment_type": "Web Application",
    "classification": "CONFIDENTIAL",
    "author": "Rizko Febri Rachmayadi"
  },
  "scope": [
    "https://app.example.com"
  ],
  "executive_summary": "The assessment identified one high-risk vulnerability.",
  "findings": [
    {
      "id": "FIND-001",
      "title": "SQL Injection in Login Endpoint",
      "severity": "high",
      "affected_asset": "https://app.example.com/login",
      "description": "The login endpoint does not safely handle user input.",
      "impact": "An attacker may access or modify sensitive application data.",
      "evidence": "A crafted input changed the authentication response.",
      "remediation": "Use parameterized queries for all database operations."
    }
  ]
}
```

Allowed severity values, in report order:

```text
critical, high, medium, low, info
```

All project fields and all finding fields are required. Finding IDs must be
unique, and invalid input stops the build with a readable validation error.

## Feature Roadmap

The roadmap is intentionally incremental. Each stage should preserve the
simple JSON-first workflow and remain useful on its own.

### v0.1 - JSON to HTML foundation

Current release:

- Minimal report schema
- `init` and `build` CLI commands
- Required-field and severity validation
- Duplicate finding ID detection
- Severity-based finding ordering
- Self-contained dark-theme HTML output
- Browser print stylesheet for optional PDF export
- Standard-library test suite

### v0.2 - Manual finding workflow

Make authoring reports easier without introducing a database:

- `pwnreport finding add`
- `pwnreport finding list`
- `pwnreport finding show <id>`
- `pwnreport validate <report.json>`
- Automatic finding ID generation
- Safer editing while preserving the JSON schema

### v0.3 - Better assessment detail

Extend the schema for findings that need more technical context:

- Reproduction steps
- Evidence file references and screenshots
- CWE, CVE, and OWASP mappings
- CVSS vector and score fields
- Methodology and limitations sections
- Remediation priority and status

### v0.4 - Scanner importers

Normalize common tool output into the PwnReport schema. Importers should be
added one at a time with fixtures and tests:

- Nuclei JSONL importer
- Burp Suite issue export importer
- Nmap result importer
- Nessus result importer
- Generic custom JSON importer

The original source files should remain available in the project workspace so
the final report can be traced back to the tool output.

### v0.5 - Professional exports and templates

- Native PDF export
- Markdown export
- Table of contents
- Client logo and branding fields
- Report metadata and report date
- Multiple report templates
- Light and dark themes

### v1.0 - Reporting workspace

Only after the CLI and schema have matured:

- Multiple projects and report history
- Reusable finding library
- Finding deduplication across assessments
- Scope and asset management
- Review and approval workflow
- Optional local web interface
- Optional team collaboration

The roadmap does not make PwnReport responsible for reconnaissance or
exploitation. Scanner and assessment tools remain separate inputs, while
PwnReport focuses on normalization, validation, and report delivery.

## Development

Run the standard-library test suite:

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
