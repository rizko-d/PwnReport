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

The original v0.1 foundation remains intentionally small:

```text
init workspace -> edit report.json -> build report.html
```

It uses only the Python standard library and generates a self-contained HTML
report that can be opened offline. The generated HTML includes a print
stylesheet, so it can also be saved as PDF from a browser without adding a PDF
library to the project.

## What PwnReport Does

PwnReport provides a small, predictable reporting pipeline:

1. Create a report workspace with `pwnreport init`.
2. Store engagement information in `report.json`.
3. Add and inspect findings through the CLI or edit the JSON directly.
4. Validate required fields, severity values, and unique finding IDs.
5. Sort findings by severity.
6. Build a self-contained HTML report with:
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

The v0.3 release does not include scanner importers, a web interface, a
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
pwnreport finding add demo-report/report.json
pwnreport validate demo-report/report.json
pwnreport build demo-report/report.json
```

Open `demo-report/output/report.html` in a browser. The generated report also
includes a print stylesheet, so the browser's print dialog can be used to save
it as PDF without a PDF dependency.

Without installing the package, use the module directly:

```bash
PYTHONPATH=src python3 -m pwnreport --help
PYTHONPATH=src python3 -m pwnreport init demo-report
PYTHONPATH=src python3 -m pwnreport finding add demo-report/report.json
PYTHONPATH=src python3 -m pwnreport validate demo-report/report.json
PYTHONPATH=src python3 -m pwnreport build demo-report/report.json
```

## Commands

```bash
pwnreport --version
pwnreport init <directory>
pwnreport validate <report.json>
pwnreport finding add <report.json>
pwnreport finding list <report.json>
pwnreport finding show <report.json> <finding-id>
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

### Finding workflow

Run `finding add` without field flags to use the interactive prompts:

```bash
pwnreport finding add demo-report/report.json
```

For scripts and repeatable automation, provide all fields as flags:

```bash
pwnreport finding add demo-report/report.json \
  --title "Missing Content Security Policy" \
  --severity high \
  --affected-asset "https://app.example.com" \
  --description "The application does not return a CSP header." \
  --impact "Client-side injection can have a wider impact." \
  --evidence "Content-Security-Policy was absent from the response." \
  --remediation "Deploy a restrictive Content Security Policy."
```

Additional v0.3 optional flags are also available:

```bash
pwnreport finding add demo-report/report.json \
  --reproduction-steps "Step A,Step B,Step C" \
  --references "CWE-693,OWASP A05:2021" \
  --cvss-vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  --cvss-score "9.8" \
  --remediation-status "open"
```

PwnReport assigns IDs automatically in `FIND-001` format. It derives the next
ID from the highest existing numeric finding ID rather than reusing deleted
numbers.

Inspect and validate findings before building the report:

```bash
pwnreport finding list demo-report/report.json
pwnreport finding show demo-report/report.json FIND-001
pwnreport validate demo-report/report.json
```

Finding changes are validated before saving. PwnReport writes a temporary file
beside `report.json`, flushes it to disk, and atomically replaces the original.
Unknown JSON fields are preserved, so adding a finding does not discard custom
metadata maintained by another tool.

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

Delivered foundation:

- [x] Minimal report schema
- [x] `init` and `build` CLI commands
- [x] Required-field and severity validation
- [x] Duplicate finding ID detection
- [x] Severity-based finding ordering
- [x] Self-contained dark-theme HTML output
- [x] Browser print stylesheet for optional PDF export
- [x] Standard-library test suite

### v0.2 - Manual finding workflow

Delivered:

Make authoring reports easier without introducing a database:

- [x] `pwnreport finding add`
- [x] `pwnreport finding list`
- [x] `pwnreport finding show <id>`
- [x] `pwnreport validate <report.json>`
- [x] Automatic finding ID generation
- [x] Safer editing while preserving the JSON schema

### v0.3 - Better assessment detail

Current release:

Extend the schema for findings that need more technical context:

- [x] Reproduction steps
- [x] Evidence file references (references field)
- [x] CWE, CVE, and OWASP mappings (references field)
- [x] CVSS vector and score fields
- [x] Methodology and limitations sections
- [x] Remediation status

### v0.4 - Scanner importers

Normalize common tool output into the PwnReport schema. Importers should be
added one at a time with fixtures and tests:

- [ ] Nuclei JSONL importer
- [ ] Burp Suite issue export importer
- [ ] Nmap result importer
- [ ] Nessus result importer
- [ ] Generic custom JSON importer

The original source files should remain available in the project workspace so
the final report can be traced back to the tool output.

### v0.5 - Professional exports and templates

- [ ] Native PDF export
- [ ] Markdown export
- [ ] Table of contents
- [ ] Client logo and branding fields
- [ ] Report metadata and report date
- [ ] Multiple report templates
- [ ] Light and dark themes

### v1.0 - Reporting workspace

Only after the CLI and schema have matured:

- [ ] Multiple projects and report history
- [ ] Reusable finding library
- [ ] Finding deduplication across assessments
- [ ] Scope and asset management
- [ ] Review and approval workflow
- [ ] Optional local web interface
- [ ] Optional team collaboration

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
