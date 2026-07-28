# PwnReport

Minimal JSON-to-HTML penetration test report generator.

PwnReport v0.1 focuses on one reliable workflow:

```text
init workspace -> edit report.json -> build report.html
```

It uses only the Python standard library and generates a self-contained HTML
report that can be opened offline.

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

## Development

Run the standard-library test suite:

```bash
python3 -m unittest discover -s tests -v
```

The first release deliberately does not include a database, web UI, scanner
importers, CVSS calculation, or PDF library. These can be added incrementally
after the JSON-to-HTML workflow is stable.

## License

MIT
