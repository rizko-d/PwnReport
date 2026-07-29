"""Markdown exporter for PwnReport."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import __version__
from .constants import SEVERITIES
from .presentation import (
    effective_report_config,
    plain_text,
    report_sections,
    severity_counts,
    slugify,
)


def _clean(value: Any) -> str:
    return plain_text(value).replace("\x00", "")


def _finding_markdown(finding: Dict[str, Any], template: str) -> List[str]:
    lines = [
        f'### {finding["id"]}: {_clean(finding["title"])}',
        "",
        f'- **Severity:** {_clean(finding["severity"].upper())}',
        f'- **Affected asset:** `{_clean(finding["affected_asset"])}`',
    ]
    if finding.get("cvss_score") is not None:
        lines.append(f'- **CVSS score:** {_clean(finding["cvss_score"])}')
    if finding.get("cvss_vector"):
        lines.append(f'- **CVSS vector:** `{_clean(finding["cvss_vector"])}`')
    if finding.get("remediation_status"):
        status = str(finding["remediation_status"]).replace("_", " ").title()
        lines.append(f"- **Remediation status:** {status}")
    lines.extend(["", "#### Description", "", _clean(finding["description"]), ""])
    lines.extend(["#### Impact", "", _clean(finding["impact"]), ""])

    if template == "technical":
        steps = finding.get("reproduction_steps")
        if steps:
            lines.extend(["#### Reproduction Steps", ""])
            for index, step in enumerate(steps, 1):
                lines.append(f"{index}. {_clean(step)}")
            lines.append("")
        lines.extend(["#### Evidence", "", "```text", _clean(finding["evidence"]), "```", ""])
        references = finding.get("references")
        if references:
            lines.extend(["#### References", ""])
            lines.extend(f"- {_clean(reference)}" for reference in references)
            lines.append("")
        source = finding.get("source")
        if isinstance(source, dict):
            lines.extend(["#### Source", ""])
            if source.get("tool"):
                lines.append(f'- **Tool:** {_clean(source["tool"])}')
            if source.get("source_id"):
                lines.append(f'- **Source ID:** `{_clean(source["source_id"])}`')
            if source.get("file"):
                lines.append(f'- **File:** `{_clean(source["file"])}`')
            lines.append("")

    lines.extend(["#### Remediation", "", _clean(finding["remediation"]), "", "---", ""])
    return lines


def render_markdown(
    data: Dict[str, Any],
    template: Optional[str] = None,
    theme: Optional[str] = None,
) -> str:
    """Render a deterministic Markdown report."""
    config = effective_report_config(data, template=template, theme=theme)
    project = data["project"]
    findings = data["findings"]
    sections = report_sections(data, config["template"])
    branding = config["branding"]
    lines: List[str] = [
        f'# {_clean(project["name"])}',
        "",
        "Security Assessment Report",
        "",
    ]
    if branding.get("company_name"):
        lines.extend([f'**Prepared by:** {_clean(branding["company_name"])}', ""])
    lines.extend(
        [
            f'**Prepared for:** {_clean(project["client"])}',
            f'**Classification:** {_clean(project["classification"])}',
            f'**Assessment type:** {_clean(project["assessment_type"])}',
            f'**Author:** {_clean(project["author"])}',
        ]
    )
    if config.get("date"):
        lines.append(f'**Report date:** {_clean(config["date"])}')
    lines.extend(
        [
            f'**Report version:** {_clean(config["version"])}',
            f'**Template:** {_clean(config["template"].title())}',
            "",
            "## Table of Contents",
            "",
        ]
    )
    for section in sections:
        lines.append(f'- [{section["title"]}](#{slugify(section["title"])})')
    for finding in findings:
        anchor = slugify(f'{finding["id"]}-{finding["title"]}')
        lines.append(f'- [{finding["id"]}: {_clean(finding["title"])}](#{anchor})')

    lines.extend(["", "## Engagement", ""])
    lines.extend(
        [
            f'- **Client:** {_clean(project["client"])}',
            f'- **Assessment type:** {_clean(project["assessment_type"])}',
            f'- **Author:** {_clean(project["author"])}',
            f'- **Classification:** {_clean(project["classification"])}',
            "",
            "## Scope",
            "",
        ]
    )
    if data["scope"]:
        lines.extend(f'- `{_clean(asset)}`' for asset in data["scope"])
    else:
        lines.append("No assets listed.")
    lines.extend(["", "## Executive Summary", "", _clean(data["executive_summary"]), ""])

    if config["template"] == "technical" and str(data.get("methodology", "")).strip():
        lines.extend(["## Methodology", "", _clean(data["methodology"]), ""])
    if config["template"] == "technical" and str(data.get("limitations", "")).strip():
        lines.extend(["## Limitations", "", _clean(data["limitations"]), ""])

    counts = severity_counts(findings)
    lines.extend(["## Severity Summary", "", "| Severity | Count |", "|----------|------:|"])
    for severity in SEVERITIES:
        lines.append(f"| {severity.title()} | {counts[severity]} |")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.extend(["No security findings were recorded for this assessment.", ""])
    else:
        for finding in findings:
            lines.extend(_finding_markdown(finding, config["template"]))

    lines.extend(
        [
            f"Generated by PwnReport {__version__}.",
            "",
        ]
    )
    return "\n".join(lines)
