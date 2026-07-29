"""Self-contained HTML renderer for PwnReport."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import __version__
from .constants import SEVERITIES
from .presentation import (
    PresentationError,
    effective_report_config,
    embedded_logo,
    report_sections,
    section_number,
    severity_counts,
    slugify,
)


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def _paragraphs(value: str) -> str:
    paragraphs = [part.strip() for part in value.split("\n\n") if part.strip()]
    return "".join(f"<p>{_text(part).replace(chr(10), '<br>')}</p>" for part in paragraphs)


def _scope_items(scope: Iterable[str]) -> str:
    items = "".join(f"<li><code>{_text(asset)}</code></li>" for asset in scope)
    return items or '<li class="muted">No assets listed.</li>'


def _toc(sections: List[Dict[str, str]], findings: List[Dict[str, Any]]) -> str:
    entries = []
    for index, section in enumerate(sections, 1):
        entries.append(
            f'<li><a href="#{_text(section["id"])}">'
            f'<span>{index:02d}</span>{_text(section["title"])}</a></li>'
        )
    finding_entries = "".join(
        f'<li class="toc-finding"><a href="#{slugify(finding["id"])}">'
        f'<span>{_text(finding["id"])}</span>{_text(finding["title"])}</a></li>'
        for finding in findings
    )
    return (
        '<nav class="toc" aria-label="Table of contents">'
        '<h2>Table of Contents</h2><ol>'
        + "".join(entries)
        + finding_entries
        + "</ol></nav>"
    )


def _branding(config: Dict[str, Any], project_root: Path) -> str:
    branding = config["branding"]
    logo_uri = embedded_logo(project_root, config)
    logo = (
        f'<img class="brand-logo" src="{_text(logo_uri)}" alt="Client logo">'
        if logo_uri
        else ""
    )
    company = branding.get("company_name", "")
    company_html = f'<div class="brand-name">{_text(company)}</div>' if company else ""
    return f'<div class="brand">{logo}{company_html}</div>'


def _report_metadata(config: Dict[str, Any]) -> str:
    rows = []
    if config.get("date"):
        rows.append(
            f'<div class="meta-item"><span class="meta-label">Report Date</span>'
            f'<span class="meta-value">{_text(config["date"])}</span></div>'
        )
    if config.get("version"):
        rows.append(
            f'<div class="meta-item"><span class="meta-label">Report Version</span>'
            f'<span class="meta-value">{_text(config["version"])}</span></div>'
        )
    rows.append(
        f'<div class="meta-item"><span class="meta-label">Template</span>'
        f'<span class="meta-value">{_text(config["template"].title())}</span></div>'
    )
    return "".join(rows)


def _theme_values(config: Dict[str, Any]) -> Dict[str, str]:
    branding = config["branding"]
    if config["theme"] == "light":
        return {
            "bg": "#FFFFFF", "panel": "#F6F8FA", "line": "#D0D7DE",
            "text": "#1F2328", "muted": "#59636E",
            "primary": branding["primary_color"],
            "secondary": branding["secondary_color"],
        }
    return {
        "bg": "#0A0C10", "panel": "#0F131A", "line": "#30363D",
        "text": "#E6EDF3", "muted": "#8B949E",
        "primary": branding["primary_color"],
        "secondary": branding["secondary_color"],
    }


def _severity_summary(findings: List[Dict[str, Any]]) -> str:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1

    return "".join(
        (
            f'<div class="metric severity-{severity}">'
            f'<span class="metric-value">{counts[severity]}</span>'
            f'<span class="metric-label">{severity.title()}</span>'
            "</div>"
        )
        for severity in SEVERITIES
    )


def _methodology_section(
    data: Dict[str, Any], sections: List[Dict[str, str]], template: str
) -> str:
    methodology = data.get("methodology")
    if template != "technical" or not methodology or not methodology.strip():
        return ""
    number = section_number(sections, "methodology")
    return f"""<section id="methodology" aria-labelledby="methodology-title">
        <h2 id="methodology-title">{number} / Methodology</h2>
        {_paragraphs(methodology)}
      </section>"""


def _limitations_section(
    data: Dict[str, Any], sections: List[Dict[str, str]], template: str
) -> str:
    limitations = data.get("limitations")
    if template != "technical" or not limitations or not limitations.strip():
        return ""
    number = section_number(sections, "limitations")
    return f"""<section id="limitations" aria-labelledby="limitations-title">
        <h2 id="limitations-title">{number} / Limitations</h2>
        {_paragraphs(limitations)}
      </section>"""


def _remediation_badge(finding: Dict[str, Any]) -> str:
    """Render a remediation status badge if present."""
    status = finding.get("remediation_status")
    if not status:
        return ""
    return f"""<span class="status-badge status-{_text(status)}">{_text(status.replace("_", " ").upper())}</span>"""


def _cvss_meta(finding: Dict[str, Any]) -> str:
    """Render CVSS metadata rows if present."""
    rows = []
    score = finding.get("cvss_score")
    vector = finding.get("cvss_vector")
    if score is not None:
        rows.append(
            f"""<div><dt>CVSS Score</dt><dd>{_text(str(score))}</dd></div>"""
        )
    if vector:
        rows.append(
            f"""<div><dt>CVSS Vector</dt><dd><code>{_text(vector)}</code></dd></div>"""
        )
    return "".join(rows)


def _source_meta(finding: Dict[str, Any]) -> str:
    """Render scanner provenance when a finding was imported."""
    source = finding.get("source")
    if not isinstance(source, dict):
        return ""
    rows = []
    if source.get("tool"):
        rows.append(
            f"""<div><dt>Source Tool</dt><dd>{_text(source['tool'])}</dd></div>"""
        )
    if source.get("source_id"):
        rows.append(
            f"""<div><dt>Source ID</dt><dd><code>{_text(source['source_id'])}</code></dd></div>"""
        )
    if source.get("file"):
        rows.append(
            f"""<div><dt>Source File</dt><dd><code>{_text(source['file'])}</code></dd></div>"""
        )
    return "".join(rows)


def _finding_sections(findings: List[Dict[str, Any]], template: str) -> str:
    if not findings:
        return """<section class="finding empty-state">
          <h3>No findings</h3>
          <p>No security findings were recorded for this assessment.</p>
        </section>"""

    sections = []
    detailed = template == "technical"
    for finding in findings:
        severity = finding["severity"]

        finding_blocks = [
            f"""<article id="{slugify(finding['id'])}" class="finding severity-{severity}">
          <header class="finding-header">
            <div>
              <span class="finding-id">{_text(finding["id"])}</span>
              <h3>{_text(finding["title"])}</h3>
            </div>
            <div class="finding-header-right">
              <span class="severity-badge">{_text(severity.upper())}</span>
              {_remediation_badge(finding)}
            </div>
          </header>
          <dl class="finding-meta">
            <div>
              <dt>Affected Asset</dt>
              <dd><code>{_text(finding["affected_asset"])}</code></dd>
            </div>
            {_cvss_meta(finding)}
            {_source_meta(finding) if detailed else ""}
          </dl>
          <div class="finding-block">
            <h4>Description</h4>
            {_paragraphs(finding["description"])}
          </div>
          <div class="finding-block">
            <h4>Impact</h4>
            {_paragraphs(finding["impact"])}
          </div>"""
        ]

        # Reproduction steps (optional)
        blocks = finding.get("reproduction_steps")
        if detailed and blocks:
            steps_html = "".join(
                f"<li>{_text(step)}</li>" for step in blocks
            )
            finding_blocks.append(
                f"""<div class="finding-block">
              <h4>Reproduction Steps</h4>
              <ol class="repro-steps">{steps_html}</ol>
            </div>"""
            )

        # Evidence (technical template only)
        if detailed:
            finding_blocks.append(
                f"""<div class="finding-block">
            <h4>Evidence</h4>
            <div class="evidence">{_paragraphs(finding["evidence"])}</div>
          </div>"""
            )

        # References (optional)
        refs = finding.get("references")
        if detailed and refs:
            refs_html = "".join(
                f"<span class=\"ref-tag\">{_text(ref)}</span>" for ref in refs
            )
            finding_blocks.append(
                f"""<div class="finding-block">
              <h4>References</h4>
              <div class="refs">{refs_html}</div>
            </div>"""
            )

        # Remediation
        finding_blocks.append(
            f"""<div class="finding-block remediation">
            <h4>Remediation</h4>
            {_paragraphs(finding["remediation"])}
          </div>
        </article>"""
        )

        sections.append("".join(finding_blocks))
    return "\n".join(sections)


def render_report(
    data: Dict[str, Any],
    project_root: Optional[Path] = None,
    template: Optional[str] = None,
    theme: Optional[str] = None,
) -> str:
    """Render validated report data as one self-contained HTML document."""
    project = data["project"]
    findings = data["findings"]
    root = (project_root or Path.cwd()).expanduser().resolve()
    config = effective_report_config(data, template=template, theme=theme)
    sections = report_sections(data, config["template"])
    colors = _theme_values(config)
    total_findings = len(findings)
    total_label = "finding" if total_findings == 1 else "findings"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="PwnReport {__version__}">
  <title>{_text(project["name"])} | Security Assessment Report</title>
  <style>
    :root {{
      color-scheme: {_text(config["theme"])};
      --bg: {colors["bg"]};
      --panel: {colors["panel"]};
      --line: {colors["line"]};
      --text: {colors["text"]};
      --muted: {colors["muted"]};
      --green: {colors["primary"]};
      --blue: {colors["secondary"]};
      --critical: #ff7b72;
      --high: #ffa657;
      --medium: #d29922;
      --low: #79c0ff;
      --info: #8b949e;
    }}
    * {{ box-sizing: border-box; }}
    html {{ background: var(--bg); }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 14px;
      line-height: 1.65;
    }}
    a {{ color: var(--blue); }}
    code {{ color: var(--blue); overflow-wrap: anywhere; }}
    .page {{ width: min(1120px, calc(100% - 48px)); margin: 0 auto; }}
    .cover {{
      min-height: 82vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 72px 0 56px;
      border-bottom: 1px solid var(--line);
    }}
    .eyebrow {{ color: var(--green); letter-spacing: .12em; text-transform: uppercase; }}
    h1 {{ max-width: 850px; margin: 18px 0; font-size: clamp(38px, 7vw, 76px); line-height: 1.05; }}
    .subtitle {{ color: var(--muted); font-size: 18px; }}
    .classification {{ align-self: flex-start; border: 1px solid var(--green); color: var(--green); padding: 7px 12px; }}
    .brand {{ display: flex; align-items: center; gap: 16px; min-height: 32px; }}
    .brand-logo {{ display: block; max-width: 180px; max-height: 72px; object-fit: contain; }}
    .brand-name {{ color: var(--green); font-size: 15px; text-transform: uppercase; letter-spacing: .1em; }}
    .toc {{ margin: 56px 0 72px; padding: 28px; border: 1px solid var(--line); background: var(--panel); }}
    .toc h2 {{ margin-bottom: 16px; }}
    .toc ol {{ list-style: none; margin: 0; padding: 0; }}
    .toc li {{ border-bottom: 1px solid var(--line); }}
    .toc li:last-child {{ border-bottom: 0; }}
    .toc a {{ display: grid; grid-template-columns: 110px 1fr; gap: 12px; padding: 9px 0; color: var(--text); text-decoration: none; }}
    .toc a span {{ color: var(--muted); }}
    .toc-finding {{ padding-left: 24px; font-size: 12px; }}
    main {{ padding: 64px 0 100px; }}
    section {{ margin-bottom: 72px; }}
    h2 {{ margin: 0 0 28px; color: var(--blue); font-size: 22px; border-bottom: 1px solid var(--line); padding-bottom: 12px; }}
    h3 {{ margin: 5px 0 0; font-size: 21px; line-height: 1.35; }}
    h4 {{ color: var(--green); margin: 0 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: .08em; }}
    p {{ margin: 0 0 14px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 1px; background: var(--line); border: 1px solid var(--line); }}
    .meta-item {{ padding: 22px; background: var(--bg); }}
    .meta-label {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .meta-value {{ display: block; margin-top: 5px; }}
    .scope-list {{ margin: 0; padding-left: 22px; }}
    .scope-list li {{ padding: 5px 0; }}
    .muted {{ color: var(--muted); }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: var(--line); border: 1px solid var(--line); }}
    .metric {{ padding: 20px; background: var(--bg); border-top: 3px solid currentColor; }}
    .metric-value, .metric-label {{ display: block; }}
    .metric-value {{ color: var(--text); font-size: 30px; font-weight: 700; }}
    .metric-label {{ font-size: 12px; text-transform: uppercase; }}
    .severity-critical {{ color: var(--critical); }}
    .severity-high {{ color: var(--high); }}
    .severity-medium {{ color: var(--medium); }}
    .severity-low {{ color: var(--low); }}
    .severity-info {{ color: var(--info); }}
    .finding {{ margin-bottom: 36px; padding: 28px; border: 1px solid var(--line); border-left: 4px solid currentColor; background: var(--panel); break-inside: avoid; }}
    .finding-header {{ display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; padding-bottom: 22px; border-bottom: 1px solid var(--line); }}
    .finding-header-right {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .finding-id {{ color: var(--muted); font-size: 12px; }}
    .severity-badge {{ flex: 0 0 auto; border: 1px solid currentColor; padding: 4px 9px; font-size: 11px; font-weight: 700; }}
    .status-badge {{ flex: 0 0 auto; padding: 4px 9px; font-size: 11px; font-weight: 700; background: var(--panel); border: 1px solid var(--line); }}
    .finding-meta {{ margin: 20px 0 26px; }}
    .finding-meta dt {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
    .finding-meta dd {{ margin: 4px 0 0; }}
    .finding-block {{ color: var(--text); margin-top: 25px; }}
    .evidence {{ padding: 16px 18px; border-left: 2px solid var(--blue); background: var(--bg); }}
    .remediation {{ padding-top: 20px; border-top: 1px solid var(--line); }}
    .repro-steps {{ margin: 0; padding-left: 22px; }}
    .repro-steps li {{ padding: 4px 0; }}
    .refs {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .ref-tag {{ display: inline-block; padding: 3px 8px; font-size: 11px; border: 1px solid var(--blue); color: var(--blue); }}
    .empty-state {{ color: var(--muted); }}
    footer {{ padding: 30px 0; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }}
    @media (max-width: 720px) {{
      .page {{ width: min(100% - 28px, 1120px); }}
      .cover {{ min-height: 70vh; padding-top: 44px; }}
      main {{ padding-top: 44px; }}
      .meta-grid {{ grid-template-columns: 1fr; }}
      .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
      .finding {{ padding: 20px; }}
      .finding-header {{ flex-direction: column; }}
    }}
    @media print {{
      :root {{ color-scheme: light; --bg: #ffffff; --panel: #ffffff; --line: #c8c8c8; --text: #111111; --muted: #555555; }}
      body {{ font-size: 11px; }}
      .page {{ width: 100%; }}
      .cover {{ min-height: 95vh; page-break-after: always; }}
      main {{ padding-top: 0; }}
      section {{ margin-bottom: 40px; }}
      .finding {{ page-break-inside: avoid; }}
      .evidence {{ background: #f5f5f5; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <header class="cover">
      <div>
        {_branding(config, root)}
        <div class="eyebrow">Security Assessment Report</div>
        <h1>{_text(project["name"])}</h1>
        <div class="subtitle">Prepared for {_text(project["client"])}</div>
      </div>
      <div class="classification">{_text(project["classification"])}</div>
    </header>

    {_toc(sections, findings)}

    <main>
      <section id="engagement" aria-labelledby="engagement-title">
        <h2 id="engagement-title">{section_number(sections, "engagement")} / Engagement</h2>
        <div class="meta-grid">
          <div class="meta-item"><span class="meta-label">Client</span><span class="meta-value">{_text(project["client"])}</span></div>
          <div class="meta-item"><span class="meta-label">Assessment Type</span><span class="meta-value">{_text(project["assessment_type"])}</span></div>
          <div class="meta-item"><span class="meta-label">Author</span><span class="meta-value">{_text(project["author"])}</span></div>
          <div class="meta-item"><span class="meta-label">Classification</span><span class="meta-value">{_text(project["classification"])}</span></div>
          {_report_metadata(config)}
        </div>
      </section>

      <section id="scope" aria-labelledby="scope-title">
        <h2 id="scope-title">{section_number(sections, "scope")} / Scope</h2>
        <ul class="scope-list">{_scope_items(data["scope"])}</ul>
      </section>

      <section id="executive-summary" aria-labelledby="executive-title">
        <h2 id="executive-title">{section_number(sections, "executive-summary")} / Executive Summary</h2>
        {_paragraphs(data["executive_summary"])}
      </section>

      {_methodology_section(data, sections, config["template"])}
      {_limitations_section(data, sections, config["template"])}

      <section id="severity-summary" aria-labelledby="summary-title">
        <h2 id="summary-title">{section_number(sections, "severity-summary")} / Severity Summary</h2>
        <p class="muted">{total_findings} {total_label} recorded.</p>
        <div class="summary-grid">{_severity_summary(findings)}</div>
      </section>

      <section id="findings" aria-labelledby="findings-title">
        <h2 id="findings-title">{section_number(sections, "findings")} / Findings</h2>
        {_finding_sections(findings, config["template"])}
      </section>
    </main>

    <footer>Generated by PwnReport {__version__}. This document may contain confidential security information.</footer>
  </div>
</body>
</html>
"""
