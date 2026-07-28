"""Self-contained HTML renderer for PwnReport."""

from __future__ import annotations

from html import escape
from typing import Any, Dict, Iterable, List

from .constants import SEVERITIES


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def _paragraphs(value: str) -> str:
    paragraphs = [part.strip() for part in value.split("\n\n") if part.strip()]
    return "".join(f"<p>{_text(part).replace(chr(10), '<br>')}</p>" for part in paragraphs)


def _scope_items(scope: Iterable[str]) -> str:
    items = "".join(f"<li><code>{_text(asset)}</code></li>" for asset in scope)
    return items or '<li class="muted">No assets listed.</li>'


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


def _finding_sections(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return """<section class="finding empty-state">
          <h3>No findings</h3>
          <p>No security findings were recorded for this assessment.</p>
        </section>"""

    sections = []
    for finding in findings:
        severity = finding["severity"]
        sections.append(
            f"""<article class="finding severity-{severity}">
          <header class="finding-header">
            <div>
              <span class="finding-id">{_text(finding["id"])}</span>
              <h3>{_text(finding["title"])}</h3>
            </div>
            <span class="severity-badge">{_text(severity.upper())}</span>
          </header>
          <dl class="finding-meta">
            <div>
              <dt>Affected Asset</dt>
              <dd><code>{_text(finding["affected_asset"])}</code></dd>
            </div>
          </dl>
          <div class="finding-block">
            <h4>Description</h4>
            {_paragraphs(finding["description"])}
          </div>
          <div class="finding-block">
            <h4>Impact</h4>
            {_paragraphs(finding["impact"])}
          </div>
          <div class="finding-block">
            <h4>Evidence</h4>
            <div class="evidence">{_paragraphs(finding["evidence"])}</div>
          </div>
          <div class="finding-block remediation">
            <h4>Remediation</h4>
            {_paragraphs(finding["remediation"])}
          </div>
        </article>"""
        )
    return "\n".join(sections)


def render_report(data: Dict[str, Any]) -> str:
    """Render validated report data as one offline HTML document."""
    project = data["project"]
    findings = data["findings"]
    total_findings = len(findings)
    total_label = "finding" if total_findings == 1 else "findings"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="PwnReport 0.1.0">
  <title>{_text(project["name"])} | Security Assessment Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0a0c10;
      --panel: #0f131a;
      --line: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --green: #7ee787;
      --blue: #79c0ff;
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
    .finding-id {{ color: var(--muted); font-size: 12px; }}
    .severity-badge {{ flex: 0 0 auto; border: 1px solid currentColor; padding: 4px 9px; font-size: 11px; font-weight: 700; }}
    .finding-meta {{ margin: 20px 0 26px; }}
    .finding-meta dt {{ color: var(--muted); font-size: 11px; text-transform: uppercase; }}
    .finding-meta dd {{ margin: 4px 0 0; }}
    .finding-block {{ color: var(--text); margin-top: 25px; }}
    .evidence {{ padding: 16px 18px; border-left: 2px solid var(--blue); background: #0a0c10; }}
    .remediation {{ padding-top: 20px; border-top: 1px solid var(--line); }}
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
        <div class="eyebrow">Security Assessment Report</div>
        <h1>{_text(project["name"])}</h1>
        <div class="subtitle">Prepared for {_text(project["client"])}</div>
      </div>
      <div class="classification">{_text(project["classification"])}</div>
    </header>

    <main>
      <section aria-labelledby="engagement-title">
        <h2 id="engagement-title">01 / Engagement</h2>
        <div class="meta-grid">
          <div class="meta-item"><span class="meta-label">Client</span><span class="meta-value">{_text(project["client"])}</span></div>
          <div class="meta-item"><span class="meta-label">Assessment Type</span><span class="meta-value">{_text(project["assessment_type"])}</span></div>
          <div class="meta-item"><span class="meta-label">Author</span><span class="meta-value">{_text(project["author"])}</span></div>
          <div class="meta-item"><span class="meta-label">Classification</span><span class="meta-value">{_text(project["classification"])}</span></div>
        </div>
      </section>

      <section aria-labelledby="scope-title">
        <h2 id="scope-title">02 / Scope</h2>
        <ul class="scope-list">{_scope_items(data["scope"])}</ul>
      </section>

      <section aria-labelledby="executive-title">
        <h2 id="executive-title">03 / Executive Summary</h2>
        {_paragraphs(data["executive_summary"])}
      </section>

      <section aria-labelledby="summary-title">
        <h2 id="summary-title">04 / Severity Summary</h2>
        <p class="muted">{total_findings} {total_label} recorded.</p>
        <div class="summary-grid">{_severity_summary(findings)}</div>
      </section>

      <section aria-labelledby="findings-title">
        <h2 id="findings-title">05 / Findings</h2>
        {_finding_sections(findings)}
      </section>
    </main>

    <footer>Generated by PwnReport 0.1.0. This document may contain confidential security information.</footer>
  </div>
</body>
</html>
"""
