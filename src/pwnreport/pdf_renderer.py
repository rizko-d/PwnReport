"""Dependency-free native PDF exporter for PwnReport."""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .constants import SEVERITIES
from .presentation import (
    ascii_pdf_text,
    color_rgb,
    effective_report_config,
    report_sections,
    severity_counts,
)

PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN = 54
CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN)
TOP = PAGE_HEIGHT - MARGIN
BOTTOM = MARGIN


def _pdf_escape(value: Any) -> str:
    text = ascii_pdf_text(value)
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(value: Any, size: float, monospace: bool = False) -> List[str]:
    text = ascii_pdf_text(value)
    if not text:
        return [""]
    average = size * (0.60 if monospace else 0.52)
    width = max(20, int(CONTENT_WIDTH / average))
    lines: List[str] = []
    for paragraph in text.splitlines() or [""]:
        if not paragraph:
            lines.append("")
            continue
        lines.extend(
            textwrap.wrap(
                paragraph,
                width=width,
                replace_whitespace=False,
                drop_whitespace=True,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    return lines


@dataclass
class PdfPage:
    """A single PDF page represented as drawing operations."""

    operations: List[str] = field(default_factory=list)
    y: float = TOP

    def text(
        self,
        value: Any,
        *,
        x: float = MARGIN,
        size: float = 10,
        font: str = "F1",
        color: Tuple[float, float, float] = (0.1, 0.1, 0.1),
    ) -> None:
        r, g, b = color
        self.operations.append(
            f"BT /{font} {size:.1f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.1f} {self.y:.1f} Tm ({_pdf_escape(value)}) Tj ET"
        )

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: Tuple[float, float, float] = (0.7, 0.7, 0.7),
        width: float = 0.5,
    ) -> None:
        r, g, b = color
        self.operations.append(
            f"{r:.3f} {g:.3f} {b:.3f} RG {width:.1f} w "
            f"{x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S"
        )

    def rectangle(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        color: Tuple[float, float, float],
    ) -> None:
        r, g, b = color
        self.operations.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} "
            f"{width:.1f} {height:.1f} re f"
        )

    def stream(self) -> bytes:
        return ("\n".join(self.operations) + "\n").encode("latin-1", errors="replace")


class BodyBuilder:
    """Paginated body-page builder with section page tracking."""

    def __init__(self, primary: Tuple[float, float, float]) -> None:
        self.primary = primary
        self.pages: List[PdfPage] = [PdfPage()]
        self.section_pages: Dict[str, int] = {}

    @property
    def page(self) -> PdfPage:
        return self.pages[-1]

    def new_page(self) -> None:
        self.pages.append(PdfPage())

    def ensure(self, height: float) -> None:
        if self.page.y - height < BOTTOM + 24:
            self.new_page()

    def spacer(self, height: float = 8) -> None:
        self.page.y -= height

    def heading(self, section_id: str, title: str) -> None:
        self.ensure(42)
        self.section_pages.setdefault(section_id, len(self.pages))
        self.page.text(title, size=16, font="F2", color=self.primary)
        self.page.y -= 9
        self.page.line(MARGIN, self.page.y, PAGE_WIDTH - MARGIN, self.page.y, self.primary, 1)
        self.page.y -= 24

    def subheading(self, title: str) -> None:
        self.ensure(28)
        self.page.text(title, size=12, font="F2", color=self.primary)
        self.page.y -= 18

    def paragraph(self, value: Any, *, size: float = 10, monospace: bool = False) -> None:
        font = "F3" if monospace else "F1"
        lines = _wrap(value, size, monospace)
        line_height = size * 1.4
        for line in lines:
            self.ensure(line_height)
            self.page.text(line, size=size, font=font)
            self.page.y -= line_height
        self.page.y -= 5

    def bullet(self, value: Any, prefix: str = "-") -> None:
        lines = _wrap(value, 9.5)
        for index, line in enumerate(lines):
            self.ensure(14)
            marker = prefix if index == 0 else " " * len(prefix)
            self.page.text(f"{marker} {line}", x=MARGIN + 10, size=9.5)
            self.page.y -= 13

    def key_value(self, key: str, value: Any) -> None:
        text = f"{key}: {ascii_pdf_text(value)}"
        self.paragraph(text, size=9.5)


def _body_pages(
    data: Dict[str, Any], config: Dict[str, Any]
) -> Tuple[List[PdfPage], Dict[str, int]]:
    primary = color_rgb(config["branding"]["primary_color"])
    builder = BodyBuilder(primary)
    project = data["project"]
    findings = data["findings"]
    template = config["template"]

    builder.heading("engagement", "Engagement")
    builder.key_value("Client", project["client"])
    builder.key_value("Assessment type", project["assessment_type"])
    builder.key_value("Author", project["author"])
    builder.key_value("Classification", project["classification"])
    if config.get("date"):
        builder.key_value("Report date", config["date"])
    builder.key_value("Report version", config["version"])
    builder.key_value("Template", template.title())

    builder.heading("scope", "Scope")
    if data["scope"]:
        for asset in data["scope"]:
            builder.bullet(asset)
    else:
        builder.paragraph("No assets listed.")

    builder.heading("executive-summary", "Executive Summary")
    builder.paragraph(data["executive_summary"])

    if template == "technical" and str(data.get("methodology", "")).strip():
        builder.heading("methodology", "Methodology")
        builder.paragraph(data["methodology"])
    if template == "technical" and str(data.get("limitations", "")).strip():
        builder.heading("limitations", "Limitations")
        builder.paragraph(data["limitations"])

    builder.heading("severity-summary", "Severity Summary")
    counts = severity_counts(findings)
    for severity in SEVERITIES:
        builder.key_value(severity.title(), counts[severity])

    builder.heading("findings", "Findings")
    if not findings:
        builder.paragraph("No security findings were recorded for this assessment.")
    for finding in findings:
        builder.section_pages.setdefault(finding["id"], len(builder.pages))
        builder.subheading(f'{finding["id"]}: {finding["title"]}')
        builder.key_value("Severity", finding["severity"].upper())
        builder.key_value("Affected asset", finding["affected_asset"])
        if finding.get("cvss_score") is not None:
            builder.key_value("CVSS score", finding["cvss_score"])
        if finding.get("cvss_vector"):
            builder.key_value("CVSS vector", finding["cvss_vector"])
        if finding.get("remediation_status"):
            builder.key_value(
                "Remediation status",
                str(finding["remediation_status"]).replace("_", " ").title(),
            )
        builder.subheading("Description")
        builder.paragraph(finding["description"])
        builder.subheading("Impact")
        builder.paragraph(finding["impact"])
        if template == "technical":
            steps = finding.get("reproduction_steps")
            if steps:
                builder.subheading("Reproduction Steps")
                for index, step in enumerate(steps, 1):
                    builder.bullet(step, prefix=f"{index}.")
            builder.subheading("Evidence")
            builder.paragraph(finding["evidence"], size=8.5, monospace=True)
            references = finding.get("references")
            if references:
                builder.subheading("References")
                for reference in references:
                    builder.bullet(reference)
            source = finding.get("source")
            if isinstance(source, dict):
                builder.subheading("Source")
                if source.get("tool"):
                    builder.key_value("Tool", source["tool"])
                if source.get("source_id"):
                    builder.key_value("Source ID", source["source_id"])
                if source.get("file"):
                    builder.key_value("File", source["file"])
        builder.subheading("Remediation")
        builder.paragraph(finding["remediation"])
        builder.spacer(10)

    return builder.pages, builder.section_pages


def _cover_page(data: Dict[str, Any], config: Dict[str, Any]) -> PdfPage:
    page = PdfPage()
    primary = color_rgb(config["branding"]["primary_color"])
    project = data["project"]
    page.rectangle(0, 0, PAGE_WIDTH, PAGE_HEIGHT, (0.04, 0.05, 0.07))
    page.y = PAGE_HEIGHT - 110
    company = config["branding"].get("company_name")
    if company:
        page.text(company.upper(), size=11, font="F2", color=primary)
        page.y -= 48
    page.text("SECURITY ASSESSMENT REPORT", size=13, font="F2", color=primary)
    page.y -= 52
    for line in _wrap(project["name"], 28):
        page.text(line, size=28, font="F2", color=(0.90, 0.93, 0.95))
        page.y -= 36
    page.y -= 12
    page.text(f'Prepared for {ascii_pdf_text(project["client"])}', size=13, color=(0.65, 0.69, 0.73))
    page.y -= 34
    page.text(project["classification"], size=10, font="F2", color=primary)
    page.y = 100
    if config.get("date"):
        page.text(f'Report date: {config["date"]}', size=9, color=(0.65, 0.69, 0.73))
        page.y -= 14
    page.text(f'Report version: {config["version"]}', size=9, color=(0.65, 0.69, 0.73))
    page.y -= 14
    page.text(f'Generated by PwnReport {__version__}', size=9, color=(0.65, 0.69, 0.73))
    return page


def _toc_pages(
    data: Dict[str, Any],
    config: Dict[str, Any],
    body_section_pages: Dict[str, int],
) -> List[PdfPage]:
    entries: List[Tuple[str, str]] = [
        (section["id"], section["title"])
        for section in report_sections(data, config["template"])
    ]
    entries.extend((finding["id"], f'{finding["id"]}: {finding["title"]}') for finding in data["findings"])
    lines_per_page = 42
    page_count = max(1, (len(entries) + lines_per_page - 1) // lines_per_page)
    body_offset = 1 + page_count
    pages: List[PdfPage] = []
    primary = color_rgb(config["branding"]["primary_color"])
    for page_index in range(page_count):
        page = PdfPage()
        page.text("Table of Contents", size=20, font="F2", color=primary)
        page.y -= 32
        start = page_index * lines_per_page
        for key, title in entries[start : start + lines_per_page]:
            target = body_offset + body_section_pages[key]
            display = ascii_pdf_text(title)
            max_title = 68
            if len(display) > max_title:
                display = display[: max_title - 3] + "..."
            dots = "." * max(3, 76 - len(display))
            page.text(f"{display} {dots} {target}", size=9, font="F3")
            page.y -= 16
        pages.append(page)
    return pages


def _footer_pages(pages: List[PdfPage], config: Dict[str, Any]) -> None:
    muted = (0.45, 0.48, 0.52)
    total = len(pages)
    for number, page in enumerate(pages, 1):
        if number == 1:
            continue
        page.line(MARGIN, 38, PAGE_WIDTH - MARGIN, 38, (0.75, 0.75, 0.75), 0.4)
        page.operations.append(
            f"BT /F1 8 Tf {muted[0]:.3f} {muted[1]:.3f} {muted[2]:.3f} rg "
            f"1 0 0 1 {MARGIN:.1f} 24 Tm (PwnReport {__version__}) Tj ET"
        )
        page.operations.append(
            f"BT /F1 8 Tf {muted[0]:.3f} {muted[1]:.3f} {muted[2]:.3f} rg "
            f"1 0 0 1 {PAGE_WIDTH - MARGIN - 70:.1f} 24 Tm (Page {number} of {total}) Tj ET"
        )


def _pdf_objects(pages: List[PdfPage], data: Dict[str, Any]) -> bytes:
    """Serialize page streams into a minimal valid PDF 1.4 document."""
    page_count = len(pages)
    font_ids = {"F1": 3, "F2": 4, "F3": 5}
    first_page_id = 6
    objects: Dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    }
    kids = []
    for index, page in enumerate(pages):
        page_id = first_page_id + (index * 2)
        stream_id = page_id + 1
        kids.append(f"{page_id} 0 R")
        resources = " ".join(f"/{name} {object_id} 0 R" for name, object_id in font_ids.items())
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << {resources} >> >> /Contents {stream_id} 0 R >>"
        ).encode("ascii")
        stream = page.stream()
        objects[stream_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream"
        )
    objects[2] = f"<< /Type /Pages /Count {page_count} /Kids [{' '.join(kids)}] >>".encode("ascii")
    info_id = first_page_id + (page_count * 2)
    objects[info_id] = (
        f"<< /Title ({_pdf_escape(data['project']['name'])}) "
        f"/Author ({_pdf_escape(data['project']['author'])}) "
        f"/Creator (PwnReport {__version__}) >>"
    ).encode("latin-1", errors="replace")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {0: 0}
    for object_id in range(1, info_id + 1):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {info_id + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for object_id in range(1, info_id + 1):
        output.extend(f"{offsets[object_id]:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {info_id + 1} /Root 1 0 R /Info {info_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def render_pdf(
    data: Dict[str, Any],
    template: Optional[str] = None,
    theme: Optional[str] = None,
) -> bytes:
    """Render a complete native PDF report as bytes."""
    config = effective_report_config(data, template=template, theme=theme)
    body, body_section_pages = _body_pages(data, config)
    toc = _toc_pages(data, config, body_section_pages)
    pages = [_cover_page(data, config), *toc, *body]
    _footer_pages(pages, config)
    return _pdf_objects(pages, data)
