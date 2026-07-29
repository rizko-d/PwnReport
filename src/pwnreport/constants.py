"""Shared schema constants for PwnReport."""

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}

REMEDIATION_STATUSES = ("open", "in_progress", "resolved", "accepted")
EXPORT_FORMATS = ("html", "pdf", "markdown")
REPORT_TEMPLATES = ("technical", "executive")
REPORT_THEMES = ("dark", "light")

PROJECT_FIELDS = ("name", "client", "assessment_type", "classification", "author")

FINDING_FIELDS = (
    "id",
    "title",
    "severity",
    "affected_asset",
    "description",
    "impact",
    "evidence",
    "remediation",
    "reproduction_steps",
    "references",
    "cvss_vector",
    "cvss_score",
    "remediation_status",
)

REQUIRED_FINDING_FIELDS = (
    "id",
    "title",
    "severity",
    "affected_asset",
    "description",
    "impact",
    "evidence",
    "remediation",
)
