"""Shared schema constants for PwnReport."""

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}
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
)
