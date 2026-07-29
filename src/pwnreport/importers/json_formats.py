"""Importers for JSON and JSONL scanner exports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .common import (
    ImporterError,
    clean_text,
    normalized_finding,
    read_import_bytes,
    require_findings,
    string_list,
)


def _decode_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ImporterError(f"{label} export must use UTF-8 encoding") from exc
    except json.JSONDecodeError as exc:
        raise ImporterError(
            f"Invalid {label} JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def _decode_jsonl(data: bytes, label: str) -> List[Any]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImporterError(f"{label} export must use UTF-8 encoding") from exc
    records: List[Any] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ImporterError(
                f"Invalid {label} JSONL at line {number}: {exc.msg}"
            ) from exc
    return records


def _records_from_json_or_jsonl(data: bytes, label: str) -> List[Any]:
    stripped = data.lstrip()
    if stripped.startswith(b"["):
        decoded = _decode_json(data, label)
        if not isinstance(decoded, list):
            raise ImporterError(f"{label} export root must be an array")
        return decoded
    if stripped.startswith(b"{"):
        try:
            decoded = _decode_json(data, label)
        except ImporterError:
            return _decode_jsonl(data, label)
        if isinstance(decoded, dict):
            return [decoded]
        raise ImporterError(f"{label} export must contain JSON objects")
    return _decode_jsonl(data, label)


def parse_nuclei(path: Path) -> List[Dict[str, Any]]:
    """Parse Nuclei JSONL or JSON array output."""
    records = _records_from_json_or_jsonl(read_import_bytes(path), "Nuclei")
    findings: List[Dict[str, Any]] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ImporterError(f"Nuclei record {index} must be a JSON object")
        raw_info = record.get("info")
        info: Dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
        raw_classification = info.get("classification")
        classification: Dict[str, Any] = (
            raw_classification if isinstance(raw_classification, dict) else {}
        )
        references = string_list(info.get("reference"))
        references.extend(string_list(classification.get("cwe-id")))
        references.extend(string_list(classification.get("cve-id")))
        request = clean_text(record.get("request"))
        response = clean_text(record.get("response"))
        evidence_parts = []
        if record.get("matcher-name"):
            evidence_parts.append(f"Matcher: {record['matcher-name']}")
        if record.get("extracted-results"):
            evidence_parts.append(
                "Extracted: " + ", ".join(string_list(record["extracted-results"]))
            )
        if request:
            evidence_parts.append("Request:\n" + request)
        if response:
            evidence_parts.append("Response:\n" + response)
        asset = (
            record.get("matched-at")
            or record.get("host")
            or record.get("url")
            or record.get("ip")
        )
        finding = normalized_finding(
            title=info.get("name") or record.get("template-id"),
            severity=info.get("severity"),
            affected_asset=asset,
            description=info.get("description"),
            impact=info.get("impact"),
            evidence="\n\n".join(evidence_parts),
            remediation=info.get("remediation"),
            references=references,
            cvss_vector=classification.get("cvss-metrics"),
            cvss_score=classification.get("cvss-score"),
            source_tool="nuclei",
            source_id=record.get("template-id"),
        )
        findings.append(finding)
    return require_findings(findings, "Nuclei")


def _custom_records(decoded: Any) -> List[Any]:
    if isinstance(decoded, list):
        return decoded
    if isinstance(decoded, dict) and isinstance(decoded.get("findings"), list):
        return decoded["findings"]
    if isinstance(decoded, dict):
        return [decoded]
    raise ImporterError(
        "Custom JSON must be a finding object, an array, or an object with findings[]"
    )


def parse_custom(path: Path) -> List[Dict[str, Any]]:
    """Parse generic JSON findings using common field aliases."""
    records = _custom_records(_decode_json(read_import_bytes(path), "custom"))
    findings: List[Dict[str, Any]] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ImporterError(f"Custom finding {index} must be a JSON object")
        affected = (
            record.get("affected_asset")
            or record.get("asset")
            or record.get("host")
            or record.get("url")
            or record.get("target")
        )
        description = (
            record.get("description")
            or record.get("detail")
            or record.get("summary")
        )
        evidence = record.get("evidence") or record.get("proof") or record.get("output")
        remediation = (
            record.get("remediation")
            or record.get("recommendation")
            or record.get("solution")
        )
        references = record.get("references") or record.get("reference")
        references = string_list(references)
        references.extend(string_list(record.get("cwe")))
        references.extend(string_list(record.get("cve")))
        finding = normalized_finding(
            title=record.get("title") or record.get("name"),
            severity=record.get("severity") or record.get("risk"),
            affected_asset=affected,
            description=description,
            impact=record.get("impact"),
            evidence=evidence,
            remediation=remediation,
            references=references,
            cvss_vector=(
                record["cvss_vector"]
                if "cvss_vector" in record
                else record.get("cvss-vector")
            ),
            cvss_score=(
                record["cvss_score"]
                if "cvss_score" in record
                else record.get("cvss-score")
            ),
            source_tool="custom",
            source_id=record.get("id") or record.get("source_id"),
        )
        steps = record.get("reproduction_steps") or record.get("steps")
        normalized_steps = string_list(steps)
        if normalized_steps:
            finding["reproduction_steps"] = normalized_steps
        status = record.get("remediation_status") or record.get("status")
        if status in ("open", "in_progress", "resolved", "accepted"):
            finding["remediation_status"] = status
        findings.append(finding)
    return require_findings(findings, "custom JSON")
