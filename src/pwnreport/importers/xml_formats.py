"""Importers for XML scanner exports."""

from __future__ import annotations

import base64
import binascii
import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from .common import (
    ImporterError,
    clean_text,
    compact_text,
    normalized_finding,
    read_import_bytes,
    require_findings,
    string_list,
)

TAG_RE = re.compile(r"<[^>]+>")


def _parse_xml(path: Path, label: str) -> ET.Element:
    data = read_import_bytes(path)
    upper = data[:65536].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ImporterError(f"{label} XML with DOCTYPE or ENTITY declarations is not supported")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ImporterError(f"Invalid {label} XML: {exc}") from exc


def _element_text(element: Optional[ET.Element], default: str = "") -> str:
    if element is None:
        return default
    raw = "".join(element.itertext())
    unescaped = html.unescape(raw)
    return clean_text(TAG_RE.sub(" ", unescaped), default)


def _child_text(parent: ET.Element, name: str, default: str = "") -> str:
    return _element_text(parent.find(name), default)


def _decode_burp_blob(element: Optional[ET.Element]) -> str:
    if element is None or element.text is None:
        return ""
    value = element.text.strip()
    if element.get("base64", "false").lower() == "true":
        compact_value = "".join(value.split())
        try:
            return base64.b64decode(compact_value, validate=True).decode(
                "utf-8", errors="replace"
            )
        except (binascii.Error, ValueError):
            return "[Invalid base64 data in Burp export]"
    return value


def parse_burp(path: Path) -> List[Dict[str, Any]]:
    """Parse Burp Suite XML issue exports."""
    root = _parse_xml(path, "Burp")
    findings: List[Dict[str, Any]] = []
    for issue in root.findall(".//issue"):
        host = _child_text(issue, "host")
        path_value = _child_text(issue, "path")
        location = _child_text(issue, "location")
        asset = location or (host.rstrip("/") + path_value if host else path_value)
        detail = _child_text(issue, "issueDetail")
        background = _child_text(issue, "issueBackground")
        description = "\n\n".join(part for part in (detail, background) if part)
        remediation = "\n\n".join(
            part
            for part in (
                _child_text(issue, "remediationDetail"),
                _child_text(issue, "remediationBackground"),
            )
            if part
        )
        evidence_parts: List[str] = []
        confidence = _child_text(issue, "confidence")
        if confidence:
            evidence_parts.append(f"Burp confidence: {confidence}")
        for pair_index, pair in enumerate(issue.findall(".//requestresponse"), 1):
            request = _decode_burp_blob(pair.find("request"))
            response = _decode_burp_blob(pair.find("response"))
            if request:
                evidence_parts.append(f"Request {pair_index}:\n{request}")
            if response:
                evidence_parts.append(f"Response {pair_index}:\n{response}")
        references = string_list(_child_text(issue, "type"))
        findings.append(
            normalized_finding(
                title=_child_text(issue, "name"),
                severity=_child_text(issue, "severity"),
                affected_asset=asset,
                description=description,
                impact=_child_text(issue, "issueBackground"),
                evidence="\n\n".join(evidence_parts),
                remediation=remediation,
                references=references,
                source_tool="burp",
                source_id=_child_text(issue, "serialNumber") or _child_text(issue, "type"),
            )
        )
    return require_findings(findings, "Burp")


def _nmap_host_asset(host: ET.Element) -> str:
    hostname = host.find("./hostnames/hostname")
    if hostname is not None and hostname.get("name"):
        return hostname.get("name", "")
    for address_type in ("ipv4", "ipv6", "mac"):
        for address in host.findall("address"):
            if address.get("addrtype") == address_type and address.get("addr"):
                return address.get("addr", "")
    return "Unspecified host"


def parse_nmap(path: Path) -> List[Dict[str, Any]]:
    """Parse Nmap XML and create one informational finding per open port."""
    root = _parse_xml(path, "Nmap")
    findings: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        host_asset = _nmap_host_asset(host)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            protocol = port.get("protocol", "tcp")
            port_id = port.get("portid", "unknown")
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            fingerprint_parts: List[str] = [f"State: open", f"Service: {service_name}"]
            if service is not None:
                product = compact_text(service.get("product"))
                version = compact_text(service.get("version"))
                extra = compact_text(service.get("extrainfo"))
                fingerprint = " ".join(part for part in (product, version, extra) if part)
                if fingerprint:
                    fingerprint_parts.append(f"Fingerprint: {fingerprint}")
            for script in port.findall("script"):
                script_id = compact_text(script.get("id"), "script")
                output = clean_text(script.get("output"))
                if output:
                    fingerprint_parts.append(f"{script_id}: {output}")
            asset = f"{host_asset}:{port_id}/{protocol}"
            findings.append(
                normalized_finding(
                    title=f"Open {protocol.upper()} port {port_id} ({service_name})",
                    severity="info",
                    affected_asset=asset,
                    description=(
                        f"Nmap identified an open {protocol.upper()} service on port "
                        f"{port_id}. Validate that the service is expected and required."
                    ),
                    impact=(
                        "Exposed services increase the reachable attack surface and may "
                        "require additional configuration or vulnerability review."
                    ),
                    evidence="\n".join(fingerprint_parts),
                    remediation=(
                        "Restrict unnecessary network exposure and harden the service "
                        "according to organizational requirements."
                    ),
                    source_tool="nmap",
                    source_id=f"{host_asset}:{port_id}/{protocol}",
                )
            )
    return require_findings(findings, "Nmap")


def _nessus_host_asset(report_host: ET.Element) -> str:
    """Choose the most descriptive stable host identity from Nessus metadata."""
    properties: Dict[str, str] = {}
    for tag in report_host.findall("./HostProperties/tag"):
        key = tag.get("name")
        value = _element_text(tag)
        if key and value:
            properties[key] = value
    for key in ("host-fqdn", "hostname", "host-ip"):
        if properties.get(key):
            return properties[key]
    return compact_text(report_host.get("name"), "Unspecified host")


def parse_nessus(path: Path) -> List[Dict[str, Any]]:
    """Parse Nessus .nessus XML exports."""
    root = _parse_xml(path, "Nessus")
    findings: List[Dict[str, Any]] = []
    for report_host in root.findall(".//ReportHost"):
        host_asset = _nessus_host_asset(report_host)
        for item in report_host.findall("ReportItem"):
            port = compact_text(item.get("port"), "0")
            protocol = compact_text(item.get("protocol"), "tcp")
            service = compact_text(item.get("svc_name"))
            asset = host_asset
            if port not in ("", "0"):
                asset = f"{host_asset}:{port}/{protocol}"
            references: List[str] = []
            for tag in ("cve", "cwe", "bid", "xref", "see_also"):
                for element in item.findall(tag):
                    references.extend(string_list(_element_text(element)))
            plugin_id = item.get("pluginID")
            evidence_parts = []
            if service:
                evidence_parts.append(f"Service: {service}")
            plugin_output = _child_text(item, "plugin_output")
            if plugin_output:
                evidence_parts.append(plugin_output)
            findings.append(
                normalized_finding(
                    title=item.get("pluginName") or _child_text(item, "plugin_name"),
                    severity=_child_text(item, "risk_factor") or item.get("severity"),
                    affected_asset=asset,
                    description=_child_text(item, "description") or _child_text(item, "synopsis"),
                    impact=_child_text(item, "synopsis"),
                    evidence="\n\n".join(evidence_parts),
                    remediation=_child_text(item, "solution"),
                    references=references,
                    cvss_vector=(
                        _child_text(item, "cvss3_vector")
                        or _child_text(item, "cvss_vector")
                    ),
                    cvss_score=(
                        _child_text(item, "cvss3_base_score")
                        or _child_text(item, "cvss_base_score")
                    ),
                    source_tool="nessus",
                    source_id=plugin_id,
                )
            )
    return require_findings(findings, "Nessus")
