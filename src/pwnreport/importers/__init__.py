"""Scanner import dispatcher for PwnReport."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List

from .common import ImporterError
from .json_formats import parse_custom, parse_nuclei
from .xml_formats import parse_burp, parse_nessus, parse_nmap

Importer = Callable[[Path], List[Dict[str, Any]]]

IMPORTERS: Dict[str, Importer] = {
    "nuclei": parse_nuclei,
    "burp": parse_burp,
    "nmap": parse_nmap,
    "nessus": parse_nessus,
    "custom": parse_custom,
}


def parse_import(tool: str, source: Path) -> List[Dict[str, Any]]:
    """Parse one supported scanner export."""
    importer = IMPORTERS.get(tool.lower())
    if importer is None:
        raise ImporterError(f"Unsupported importer: {tool}")
    return importer(source)


__all__ = ["IMPORTERS", "ImporterError", "parse_import"]
