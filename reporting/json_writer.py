import json
import os
from datetime import datetime
from typing import Any, Dict, List

from core import __app_name__, __version__


def export_json_report(
    target_host: str,
    open_findings: List[Dict[str, Any]],
    scan_mode: str,
    ports_scanned: int = 0,
    duration_seconds: float = 0.0,
    output_dir: str = ".",
) -> str:
    """
    Writes the same scan results as a structured JSON document, intended for
    feeding into other tooling (CI pipelines, dashboards, SIEMs, etc.).
    Returns the path to the written file.
    """
    os.makedirs(output_dir, exist_ok=True)
    report_filename = os.path.join(output_dir, f"nexus_audit_{target_host.replace('.', '_')}.json")

    payload = {
        "generator": f"{__app_name__} v{__version__}",
        "target": target_host,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "scan_mode": scan_mode,
        "ports_scanned": ports_scanned,
        "duration_seconds": round(duration_seconds, 2),
        "total_open_ports": len(open_findings),
        "findings": open_findings,
    }

    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return report_filename
