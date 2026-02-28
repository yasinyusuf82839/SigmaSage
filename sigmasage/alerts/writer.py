"""Output deterministic alert and evidence bundles."""

from __future__ import annotations

import json
from pathlib import Path

from sigmasage.alerts.models import AlertRecord


def _normalize_output_paths(output: str | Path) -> tuple[Path, Path]:
    output_path = Path(output)
    if output_path.suffix.lower() == ".json":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        alerts_path = output_path
        evidence_path = output_path.with_name(f"{output_path.stem}.evidence.ndjson")
    else:
        output_path.mkdir(parents=True, exist_ok=True)
        alerts_path = output_path / "alerts.json"
        evidence_path = output_path / "evidence.ndjson"
    return alerts_path, evidence_path


def write_alert_bundle(alerts: list[AlertRecord], output: str | Path) -> tuple[Path, Path]:
    """Write deterministic alert JSON and NDJSON evidence output."""

    alerts_path, evidence_path = _normalize_output_paths(output)

    sorted_alerts = sorted(
        alerts,
        key=lambda item: (item.rule_id, item.event_index, json.dumps(item.event, sort_keys=True)),
    )
    serialized = [alert.to_dict() for alert in sorted_alerts]

    alerts_path.write_text(
        json.dumps(serialized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with evidence_path.open("w", encoding="utf-8") as handle:
        for alert in sorted_alerts:
            evidence = {
                "rule_id": alert.rule_id,
                "event_index": alert.event_index,
                "event": alert.event,
            }
            handle.write(json.dumps(evidence, sort_keys=True) + "\n")

    return alerts_path, evidence_path
