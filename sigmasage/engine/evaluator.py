"""Evaluate JSON/NDJSON events against compiled Sigma-style rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sigmasage.alerts.models import AlertRecord
from sigmasage.rules.compiler import CompiledRule


class EvaluationError(ValueError):
    """Raised when input events are malformed or unsupported."""


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load events from JSON array/object or NDJSON."""

    input_path = Path(path)
    text = input_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
            return payload
        raise EvaluationError("JSON input must be an object or list of objects")
    except json.JSONDecodeError:
        events: list[dict[str, Any]] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvaluationError(f"invalid NDJSON at line {line_no}: {exc}") from exc
            if not isinstance(record, dict):
                raise EvaluationError(f"NDJSON record at line {line_no} is not an object")
            events.append(record)
        return events


def evaluate_events(events: list[dict[str, Any]], rules: list[CompiledRule]) -> list[AlertRecord]:
    """Run compiled rules against each event and return alert records."""

    alerts: list[AlertRecord] = []
    for event_index, event in enumerate(events):
        for rule in rules:
            if rule.predicate(event):
                alerts.append(
                    AlertRecord(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        rule_source=rule.source_path,
                        event_index=event_index,
                        event=event,
                    )
                )
    return alerts
