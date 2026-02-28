"""Alert data models for deterministic output."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class AlertRecord:
    """Minimal alert record produced by the vertical-slice engine."""

    rule_id: str
    rule_title: str
    event_index: int
    event: dict[str, Any]
    rule_source: str | None = None
    alert_version: str = "v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
