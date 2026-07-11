"""Timeline Engine.

Merges timestamps from every artifact source (filesystem metadata,
registry, EVTX, browser history, network logs, module-contributed
events, plugin events, ...) into one unified, sortable chronology.

Every module in modules/ is expected to emit TimelineEvent-shaped
dicts; this engine only cares about the common shape, not the source
format, which keeps it decoupled from any single OS or artifact type.
"""
from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class TimelineEvent:
    timestamp: str          # ISO-8601, UTC preferred
    source: str              # e.g. "filesystem", "registry", "evtx", "browser"
    event_type: str          # e.g. "file_modified", "process_created", "login"
    description: str
    artifact_path: str | None = None
    evidence_id: str | None = None
    confidence: str = "medium"   # low | medium | high
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        # Fall back to epoch-min so malformed timestamps sort first,
        # not crash the whole merge.
        return datetime.min


class TimelineEngine:
    """Collects TimelineEvents from many sources and produces one chronology."""

    def __init__(self):
        self._events: list[TimelineEvent] = []

    def add_event(self, event: TimelineEvent) -> None:
        self._events.append(event)

    def add_events(self, events: Iterable[TimelineEvent]) -> None:
        self._events.extend(events)

    def ingest_metadata(self, file_metadata_iter: Iterable, evidence_id: str | None = None) -> None:
        """Turn FileMetadata objects (core.metadata) into timeline events,
        one per normalized timestamp field (created/modified/accessed/changed)."""
        for fm in file_metadata_iter:
            for kind, ts in fm.timestamps.items():
                self._events.append(TimelineEvent(
                    timestamp=ts,
                    source="filesystem",
                    event_type=f"file_{kind}",
                    description=f"{fm.path} {kind.replace('_', ' ')}",
                    artifact_path=fm.path,
                    evidence_id=evidence_id,
                    confidence="high",
                    tags=["filesystem", "metadata"],
                    raw={"size_bytes": fm.size_bytes, "mime_type": fm.mime_type},
                ))

    def merged(self, reverse: bool = False) -> list[TimelineEvent]:
        return sorted(self._events, key=lambda e: _parse_ts(e.timestamp), reverse=reverse)

    def filter(self, source: str | None = None, event_type: str | None = None,
               start: str | None = None, end: str | None = None) -> list[TimelineEvent]:
        events = self.merged()
        if source:
            events = [e for e in events if e.source == source]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if start:
            start_dt = _parse_ts(start)
            events = [e for e in events if _parse_ts(e.timestamp) >= start_dt]
        if end:
            end_dt = _parse_ts(end)
            events = [e for e in events if _parse_ts(e.timestamp) <= end_dt]
        return events

    # -- I/O -----------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.merged()], indent=2, default=str)

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def save_csv(self, path: str | Path) -> None:
        events = self.merged()
        fields = ["timestamp", "source", "event_type", "description",
                  "artifact_path", "evidence_id", "confidence", "tags"]
        with Path(path).open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for e in events:
                row = e.to_dict()
                row["tags"] = ",".join(row["tags"])
                row.pop("raw", None)
                writer.writerow({k: row.get(k, "") for k in fields})

    @classmethod
    def load_json(cls, path: str | Path) -> TimelineEngine:
        engine = cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for d in data:
            engine.add_event(TimelineEvent(**d))
        return engine
