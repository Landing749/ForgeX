"""macOS Module.

Covers: Unified Logs, LaunchAgents, Spotlight, Quarantine, Safari.

LaunchAgents/LaunchDaemons are XML or binary plists -- fully parseable
with the stdlib `plistlib`. Quarantine attributes and Safari history
are SQLite databases, parseable with stdlib `sqlite3`. Unified Logs
(.logarchive / tracev3) and Spotlight (.store databases) are
proprietary binary formats requiring Apple's own tooling (`log show`)
or the `mac_apt`/`macos-UnifiedLogs` ecosystem, so those remain
documented extension points.
"""
from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path
from typing import Any


def parse_launch_agent(path: str | Path) -> dict[str, Any]:
    """Parse a LaunchAgent/LaunchDaemon .plist (persistence mechanism)."""
    with Path(path).open("rb") as fh:
        data = plistlib.load(fh)
    return {
        "path": str(path),
        "label": data.get("Label"),
        "program": data.get("Program") or (data.get("ProgramArguments") or [None])[0],
        "program_arguments": data.get("ProgramArguments"),
        "run_at_load": data.get("RunAtLoad"),
        "keep_alive": data.get("KeepAlive"),
        "start_interval": data.get("StartInterval"),
        "watch_paths": data.get("WatchPaths"),
        "raw": data,
    }


def list_launch_agents(directory: str | Path) -> list[dict[str, Any]]:
    results = []
    for plist_path in Path(directory).glob("*.plist"):
        try:
            results.append(parse_launch_agent(plist_path))
        except Exception as exc:  # noqa: BLE001 - keep scanning other plists
            results.append({"path": str(plist_path), "error": str(exc)})
    return results


def parse_safari_history(history_db_path: str | Path, limit: int = 5000) -> list[dict[str, Any]]:
    """Parse Safari's History.db (SQLite). Safari stores visit_time as
    Mac absolute time (seconds since 2001-01-01), so we convert to
    Unix epoch for consistency with the rest of Forgex."""
    MAC_EPOCH_OFFSET = 978307200  # seconds between 1970-01-01 and 2001-01-01

    con = sqlite3.connect(f"file:{history_db_path}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT hi.url, hv.visit_time, hv.title
            FROM history_visits hv
            JOIN history_items hi ON hi.id = hv.history_item
            ORDER BY hv.visit_time DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()

    results = []
    for url, visit_time, title in rows:
        epoch = (visit_time + MAC_EPOCH_OFFSET) if visit_time else None
        results.append({"url": url, "title": title, "visit_time_epoch": epoch})
    return results


def parse_quarantine_events(db_path: str | Path, limit: int = 5000) -> list[dict[str, Any]]:
    """Parse com.apple.LaunchServices.QuarantineEventsV2 (SQLite) -- records
    files downloaded from the internet, a strong exfiltration/delivery
    timeline source."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
                   LSQuarantineAgentName, LSQuarantineDataURLString,
                   LSQuarantineOriginURLString
            FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    return [
        {"event_id": r[0], "timestamp_mac_absolute": r[1], "agent": r[2],
         "data_url": r[3], "origin_url": r[4]}
        for r in rows
    ]


def parse_unified_logs(_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "Unified Log (.logarchive/tracev3) parsing requires Apple's binary "
        "format decoder; use `log show --archive <path> --style json` as a "
        "host-tool extension point, or the `macos-UnifiedLogs` Rust crate."
    )


def query_spotlight(_store_path: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "Spotlight store.db parsing requires reverse-engineered proprietary "
        "structures; use `mdfind`/`mdls` as a host-tool extension point on "
        "a live/mounted macOS volume."
    )
