"""Browser Module.

Covers: History, downloads, cookies, cache, sessions, extensions.

Chromium (Chrome/Edge/Brave) and Firefox both store history/downloads/
cookies in SQLite databases with documented schemas, so those are
fully implemented here using stdlib `sqlite3`. Cache, session
restore, and extension manifests use browser-specific binary/JSON
formats handled per-function below (JSON-based ones work fully;
binary cache formats are extension points).
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chrome_time_to_iso(webkit_micros: int | None) -> str | None:
    if not webkit_micros:
        return None
    return (CHROME_EPOCH + timedelta(microseconds=webkit_micros)).isoformat()


def _readonly_connect(db_path: str | Path) -> sqlite3.Connection:
    """SQLite requires the file not be locked by the live browser; copy to
    a temp file so Forgex stays read-only against the original evidence."""
    src = Path(db_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="forgex_browser_"))
    tmp_path = tmp_dir / src.name
    shutil.copy2(src, tmp_path)
    # Copy WAL/SHM sidecar files if present, so uncommitted data is included.
    for suffix in ("-wal", "-shm"):
        sidecar = src.with_name(src.name + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, tmp_path.with_name(tmp_path.name + suffix))
    return sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)


def parse_chrome_history(history_db_path: str | Path, limit: int = 5000) -> list[dict[str, Any]]:
    con = _readonly_connect(history_db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT urls.url, urls.title, visits.visit_time, visits.transition
            FROM visits JOIN urls ON urls.id = visits.url
            ORDER BY visits.visit_time DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    return [{"url": u, "title": t, "visit_time": _chrome_time_to_iso(vt), "transition": tr}
            for u, t, vt, tr in rows]


def parse_chrome_downloads(history_db_path: str | Path, limit: int = 2000) -> list[dict[str, Any]]:
    con = _readonly_connect(history_db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT target_path, tab_url, start_time, end_time, received_bytes, total_bytes, state
            FROM downloads ORDER BY start_time DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    return [
        {"target_path": tp, "source_url": url, "start_time": _chrome_time_to_iso(st),
         "end_time": _chrome_time_to_iso(et), "received_bytes": rb, "total_bytes": tb, "state": state}
        for tp, url, st, et, rb, tb, state in rows
    ]


def parse_chrome_cookies(cookies_db_path: str | Path, limit: int = 5000) -> list[dict[str, Any]]:
    con = _readonly_connect(cookies_db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT host_key, name, value, creation_utc, expires_utc, is_secure, is_httponly
            FROM cookies LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    return [
        {"host": h, "name": n, "value_present": bool(v), "created": _chrome_time_to_iso(c),
         "expires": _chrome_time_to_iso(e), "secure": bool(s), "http_only": bool(ho)}
        for h, n, v, c, e, s, ho in rows
    ]


def parse_firefox_places(places_db_path: str | Path, limit: int = 5000) -> list[dict[str, Any]]:
    """Firefox stores history in places.sqlite; moz_historyvisits.visit_date
    is microseconds since Unix epoch."""
    con = _readonly_connect(places_db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT p.url, p.title, h.visit_date
            FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id
            ORDER BY h.visit_date DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    results = []
    for url, title, visit_date in rows:
        iso = datetime.fromtimestamp(visit_date / 1_000_000, tz=timezone.utc).isoformat() if visit_date else None
        results.append({"url": url, "title": title, "visit_time": iso})
    return results


def parse_firefox_downloads(places_db_path: str | Path, limit: int = 2000) -> list[dict[str, Any]]:
    """Modern Firefox stores downloads as moz_annos on moz_places rows."""
    con = _readonly_connect(places_db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT p.url, a.content, a.dateAdded
            FROM moz_annos a JOIN moz_places p ON p.id = a.place_id
            JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id
            WHERE attr.name LIKE '%downloads%' ORDER BY a.dateAdded DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    finally:
        con.close()
    results = []
    for url, content, date_added in rows:
        iso = datetime.fromtimestamp(date_added / 1_000_000, tz=timezone.utc).isoformat() if date_added else None
        results.append({"url": url, "detail": content, "date_added": iso})
    return results


def parse_extensions_manifest(extension_dir: str | Path) -> dict[str, Any]:
    """Chromium and Firefox extensions both ship a manifest.json (or
    manifest.json inside a versioned subdir for Chrome)."""
    ext_dir = Path(extension_dir)
    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.exists():
        candidates = list(ext_dir.glob("*/manifest.json"))
        if candidates:
            manifest_path = candidates[0]
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json found under {ext_dir}")
    data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
    return {
        "path": str(manifest_path),
        "name": data.get("name"),
        "version": data.get("version"),
        "permissions": data.get("permissions"),
        "host_permissions": data.get("host_permissions"),
        "background": data.get("background"),
    }


def parse_session_restore(session_json_path: str | Path) -> Any:
    """Firefox sessionstore.jsonlz4 must be LZ4-decompressed first (see
    note below); a plain sessionstore-backups/*.json (uncompressed) or a
    Chromium 'Sessions'/'Tabs' JSON snapshot parses directly."""
    p = Path(session_json_path)
    if p.suffix == ".jsonlz4":
        raise NotImplementedError(
            "Firefox .jsonlz4 session files use Mozilla's custom LZ4 "
            "framing; decompress with the optional 'lz4' package "
            "(mozlz4 variant) before passing plain JSON here."
        )
    return json.loads(p.read_text(encoding="utf-8", errors="ignore"))


def parse_cache(_cache_dir: str | Path) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "Chromium 'Simple Cache' / Firefox cache2 are custom binary "
        "block-file formats; implement via a plugin using e.g. "
        "`chrome_cache_parser` conventions or Mozilla's cache2 spec."
    )
