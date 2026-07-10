"""Filesystem Module.

Support target: NTFS, FAT, exFAT, ext4, APFS, HFS+, XFS (per spec,
via mounted/exposed paths or a disk-image backend from modules/disk).

Commands: fs tree, fs deleted, fs recover, fs search, fs timeline,
fs ads, fs slack.

`tree`, `search`, and `timeline` are fully working against any mounted
path (live filesystem, mounted image, or extracted evidence
directory). `deleted`, `recover`, `ads`, and `slack` require low-level
volume access (MFT parsing, journal replay, raw sector reads) that is
out of scope for a pure-Python stdlib implementation; these are
defined here as the stable interface that a native backend (e.g. via
modules/disk + pytsk3/dissect) plugs into.
"""
from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from core.metadata import MetadataEngine


def tree(root: str | Path, max_depth: int | None = None) -> dict[str, Any]:
    """Return a nested dict representing the directory tree under root."""
    root = Path(root)

    def _walk(path: Path, depth: int) -> dict[str, Any]:
        node: dict[str, Any] = {"name": path.name or str(path), "path": str(path)}
        if path.is_dir():
            node["type"] = "dir"
            if max_depth is not None and depth >= max_depth:
                node["children"] = "..."
                return node
            children = []
            try:
                for entry in sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name.lower())):
                    children.append(_walk(entry, depth + 1))
            except PermissionError:
                children = []
            node["children"] = children
        else:
            node["type"] = "file"
            try:
                node["size_bytes"] = path.stat().st_size
            except OSError:
                node["size_bytes"] = None
        return node

    return _walk(root, 0)


def search(root: str | Path, pattern: str, regex: bool = False,
           search_content: bool = False, max_results: int = 1000) -> list[dict[str, Any]]:
    """Search filenames (glob or regex) and, optionally, file contents."""
    root = Path(root)
    results: list[dict[str, Any]] = []
    matcher = re.compile(pattern) if regex else None

    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if len(results) >= max_results:
                return results
            full_path = Path(dirpath) / name
            name_match = matcher.search(name) if regex else fnmatch.fnmatch(name, pattern)
            content_match = None
            if search_content and not name_match:
                content_match = _search_content(full_path, pattern, regex)
            if name_match or content_match:
                results.append({
                    "path": str(full_path),
                    "matched_on": "name" if name_match else "content",
                    "line": content_match,
                })
    return results


def _search_content(path: Path, pattern: str, regex: bool) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i > 100_000:
                    break
                if (regex and re.search(pattern, line)) or (not regex and pattern in line):
                    return line.strip()[:200]
    except (OSError, UnicodeDecodeError):
        return None
    return None


def timeline(root: str | Path) -> Iterator[dict[str, Any]]:
    """Yield MACB-style timestamp events for every file under root."""
    engine = MetadataEngine()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            fp = Path(dirpath) / name
            try:
                fm = engine.extract(fp)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            for kind, ts in fm.timestamps.items():
                yield {"path": str(fp), "timestamp": ts, "kind": kind}


# -- extension points requiring a native volume backend --------------------
def deleted(_volume_path: str | Path) -> list[dict[str, Any]]:
    """List recoverable deleted file records (requires MFT/journal parsing
    via a native backend such as pytsk3/dissect; not available in the
    pure-Python core)."""
    raise NotImplementedError(
        "fs deleted requires a native filesystem backend (e.g. pytsk3) "
        "which is not bundled with core Forgex. See modules/disk for the "
        "disk-image integration point."
    )


def recover(_volume_path: str | Path, _record_id: str, _dest: str | Path) -> None:
    raise NotImplementedError("fs recover requires a native filesystem backend.")


def ads(_ntfs_path: str | Path) -> list[dict[str, Any]]:
    """List NTFS Alternate Data Streams. On a live Windows/NTFS mount this
    can be done via `dir /r` or the Windows API; from a raw image it needs
    MFT attribute parsing. Both are native-backend extension points."""
    raise NotImplementedError("fs ads requires NTFS-aware access (native backend).")


def slack(_volume_path: str | Path) -> list[dict[str, Any]]:
    """Recover file slack space. Requires raw cluster/sector access."""
    raise NotImplementedError("fs slack requires raw volume access (native backend).")
