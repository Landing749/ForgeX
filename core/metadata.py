"""Metadata Engine.

Normalizes file-level metadata into a consistent shape regardless of
source platform: timestamps, hashes, entropy, and (best-effort, when
optional dependencies are present) EXIF/GPS/owner/signature data.

This module intentionally has zero hard dependencies beyond the
standard library so it always works; richer extraction (EXIF, code
signing, etc.) is layered on top when optional libraries are
installed, following the same pattern the Windows/Linux/macOS/Browser/
Network/Malware modules use for their own optional native libraries.
"""
from __future__ import annotations

import json
import math
import mimetypes
import os
import stat as stat_module
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.evidence import compute_hashes


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte over the given buffer (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_entropy(path: Path, sample_bytes: int = 4 * 1024 * 1024) -> float:
    with path.open("rb") as fh:
        data = fh.read(sample_bytes)
    return shannon_entropy(data)


def _ts(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


@dataclass
class FileMetadata:
    path: str
    size_bytes: int
    mime_type: str | None
    hashes: dict[str, str]
    entropy: float
    timestamps: dict[str, str]
    owner_uid: int | None
    permissions: str
    is_signed: bool | None = None
    exif: dict[str, Any] = field(default_factory=dict)
    gps: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MetadataEngine:
    """Extracts and normalizes metadata for a single file."""

    def __init__(self, hash_algorithms: tuple[str, ...] = ("sha256", "md5")):
        self.hash_algorithms = hash_algorithms

    def extract(self, path: str | Path) -> FileMetadata:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        st = p.stat()

        timestamps = {
            "modified": _ts(st.st_mtime),
            "accessed": _ts(st.st_atime),
            # ctime is "metadata changed" on POSIX, "created" on Windows
            "changed_or_created": _ts(st.st_ctime),
        }
        if hasattr(st, "st_birthtime"):
            timestamps["created"] = _ts(st.st_birthtime)  # type: ignore[attr-defined]

        mime_type, _ = mimetypes.guess_type(str(p))
        hashes = compute_hashes(p, self.hash_algorithms) if p.is_file() else {}
        entropy = file_entropy(p) if p.is_file() else 0.0
        owner_uid = st.st_uid if hasattr(st, "st_uid") else None
        permissions = stat_module.filemode(st.st_mode)

        exif, gps = self._try_extract_exif(p, mime_type)

        return FileMetadata(
            path=str(p),
            size_bytes=st.st_size,
            mime_type=mime_type,
            hashes=hashes,
            entropy=entropy,
            timestamps=timestamps,
            owner_uid=owner_uid,
            permissions=permissions,
            exif=exif,
            gps=gps,
        )

    @staticmethod
    def _try_extract_exif(path: Path, mime_type: str | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Best-effort EXIF/GPS extraction for images.

        Uses Pillow if available; otherwise returns empty results rather
        than failing the whole metadata pass. This is an intentional
        soft-dependency extension point (see modules/ for the same
        pattern applied to OS/browser/network/malware artifacts).
        """
        if not mime_type or not mime_type.startswith("image/"):
            return {}, None
        try:
            from PIL import Image
            from PIL.ExifTags import GPSTAGS, TAGS
        except ImportError:
            return {}, None

        try:
            with Image.open(path) as img:
                raw = img._getexif() or {}
        except Exception:
            return {}, None

        exif: dict[str, Any] = {}
        gps: dict[str, Any] = {}
        for tag_id, value in raw.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo" and isinstance(value, dict):
                for gps_id, gps_value in value.items():
                    gps[GPSTAGS.get(gps_id, gps_id)] = gps_value
            else:
                try:
                    json.dumps(value)  # only keep JSON-serializable values
                    exif[tag] = value
                except TypeError:
                    exif[tag] = str(value)
        return exif, (gps or None)


def walk_metadata(root: str | Path, hash_algorithms: tuple[str, ...] = ("sha256", "md5")):
    """Generator yielding FileMetadata for every regular file under root."""
    engine = MetadataEngine(hash_algorithms)
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            fp = Path(dirpath) / name
            try:
                yield engine.extract(fp)
            except (FileNotFoundError, PermissionError, OSError):
                continue
