"""Evidence Engine.

Responsibilities (per spec):
    - Chain of custody
    - Hash verification
    - Evidence catalog

Forgex is read-only by default: adding evidence never modifies the
source file. All engine state lives in a per-case JSON catalog so the
CLI, investigation profiles, and reports can share a single source of
truth without a database dependency.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_hashes(path: Path, algorithms: Iterable[str] = ("sha256", "md5")) -> dict[str, str]:
    """Stream a file once, computing every requested digest in parallel."""
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    with path.open("rb") as fh:
        while chunk := fh.read(HASH_CHUNK_SIZE):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}


@dataclass
class CustodyEvent:
    timestamp: str
    action: str
    actor: str
    detail: str = ""


@dataclass
class EvidenceItem:
    id: str
    name: str
    original_path: str
    added_at: str
    size_bytes: int
    hashes: dict[str, str]
    evidence_type: str = "file"
    notes: str = ""
    custody: list[CustodyEvent] = field(default_factory=list)
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceItem:
        custody = [CustodyEvent(**c) for c in d.get("custody", [])]
        d = {**d, "custody": custody}
        return cls(**d)


class EvidenceCatalogError(Exception):
    pass


class EvidenceEngine:
    """Manages the evidence catalog for a single case directory.

    Catalog layout on disk:
        <case_dir>/catalog.json     -- evidence index + chain of custody
        <case_dir>/evidence/<id>/   -- optional copy of the ingested file
    """

    def __init__(self, case_dir: str | Path, algorithms: Iterable[str] = ("sha256", "md5")):
        self.case_dir = Path(case_dir)
        self.catalog_path = self.case_dir / "catalog.json"
        self.algorithms = tuple(algorithms)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        if not self.catalog_path.exists():
            self._write_catalog({"items": []})

    # -- persistence -----------------------------------------------------
    def _read_catalog(self) -> dict[str, Any]:
        with self.catalog_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_catalog(self, data: dict[str, Any]) -> None:
        tmp = self.catalog_path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        tmp.replace(self.catalog_path)

    # -- commands ----------------------------------------------------------
    def add(self, source_path: str | Path, copy_into_case: bool = False, notes: str = "",
            actor: str = "forgex") -> EvidenceItem:
        source = Path(source_path).expanduser().resolve()
        if not source.exists():
            raise EvidenceCatalogError(f"Evidence source not found: {source}")

        item_id = uuid.uuid4().hex[:12]
        hashes = compute_hashes(source, self.algorithms)
        stored_path = str(source)

        if copy_into_case:
            dest_dir = self.case_dir / "evidence" / item_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / source.name
            shutil.copy2(source, dest_path)
            stored_path = str(dest_path)

        item = EvidenceItem(
            id=item_id,
            name=source.name,
            original_path=str(source),
            added_at=now_iso(),
            size_bytes=source.stat().st_size,
            hashes=hashes,
            notes=notes,
        )
        item.custody.append(CustodyEvent(
            timestamp=item.added_at,
            action="ADD",
            actor=actor,
            detail=f"Ingested from {source}; stored at {stored_path}",
        ))

        catalog = self._read_catalog()
        catalog["items"].append(item.to_dict())
        self._write_catalog(catalog)
        return item

    def list(self) -> list[EvidenceItem]:
        catalog = self._read_catalog()
        return [EvidenceItem.from_dict(d) for d in catalog["items"]]

    def get(self, item_id: str) -> EvidenceItem:
        for item in self.list():
            if item.id == item_id:
                return item
        raise EvidenceCatalogError(f"No evidence with id {item_id}")

    def hash(self, item_id: str) -> dict[str, str]:
        return self.get(item_id).hashes

    def verify(self, item_id: str, actor: str = "forgex") -> bool:
        """Recompute hashes for the original source and compare to the catalog."""
        item = self.get(item_id)
        source = Path(item.original_path)
        if not source.exists():
            raise EvidenceCatalogError(f"Original evidence path missing: {source}")
        fresh = compute_hashes(source, item.hashes.keys())
        ok = fresh == item.hashes

        catalog = self._read_catalog()
        for d in catalog["items"]:
            if d["id"] == item_id:
                d["verified"] = ok
                d.setdefault("custody", []).append(asdict(CustodyEvent(
                    timestamp=now_iso(),
                    action="VERIFY",
                    actor=actor,
                    detail="Hash match" if ok else "HASH MISMATCH -- integrity check failed",
                )))
        self._write_catalog(catalog)
        return ok

    def export(self, item_id: str, dest: str | Path) -> Path:
        item = self.get(item_id)
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with dest_path.open("w", encoding="utf-8") as fh:
            json.dump(item.to_dict(), fh, indent=2, default=str)
        return dest_path
