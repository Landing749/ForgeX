import json
from pathlib import Path

import pytest

from core.evidence import EvidenceCatalogError, EvidenceEngine, compute_hashes


def test_compute_hashes(tmp_path: Path):
    import hashlib

    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello world")
    hashes = compute_hashes(f, ("sha256", "md5"))
    assert hashes["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert hashes["md5"] == hashlib.md5(b"hello world").hexdigest()


def test_add_list_hash_verify(tmp_path: Path):
    case_dir = tmp_path / "case"
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"forensic data" * 100)

    engine = EvidenceEngine(case_dir)
    item = engine.add(src, notes="test ingest")
    assert item.name == "evidence.bin"
    assert "sha256" in item.hashes

    listed = engine.list()
    assert len(listed) == 1
    assert listed[0].id == item.id

    assert engine.hash(item.id) == item.hashes
    assert engine.verify(item.id) is True


def test_verify_detects_tamper(tmp_path: Path):
    case_dir = tmp_path / "case"
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"original content")

    engine = EvidenceEngine(case_dir)
    item = engine.add(src)

    src.write_bytes(b"tampered content!!")
    assert engine.verify(item.id) is False


def test_missing_evidence_raises(tmp_path: Path):
    engine = EvidenceEngine(tmp_path / "case")
    with pytest.raises(EvidenceCatalogError):
        engine.get("does-not-exist")


def test_export(tmp_path: Path):
    case_dir = tmp_path / "case"
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"exportable")
    engine = EvidenceEngine(case_dir)
    item = engine.add(src)
    dest = tmp_path / "export.json"
    engine.export(item.id, dest)
    data = json.loads(dest.read_text())
    assert data["id"] == item.id
