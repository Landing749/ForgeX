from pathlib import Path

from core.metadata import MetadataEngine, shannon_entropy, walk_metadata


def test_shannon_entropy_zero_for_uniform_bytes():
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_shannon_entropy_high_for_random_bytes():
    import os
    entropy = shannon_entropy(os.urandom(4096))
    assert entropy > 7.5


def test_metadata_extract(tmp_path: Path):
    f = tmp_path / "doc.txt"
    f.write_text("hello forensic world")
    engine = MetadataEngine()
    meta = engine.extract(f)
    assert meta.size_bytes == len("hello forensic world")
    assert "sha256" in meta.hashes
    assert "modified" in meta.timestamps


def test_walk_metadata(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("b")
    results = list(walk_metadata(tmp_path))
    assert len(results) == 2
