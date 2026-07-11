import json
from pathlib import Path

from core.investigation import InvestigationEngine
from core.report import ReportEngine


def _make_sample_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "notes.txt").write_text("nothing suspicious here")
    for i in range(6):
        (target / f"encrypted_{i}.bin").write_bytes(bytes((i * 37 + j) % 256 for j in range(5000)))
    return target


def test_investigation_run_produces_findings(tmp_path: Path):
    target = _make_sample_target(tmp_path)
    engine = InvestigationEngine(profiles_dir=tmp_path / "no_profiles_here")
    result = engine.run(target, profile="quick")
    assert result.stats["files_scanned"] == 7
    assert any(f.title == "Scan scope summary" for f in result.findings)


def test_report_all_formats_render(tmp_path: Path):
    target = _make_sample_target(tmp_path)
    engine = InvestigationEngine()
    result = engine.run(target, profile="quick")
    report = ReportEngine()
    for fmt in ("json", "markdown", "html", "csv"):
        content = report.render(result, fmt)
        assert content
        assert isinstance(content, str)


def test_report_json_is_valid_json(tmp_path: Path):
    target = _make_sample_target(tmp_path)
    engine = InvestigationEngine()
    result = engine.run(target, profile="quick")
    report = ReportEngine()
    payload = json.loads(report.render(result, "json"))
    assert payload["case_id"] == result.case_id
    assert "findings" in payload and "timeline" in payload
