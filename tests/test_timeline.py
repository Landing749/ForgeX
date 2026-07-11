from core.timeline import TimelineEngine, TimelineEvent


def test_merge_sorts_by_timestamp():
    engine = TimelineEngine()
    engine.add_event(TimelineEvent(timestamp="2026-01-03T00:00:00+00:00", source="filesystem",
                                    event_type="file_modified", description="c"))
    engine.add_event(TimelineEvent(timestamp="2026-01-01T00:00:00+00:00", source="filesystem",
                                    event_type="file_modified", description="a"))
    engine.add_event(TimelineEvent(timestamp="2026-01-02T00:00:00+00:00", source="filesystem",
                                    event_type="file_modified", description="b"))
    merged = engine.merged()
    assert [e.description for e in merged] == ["a", "b", "c"]


def test_filter_by_source_and_range():
    engine = TimelineEngine()
    engine.add_event(TimelineEvent(timestamp="2026-01-01T00:00:00+00:00", source="browser",
                                    event_type="visit", description="x"))
    engine.add_event(TimelineEvent(timestamp="2026-01-05T00:00:00+00:00", source="filesystem",
                                    event_type="file_modified", description="y"))
    filtered = engine.filter(source="filesystem")
    assert len(filtered) == 1
    assert filtered[0].description == "y"

    ranged = engine.filter(start="2026-01-02T00:00:00+00:00")
    assert len(ranged) == 1
    assert ranged[0].description == "y"


def test_save_and_load_json(tmp_path):
    engine = TimelineEngine()
    engine.add_event(TimelineEvent(timestamp="2026-01-01T00:00:00+00:00", source="filesystem",
                                    event_type="file_modified", description="a"))
    path = tmp_path / "timeline.json"
    engine.save_json(path)
    loaded = TimelineEngine.load_json(path)
    assert len(loaded.merged()) == 1
