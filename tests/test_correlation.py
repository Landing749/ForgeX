import pytest

from core.correlation import CorrelationEngine


def test_add_node_and_edge():
    g = CorrelationEngine()
    g.add_node("user:alice", "user", "alice")
    g.add_node("proc:1234", "process", "malware.exe")
    g.add_edge("user:alice", "proc:1234", "EXECUTED")
    assert len(g.nodes) == 2
    assert len(g.edges) == 1


def test_invalid_node_type_raises():
    g = CorrelationEngine()
    with pytest.raises(ValueError):
        g.add_node("x", "not_a_type", "x")


def test_edge_requires_known_nodes():
    g = CorrelationEngine()
    g.add_node("user:alice", "user", "alice")
    with pytest.raises(ValueError):
        g.add_edge("user:alice", "proc:missing", "EXECUTED")


def test_related_bfs():
    g = CorrelationEngine()
    g.add_node("a", "user", "a")
    g.add_node("b", "process", "b")
    g.add_node("c", "file", "c")
    g.add_edge("a", "b", "EXECUTED")
    g.add_edge("b", "c", "WROTE")
    sub = g.related("a", max_depth=2)
    node_ids = {n["id"] for n in sub["nodes"]}
    assert {"a", "b", "c"} <= node_ids


def test_save_load_roundtrip(tmp_path):
    g = CorrelationEngine()
    g.add_node("a", "user", "a")
    g.add_node("b", "file", "b")
    g.add_edge("a", "b", "WROTE")
    path = tmp_path / "graph.json"
    g.save_json(path)
    loaded = CorrelationEngine.load_json(path)
    assert len(loaded.nodes) == 2
    assert len(loaded.edges) == 1
