"""Correlation Engine / Graph Engine.

Represents evidence as a graph of typed nodes (users, processes,
files, registry keys, browser artifacts, network endpoints, USB
devices, malware samples, persistence mechanisms) connected by typed
relationships (e.g. EXECUTED, WROTE, CONNECTED_TO, PERSISTS_VIA,
AUTHENTICATED_AS).

Implemented as a small dependency-free adjacency-list graph rather
than requiring networkx, so `forgex` has no heavy install requirement
for its core correlation features. Plugins/modules that want richer
graph algorithms can still convert to networkx on demand via
`CorrelationEngine.to_networkx()` when that package is installed.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

NODE_TYPES = {
    "user", "process", "file", "registry", "browser",
    "network", "usb", "malware", "persistence",
}


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    attrs: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CorrelationEngine:
    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adjacency: dict[str, list[int]] = {}

    def add_node(self, node_id: str, node_type: str, label: str, **attrs) -> Node:
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type '{node_type}'. Expected one of {sorted(NODE_TYPES)}")
        node = Node(id=node_id, type=node_type, label=label, attrs=attrs)
        self.nodes[node_id] = node
        self._adjacency.setdefault(node_id, [])
        return node

    def add_edge(self, source: str, target: str, relation: str, **attrs) -> Edge:
        for nid in (source, target):
            if nid not in self.nodes:
                raise ValueError(f"Cannot add edge referencing unknown node '{nid}'")
        edge = Edge(source=source, target=target, relation=relation, attrs=attrs)
        self.edges.append(edge)
        self._adjacency[source].append(len(self.edges) - 1)
        return edge

    def neighbors(self, node_id: str) -> list[tuple[Edge, Node]]:
        results = []
        for idx in self._adjacency.get(node_id, []):
            edge = self.edges[idx]
            results.append((edge, self.nodes[edge.target]))
        return results

    def related(self, node_id: str, max_depth: int = 2) -> dict[str, Any]:
        """BFS outward from a node, useful for 'what touches this file/user/process'."""
        visited = {node_id}
        frontier = [node_id]
        subgraph_nodes = {node_id}
        subgraph_edges: list[Edge] = []
        for _ in range(max_depth):
            next_frontier = []
            for nid in frontier:
                for idx in self._adjacency.get(nid, []):
                    edge = self.edges[idx]
                    subgraph_edges.append(edge)
                    subgraph_nodes.add(edge.target)
                    if edge.target not in visited:
                        visited.add(edge.target)
                        next_frontier.append(edge.target)
            frontier = next_frontier
        return {
            "nodes": [self.nodes[n].to_dict() for n in subgraph_nodes],
            "edges": [e.to_dict() for e in subgraph_edges],
        }

    def by_type(self, node_type: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == node_type]

    # -- I/O -----------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")

    @classmethod
    def load_json(cls, path: str | Path) -> CorrelationEngine:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        engine = cls()
        for n in data.get("nodes", []):
            engine.add_node(n["id"], n["type"], n["label"], **n.get("attrs", {}))
        for e in data.get("edges", []):
            engine.add_edge(e["source"], e["target"], e["relation"], **e.get("attrs", {}))
        return engine

    def to_networkx(self):
        """Optional conversion for consumers that have networkx installed."""
        try:
            import networkx as nx
        except ImportError as exc:
            raise ImportError(
                "networkx is not installed; install it to use to_networkx() "
                "(this is an optional extension, not a core dependency)"
            ) from exc
        g = nx.MultiDiGraph()
        for node in self.nodes.values():
            g.add_node(node.id, type=node.type, label=node.label, **node.attrs)
        for edge in self.edges:
            g.add_edge(edge.source, edge.target, relation=edge.relation, **edge.attrs)
        return g
