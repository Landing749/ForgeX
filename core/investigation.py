"""Investigation Engine.

Drives named Investigation Profiles (Quick, Malware, Ransomware,
Insider Threat, Exfiltration, Persistence, Phishing, Custom) against
a piece of evidence, wiring together the Metadata, Timeline,
Correlation, and Report engines and recording Findings.

    forgex investigate evidence.E01 --profile ransomware

Profiles are declarative YAML under profiles/ (see profiles/*.yaml)
describing which modules to run and which rule sets to apply; this
keeps adding a new profile a configuration change rather than a code
change, and lets the Plugin SDK contribute new profiles too.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.correlation import CorrelationEngine
from core.metadata import walk_metadata
from core.timeline import TimelineEngine

BUILTIN_PROFILES = [
    "quick", "malware", "ransomware", "insider_threat",
    "exfiltration", "persistence", "phishing", "custom",
]

Severity = str  # "info" | "low" | "medium" | "high" | "critical"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: str  # "low" | "medium" | "high"
    description: str
    evidence_refs: list[str] = field(default_factory=list)
    module: str = "core"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationResult:
    case_id: str
    profile: str
    target: str
    started_at: float
    finished_at: float
    findings: list[Finding]
    timeline: TimelineEngine
    graph: CorrelationEngine
    stats: dict[str, Any] = field(default_factory=dict)

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "profile": self.profile,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.finished_at - self.started_at, 3),
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
            "timeline_event_count": len(self.timeline.merged()),
            "graph_node_count": len(self.graph.nodes),
            "graph_edge_count": len(self.graph.edges),
        }


# A rule is any callable that inspects gathered context and yields Findings.
RuleFn = Callable[[dict[str, Any]], list[Finding]]


def rule_large_high_entropy_files(ctx: dict[str, Any]) -> list[Finding]:
    """Heuristic: many high-entropy (possibly encrypted/packed) files close
    together in time is a classic ransomware / packer signal."""
    findings = []
    suspects = [fm for fm in ctx["metadata"] if fm.entropy >= 7.5 and fm.size_bytes > 4096]
    if len(suspects) >= 5:
        findings.append(Finding(
            id=uuid.uuid4().hex[:10],
            title="Cluster of high-entropy files detected",
            severity="high",
            confidence="medium",
            description=(
                f"{len(suspects)} files with entropy >= 7.5 were found, consistent with "
                f"encryption, packing, or compression activity."
            ),
            evidence_refs=[fm.path for fm in suspects[:25]],
            module="core.rules.entropy",
            tags=["entropy", "ransomware", "packer"],
        ))
    return findings


def rule_note_scan_scope(ctx: dict[str, Any]) -> list[Finding]:
    findings = [Finding(
        id=uuid.uuid4().hex[:10],
        title="Scan scope summary",
        severity="info",
        confidence="high",
        description=f"Scanned {len(ctx['metadata'])} files under {ctx['target']}.",
        module="core.rules.scope",
        tags=["summary"],
    )]
    return findings


DEFAULT_RULES: list[RuleFn] = [rule_note_scan_scope, rule_large_high_entropy_files]


class InvestigationEngine:
    def __init__(self, profiles_dir: str | Path = "profiles"):
        self.profiles_dir = Path(profiles_dir)

    def load_profile(self, name: str) -> dict[str, Any]:
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            return yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
        if name in BUILTIN_PROFILES:
            return {"name": name, "modules": [], "rules": ["default"]}
        raise ValueError(f"Unknown profile '{name}'. Known profiles: {BUILTIN_PROFILES}")

    def run(self, target: str | Path, profile: str = "quick",
             extra_rules: list[RuleFn] | None = None) -> InvestigationResult:
        target_path = Path(target)
        started = time.time()
        case_id = uuid.uuid4().hex[:10]

        timeline = TimelineEngine()
        graph = CorrelationEngine()

        if target_path.is_dir():
            metadata_list = list(walk_metadata(target_path))
        elif target_path.is_file():
            from core.metadata import MetadataEngine
            metadata_list = [MetadataEngine().extract(target_path)]
        else:
            # Disk images (E01/DD/VHDX/QCOW2/VMDK) require the Disk module's
            # native parsers (see modules/disk) and are not walkable as a
            # plain filesystem path; this is the integration point for that.
            metadata_list = []

        timeline.ingest_metadata(metadata_list)

        for fm in metadata_list:
            graph.add_node(fm.path, "file", Path(fm.path).name, size=fm.size_bytes, entropy=fm.entropy)

        ctx = {"target": str(target_path), "metadata": metadata_list, "profile": profile}
        rules = list(DEFAULT_RULES) + (extra_rules or [])
        findings: list[Finding] = []
        for rule in rules:
            findings.extend(rule(ctx))

        finished = time.time()
        return InvestigationResult(
            case_id=case_id,
            profile=profile,
            target=str(target_path),
            started_at=started,
            finished_at=finished,
            findings=findings,
            timeline=timeline,
            graph=graph,
            stats={"files_scanned": len(metadata_list)},
        )
