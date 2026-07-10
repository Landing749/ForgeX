"""Example Forgex plugin.

Demonstrates the Plugin SDK surface: a custom rule, a custom
investigation profile, and a custom report format. Copy this file as
a starting point for your own plugin -- Forgex loads every *.py file
in plugins/ (configurable via config.yaml: plugins.directories) that
defines a top-level `register(registry)` function.
"""
from __future__ import annotations

import uuid
from typing import Any


def rule_many_small_files(ctx: dict[str, Any]) -> list:
    """Example rule: flag directories with an unusually large number of
    very small files, which can indicate a staged exfiltration bundle
    or a fragmented artifact cache."""
    from core.investigation import Finding

    small_files = [fm for fm in ctx["metadata"] if fm.size_bytes < 1024]
    if len(small_files) > 500:
        return [Finding(
            id=uuid.uuid4().hex[:10],
            title="Large number of small files detected",
            severity="low",
            confidence="low",
            description=f"{len(small_files)} files under 1KB were found under {ctx['target']}.",
            evidence_refs=[fm.path for fm in small_files[:10]],
            module="plugin.example_plugin",
            tags=["heuristic", "example"],
        )]
    return []


CUSTOM_PROFILE = {
    "name": "example_custom",
    "description": "Example plugin-contributed investigation profile.",
    "modules": ["filesystem"],
    "rules": ["many_small_files"],
}


def report_format_summary_txt(result) -> str:
    """Example plugin-contributed report format: a one-paragraph plaintext
    summary, registered under the name 'summary_txt'."""
    return (
        f"Forgex case {result.case_id} ({result.profile} profile) scanned "
        f"{result.stats.get('files_scanned', 0)} files under {result.target} "
        f"and produced {len(result.findings)} findings."
    )


def register(registry) -> None:
    registry.add_rule("many_small_files", rule_many_small_files)
    registry.add_profile("example_custom", CUSTOM_PROFILE)
    registry.add_report_format("summary_txt", report_format_summary_txt)
