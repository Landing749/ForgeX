"""Plugin Manager.

Plugins are single Python files (or packages with __init__.py) dropped
into a configured plugin directory (default: ./plugins). Each plugin
calls `register()` at import time to contribute one or more of:

    - commands       (Typer sub-apps merged into the main CLI)
    - parsers        (artifact parser callables)
    - rules          (investigation Finding-producing callables)
    - profiles       (declarative investigation profile dicts)
    - reports        (report format renderers)
    - threat_intel   (IOC/threat-intel feed providers)

Example plugin (plugins/example_plugin.py):

    from core.plugin_manager import PluginRegistry

    def my_rule(ctx):
        return []

    def register(registry: PluginRegistry):
        registry.add_rule("my_rule", my_rule)
"""
from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PluginRegistry:
    commands: dict[str, Any] = field(default_factory=dict)
    parsers: dict[str, Callable] = field(default_factory=dict)
    rules: dict[str, Callable] = field(default_factory=dict)
    profiles: dict[str, dict] = field(default_factory=dict)
    reports: dict[str, Callable] = field(default_factory=dict)
    threat_intel: dict[str, Callable] = field(default_factory=dict)
    loaded_plugins: list[str] = field(default_factory=list)

    def add_command(self, name: str, typer_app: Any) -> None:
        self.commands[name] = typer_app

    def add_parser(self, name: str, fn: Callable) -> None:
        self.parsers[name] = fn

    def add_rule(self, name: str, fn: Callable) -> None:
        self.rules[name] = fn

    def add_profile(self, name: str, profile: dict) -> None:
        self.profiles[name] = profile

    def add_report_format(self, name: str, fn: Callable) -> None:
        self.reports[name] = fn

    def add_threat_intel(self, name: str, fn: Callable) -> None:
        self.threat_intel[name] = fn


class PluginManager:
    def __init__(self, plugin_dirs: list[str | Path] | None = None):
        self.plugin_dirs = [Path(p) for p in (plugin_dirs or ["plugins"])]
        self.registry = PluginRegistry()

    def discover(self) -> list[Path]:
        found = []
        for directory in self.plugin_dirs:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                found.append(path)
        return found

    def load_all(self) -> PluginRegistry:
        for path in self.discover():
            self._load_one(path)
        return self.registry

    def _load_one(self, path: Path) -> None:
        module_name = f"forgex_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - plugin errors must not crash Forgex
            print(f"[forgex] warning: failed to load plugin '{path.name}': {exc}", file=sys.stderr)
            return
        register_fn = getattr(module, "register", None)
        if callable(register_fn):
            register_fn(self.registry)
            self.registry.loaded_plugins.append(path.stem)
        else:
            print(f"[forgex] warning: plugin '{path.name}' has no register() function; skipped", file=sys.stderr)
