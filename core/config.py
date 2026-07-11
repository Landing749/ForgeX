"""Configuration loading and access for Forgex.

Reads config.yaml (or a user-supplied path), applies sane defaults for
any missing keys, and exposes a small dotted-path accessor so the rest
of the codebase never has to worry about missing sections.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "case_root": "./cases",
    "theme": "default",
    "hash_algorithms": ["sha256", "md5"],
    "report": {
        "default_formats": ["json", "markdown"],
        "include_severity": True,
        "include_confidence": True,
    },
    "plugins": {"directories": ["./plugins"], "enabled": True},
    "profiles": {"directory": "./profiles"},
    "logging": {"level": "INFO", "file": None},
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    """Loaded Forgex configuration with dotted-path lookups."""

    def __init__(self, data: dict[str, Any], source: Path | None = None):
        self._data = data
        self.source = source

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        candidate = Path(path) if path else Path("config.yaml")
        if candidate.exists():
            with candidate.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            merged = _deep_merge(DEFAULT_CONFIG, loaded)
            return cls(merged, source=candidate)
        return cls(copy.deepcopy(DEFAULT_CONFIG), source=None)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)


_CONFIG_SINGLETON: Config | None = None


def get_config(path: str | Path | None = None, reload: bool = False) -> Config:
    global _CONFIG_SINGLETON
    if _CONFIG_SINGLETON is None or reload:
        _CONFIG_SINGLETON = Config.load(path)
    return _CONFIG_SINGLETON
