"""Linux Module.

Covers: bash history, systemd journal, auth log, cron, SSH, users.
These are all plain-text (or systemd binary journal) artifacts, so
most of this module works fully with the standard library.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def parse_bash_history(path: str | Path) -> list[dict[str, Any]]:
    """Parse ~/.bash_history. Supports the optional HISTTIMEFORMAT-style
    `#<epoch>` timestamp lines that precede a command when history
    timestamping is enabled."""
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    entries = []
    pending_ts = None
    for line in lines:
        if line.startswith("#") and line[1:].strip().isdigit():
            pending_ts = int(line[1:].strip())
            continue
        if line.strip():
            entries.append({"command": line, "epoch": pending_ts})
            pending_ts = None
    return entries


_AUTH_LINE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)


def parse_auth_log(path: str | Path, max_lines: int = 50_000) -> list[dict[str, Any]]:
    entries = []
    with Path(path).open("r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= max_lines:
                break
            m = _AUTH_LINE.match(line.strip())
            if m:
                entries.append(m.groupdict())
    return entries


def parse_auth_events(path: str | Path) -> list[dict[str, Any]]:
    """Classify auth.log lines into higher-level events: logins, sudo, ssh."""
    events = []
    for entry in parse_auth_log(path):
        msg = entry["message"]
        kind = None
        if "Accepted password" in msg or "Accepted publickey" in msg:
            kind = "ssh_login_success"
        elif "Failed password" in msg:
            kind = "ssh_login_failure"
        elif msg.startswith("sudo:") or "COMMAND=" in msg:
            kind = "sudo_command"
        elif "session opened" in msg:
            kind = "session_opened"
        elif "session closed" in msg:
            kind = "session_closed"
        if kind:
            events.append({**entry, "event_type": kind})
    return events


def parse_crontab(path: str | Path) -> list[dict[str, Any]]:
    jobs = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 5)
        if len(parts) >= 6:
            jobs.append({
                "schedule": " ".join(parts[:5]),
                "command": parts[5],
                "raw": line,
            })
    return jobs


def parse_ssh_config(path: str | Path) -> list[dict[str, Any]]:
    hosts = []
    current: dict[str, Any] | None = None
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition(" ")
        if key.lower() == "host":
            if current:
                hosts.append(current)
            current = {"host": value.strip(), "options": {}}
        elif current is not None:
            current["options"][key] = value.strip()
    if current:
        hosts.append(current)
    return hosts


def parse_ssh_authorized_keys(path: str | Path) -> list[dict[str, Any]]:
    keys = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            keys.append({"key_type": parts[0], "fingerprint_material": parts[1][:32] + "...",
                         "comment": parts[2] if len(parts) > 2 else None})
    return keys


def parse_passwd(path: str | Path = "/etc/passwd") -> list[dict[str, Any]]:
    users = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) == 7:
            users.append({
                "username": fields[0], "uid": fields[2], "gid": fields[3],
                "gecos": fields[4], "home": fields[5], "shell": fields[6],
            })
    return users


def parse_journal(_path: str | Path) -> list[dict[str, Any]]:
    """systemd journal files are a binary format (journald native
    format); reading them robustly needs `python-systemd` bindings or
    shelling out to `journalctl --file=... -o json`, both of which are
    optional-dependency/host-tool extension points rather than a pure
    stdlib parse."""
    raise NotImplementedError(
        "Journal parsing requires the systemd journal library or the "
        "`journalctl` binary; not available as a pure-Python stdlib parse."
    )
