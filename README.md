# Forgex

Forgex is an open-source DFIR (Digital Forensics & Incident Response) investigation
platform built around evidence correlation, metadata normalization, timeline
reconstruction, and reporting.

```
forgex investigate evidence.E01 --profile ransomware
```

## Principles

- **Read-only by default** — Forgex never modifies source evidence.
- **Evidence integrity** — every ingest is hashed and chain-of-custody logged; re-verify anytime.
- **Plugin architecture** — commands, parsers, rules, profiles, reports, and threat intel are all extensible.
- **JSON-first** — every command supports `--json`.
- **Cross-platform** — pure-Python core; optional native backends for deep binary-format parsing.
- **Automation-friendly** — scriptable CLI, stable module interfaces, CI-tested.

## Architecture

```
cli/            CLI entry point (Typer)
core/           Evidence, Metadata, Correlation, Timeline, Investigation,
                Report engines + Plugin Manager + Config
modules/        disk, filesystem, windows, linux, macos, browser,
                network, malware, ioc
plugins/        drop-in *.py plugins (see plugins/example_plugin.py)
profiles/       investigation profile YAML definitions
rules/          YARA / detection rule files
reports/        report output landing directory
docs/           documentation
examples/       example evidence / usage
tests/          pytest suite
```

> **Note on repo layout:** the spec's directory name `cmd/` collides with
> Python's standard library `cmd` module (used by `pdb`, `argparse`, etc.),
> which breaks tooling like pytest when the repo root is on `sys.path`. This
> implementation uses `cli/` instead, keeping every other directory name
> exactly as specified.

## Install

```bash
pip install -e .                 # core (pure Python, no native deps)
pip install -e ".[full]"         # + optional native backends (see below)
```

## Quick start

```bash
# Add evidence to the case catalog (hashed + chain-of-custody logged)
forgex evidence add ./suspicious_dir --notes "Initial triage"
forgex evidence list
forgex evidence verify <id>

# Run an investigation profile against a target and render a report
forgex investigate ./suspicious_dir --profile ransomware --format html -o report.html
forgex investigate ./suspicious_dir --profile quick --json

# Utilities
forgex util hash ./file.bin
forgex util entropy ./file.bin
forgex util strings ./file.bin --min-length 6
forgex util ioc ./browser_history_dump.txt
forgex util doctor          # check optional dependency status

# Plugins
forgex plugin list
```

## Investigation Profiles

`Quick`, `Malware`, `Ransomware`, `Insider Threat`, `Exfiltration`,
`Persistence`, `Phishing`, `Custom` — declarative YAML under `profiles/`,
extensible via the Plugin SDK.

## What's fully implemented vs. an extension point

Forgex's core (Evidence, Metadata, Timeline, Correlation, Investigation,
Report engines, Plugin Manager, CLI, IOC extraction, filesystem tree/search,
Linux text-artifact parsing, browser SQLite history/downloads/cookies, PE/ELF/
Mach-O header parsing, classic-pcap decoding) works with **zero native
dependencies**.

Formats that require proprietary/binary-format-specific decoders (Windows
Registry hives, EVTX, Prefetch, Amcache, Shimcache, Jump Lists, MFT, USN
journal; macOS Unified Logs, Spotlight; PCAPNG, JA3/TLS fingerprinting; YARA
scanning; disk image partition/filesystem extraction for E01/QCOW2/VHDX/VMDK)
are implemented as **stable interfaces with clear `NotImplementedError`
messages** pointing at the optional dependency (`pip install forgex[full]`)
or plugin that completes them. This keeps the core installable everywhere
and every extension point explicit rather than silently stubbed.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT — see `LICENSE`.
