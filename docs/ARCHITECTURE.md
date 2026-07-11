# Forgex Architecture

## Engines (`core/`)

| Engine | File | Responsibility |
|---|---|---|
| Evidence | `evidence.py` | Chain of custody, hashing, catalog (JSON-backed, per case) |
| Metadata | `metadata.py` | Normalize timestamps, hashes, entropy, EXIF/GPS |
| Timeline | `timeline.py` | Merge all timestamped events into one chronology |
| Correlation | `correlation.py` | Graph of nodes (users/processes/files/...) + relationships |
| Investigation | `investigation.py` | Drives named profiles, runs rules, produces Findings |
| Report | `report.py` | Renders JSON / Markdown / HTML / CSV / (optional) PDF |
| Plugin Manager | `plugin_manager.py` | Discovers and loads `plugins/*.py` |
| Config | `config.py` | Loads `config.yaml` with sane defaults |

## Modules (`modules/`)

Each artifact-source module exposes plain functions/dataclasses rather than
a required base class, so a plugin can import just what it needs:

- `disk/` — image format detection (E01/VHD/VHDX/QCOW2/VMDK/DD); partition
  listing requires optional `pytsk3`.
- `filesystem/` — tree, search, timeline (fully working against any mounted
  path); deleted/recover/ads/slack are native-backend extension points.
- `windows/` — working LNK parser; Registry/EVTX via optional
  `python-registry`/`python-evtx`; Prefetch/Amcache/Shimcache/JumpLists/
  MFT/USN as documented extension points.
- `linux/` — bash history, auth.log, crontab, SSH config/keys, /etc/passwd
  all fully working (text formats); journald binary format is an extension
  point.
- `macos/` — LaunchAgents (plist), Safari history, Quarantine events (all
  SQLite/plist, fully working); Unified Logs/Spotlight are extension points.
- `browser/` — Chrome/Edge/Brave + Firefox history, downloads, cookies
  (SQLite, fully working, read-only temp-copy pattern to avoid locking
  live evidence); cache formats are an extension point.
- `network/` — classic pcap parsing (Ethernet/IPv4/TCP/UDP/DNS) with zero
  dependencies; PCAPNG/JA3/HTTP reassembly via optional `scapy`.
- `malware/` — PE/ELF/Mach-O header + section parsing (stdlib `struct`);
  imports/exports via optional `pefile`; YARA via optional `yara-python`.
- `ioc/` — regex-based IOC extraction (IPs, domains, URLs, hashes, emails,
  CVEs, JWTs), fully working, zero dependencies.

## Why some things raise `NotImplementedError`

Several DFIR artifact formats (NTFS MFT/USN, Windows Registry hive binary
layout, EVTX, Prefetch's MAM compression, macOS Unified Logs, Spotlight's
store format, PCAPNG, TLS ClientHello/JA3) are proprietary or deeply
version-dependent binary structures. Reimplementing them from scratch is a
multi-week undertaking per format and the ecosystem already has well-tested
libraries for most of them. Forgex's approach:

1. Define the **stable function signature** other engines/CLI code call.
2. Implement it directly with the standard library wherever the format
   allows (LNK, plist, SQLite, PE/ELF headers, classic pcap, text logs).
3. Where that's not possible, raise `NotImplementedError` with a message
   naming the exact optional package (`pip install forgex[full]`) or the
   host tool that completes it — never a silent no-op.

This keeps `pip install forgex` (core) working everywhere with no native
build dependencies, while making every gap explicit and plugin-completable.

## Adding a Plugin

See `plugins/example_plugin.py`. Drop a `*.py` file into any directory
listed under `plugins.directories` in `config.yaml` (default: `./plugins`)
with a top-level `register(registry)` function. You can contribute rules,
profiles, report formats, parsers, CLI commands, and threat-intel providers.

## Adding an Investigation Profile

Add `profiles/<name>.yaml`:

```yaml
name: my_profile
description: What this profile is for.
modules: [filesystem, browser]
rules: [scope_summary, my_custom_rule]
```

Then: `forgex investigate <target> --profile my_profile`
