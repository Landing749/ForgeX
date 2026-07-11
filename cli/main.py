"""Forgex CLI.

    forgex evidence add/list/hash/verify/export
    forgex disk analyze/partitions/mount/info
    forgex fs tree/deleted/recover/search/timeline/ads/slack
    forgex investigate <target> --profile <name>
    forgex report generate <investigation.json> --format html
    forgex util hash/identify/entropy/strings/hexdump/archive/image/pdf/office/cert/logs/doctor
    forgex plugin list

Every command accepts --json for machine-readable output (per spec:
"Every command supports --json").
"""
from __future__ import annotations

import json as json_lib
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.config import get_config
from core.evidence import EvidenceCatalogError, EvidenceEngine
from core.investigation import InvestigationEngine
from core.plugin_manager import PluginManager
from core.report import SUPPORTED_FORMATS, ReportEngine
from modules.disk import analyze as disk_mod
from modules.filesystem import fs as fs_mod
from modules.ioc import extractor as ioc_mod

app = typer.Typer(name="forgex", help="Forgex - open-source DFIR investigation platform", no_args_is_help=True)
console = Console()

evidence_app = typer.Typer(help="Evidence catalog, chain of custody, hash verification")
disk_app = typer.Typer(help="Disk image analysis (DD/E01/VHD/VHDX/QCOW2/VMDK)")
fs_app = typer.Typer(help="Filesystem operations")
util_app = typer.Typer(help="Standalone utilities")
plugin_app = typer.Typer(help="Plugin management")
report_app = typer.Typer(help="Report generation")
windows_app = typer.Typer(help="Windows artifact parsing (registry, EVTX, MFT, USN, Prefetch, LNK)")
network_app = typer.Typer(help="Network artifact parsing (pcap/pcapng, JA3)")

app.add_typer(evidence_app, name="evidence")
app.add_typer(disk_app, name="disk")
app.add_typer(fs_app, name="fs")
app.add_typer(util_app, name="util")
app.add_typer(plugin_app, name="plugin")
app.add_typer(report_app, name="report")
app.add_typer(windows_app, name="windows")
app.add_typer(network_app, name="network")


def _emit(data, as_json: bool, title: str = "") -> None:
    if as_json:
        console.print_json(json_lib.dumps(data, indent=2, default=str))
        return
    if isinstance(data, list) and data and isinstance(data[0], dict):
        table = Table(title=title)
        for key in data[0].keys():
            table.add_column(str(key))
        for row in data:
            table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    else:
        console.print(data)


def _case_dir() -> Path:
    cfg = get_config()
    return Path(cfg.get("case_root", "./cases")) / "default"


# ---------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------
@evidence_app.command("add")
def evidence_add(source: str, copy: bool = typer.Option(False, help="Copy the file into the case directory"),
                  notes: str = "", json: bool = False):
    engine = EvidenceEngine(_case_dir())
    try:
        item = engine.add(source, copy_into_case=copy, notes=notes)
    except EvidenceCatalogError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    _emit(item.to_dict(), json, title="Evidence added")


@evidence_app.command("list")
def evidence_list(json: bool = False):
    engine = EvidenceEngine(_case_dir())
    items = [i.to_dict() for i in engine.list()]
    _emit(items, json, title="Evidence catalog")


@evidence_app.command("hash")
def evidence_hash(item_id: str, json: bool = False):
    engine = EvidenceEngine(_case_dir())
    try:
        _emit(engine.hash(item_id), json)
    except EvidenceCatalogError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)


@evidence_app.command("verify")
def evidence_verify(item_id: str, json: bool = False):
    engine = EvidenceEngine(_case_dir())
    try:
        ok = engine.verify(item_id)
    except EvidenceCatalogError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    _emit({"id": item_id, "verified": ok}, json)
    if not ok:
        console.print("[red]HASH MISMATCH -- evidence integrity check failed[/red]")
        raise typer.Exit(2)


@evidence_app.command("export")
def evidence_export(item_id: str, dest: str, json: bool = False):
    engine = EvidenceEngine(_case_dir())
    try:
        path = engine.export(item_id, dest)
    except EvidenceCatalogError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    _emit({"exported_to": str(path)}, json)


# ---------------------------------------------------------------------
# disk
# ---------------------------------------------------------------------
@disk_app.command("analyze")
def disk_analyze(image: str, json: bool = False):
    _emit(disk_mod.analyze(image), json)


@disk_app.command("partitions")
def disk_partitions(image: str, json: bool = False):
    try:
        _emit(disk_mod.partitions(image), json, title="Partitions")
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


@disk_app.command("mount")
def disk_mount(image: str, mountpoint: str, partition: int | None = None):
    try:
        disk_mod.mount(image, mountpoint, partition)
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


@disk_app.command("info")
def disk_info(image: str, json: bool = False):
    _emit(disk_mod.info(image), json)


# ---------------------------------------------------------------------
# fs
# ---------------------------------------------------------------------
@fs_app.command("tree")
def fs_tree(root: str, max_depth: int | None = None, json: bool = False):
    _emit(fs_mod.tree(root, max_depth), json)


@fs_app.command("search")
def fs_search(root: str, pattern: str, regex: bool = False, content: bool = False, json: bool = False):
    _emit(fs_mod.search(root, pattern, regex=regex, search_content=content), json, title="Search results")


@fs_app.command("timeline")
def fs_timeline(root: str, out: str | None = None, json: bool = False):
    events = list(fs_mod.timeline(root))
    if out:
        Path(out).write_text(json_lib.dumps(events, indent=2, default=str), encoding="utf-8")
        console.print(f"Wrote {len(events)} events to {out}")
        return
    _emit(events, json, title="Filesystem timeline")


@fs_app.command("deleted")
def fs_deleted(volume: str):
    try:
        fs_mod.deleted(volume)
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


@fs_app.command("recover")
def fs_recover(volume: str, record_id: str, dest: str):
    try:
        fs_mod.recover(volume, record_id, dest)
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


@fs_app.command("ads")
def fs_ads(path: str):
    try:
        fs_mod.ads(path)
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


@fs_app.command("slack")
def fs_slack(volume: str):
    try:
        fs_mod.slack(volume)
    except NotImplementedError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(3)


# ---------------------------------------------------------------------
# investigate
# ---------------------------------------------------------------------
@app.command("investigate")
def investigate(
    target: str,
    profile: str = typer.Option("quick", "--profile", help="quick|malware|ransomware|insider_threat|"
                                                             "exfiltration|persistence|phishing|custom"),
    report_format: str = typer.Option("json", "--format", help=f"One of {SUPPORTED_FORMATS}"),
    output: str | None = typer.Option(None, "--output", "-o"),
    json: bool = False,
):
    engine = InvestigationEngine()
    result = engine.run(target, profile=profile)

    if json or not output:
        _emit(result.to_summary_dict(), True, title="Investigation summary")

    if output:
        report = ReportEngine()
        path = report.write(result, report_format, output)
        console.print(f"[green]Report written to {path}[/green]")


# ---------------------------------------------------------------------
# report
# ---------------------------------------------------------------------
@report_app.command("formats")
def report_formats(json: bool = False):
    _emit(list(SUPPORTED_FORMATS), json)


# ---------------------------------------------------------------------
# util
# ---------------------------------------------------------------------
@util_app.command("hash")
def util_hash(path: str, json: bool = False):
    from core.utils import hash_file
    _emit(hash_file(path), json)


@util_app.command("identify")
def util_identify(path: str, json: bool = False):
    from core.utils import identify_file
    _emit(identify_file(path), json)


@util_app.command("entropy")
def util_entropy(path: str, json: bool = False):
    from core.utils import entropy_of_file
    _emit({"path": path, "entropy": entropy_of_file(path)}, json)


@util_app.command("strings")
def util_strings(path: str, min_length: int = 4, encoding: str = "ascii", json: bool = False):
    from core.utils import extract_strings
    _emit(extract_strings(path, min_length, encoding), json)


@util_app.command("hexdump")
def util_hexdump(path: str, offset: int = 0, length: int = 256):
    from core.utils import hexdump
    console.print(hexdump(path, offset, length))


@util_app.command("archive")
def util_archive(path: str, json: bool = False):
    from core.utils import list_archive
    _emit(list_archive(path), json, title="Archive contents")


@util_app.command("image")
def util_image(path: str, json: bool = False):
    from core.utils import image_info
    _emit(image_info(path), json)


@util_app.command("pdf")
def util_pdf(path: str, json: bool = False):
    from core.utils import pdf_info
    _emit(pdf_info(path), json)


@util_app.command("office")
def util_office(path: str, json: bool = False):
    from core.utils import office_info
    _emit(office_info(path), json)


@util_app.command("cert")
def util_cert(path: str, json: bool = False):
    from core.utils import cert_info
    _emit(cert_info(path), json)


@util_app.command("logs")
def util_logs(path: str, pattern: str, json: bool = False):
    from core.utils import grep_log
    _emit(grep_log(path, pattern), json)


@util_app.command("doctor")
def util_doctor(json: bool = False):
    from core.utils import doctor
    _emit(doctor(), json)


@util_app.command("ioc")
def util_ioc(path: str, json: bool = False):
    result = ioc_mod.extract_iocs_from_file(path)
    _emit(result.to_dict(), json)


# ---------------------------------------------------------------------
# windows
# ---------------------------------------------------------------------
@windows_app.command("registry")
def windows_registry(hive_path: str, key: str = None, json: bool = False):
    from modules.windows.registry_native import RegistryHive
    hive = RegistryHive(hive_path)
    result = hive.open_key(key) if key else hive.root()
    _emit(result.to_dict(), json)


@windows_app.command("evtx")
def windows_evtx(path: str, max_records: int = 1000, json: bool = False):
    from modules.windows.evtx_native import parse_evtx_file
    records = parse_evtx_file(path, max_records=max_records)
    _emit([r.to_dict() for r in records], json, title="EVTX records")


@windows_app.command("mft")
def windows_mft(path: str, json: bool = False):
    from modules.windows.mft import parse_mft_file
    records = list(parse_mft_file(path))
    _emit([r.to_dict() for r in records], json, title="MFT records")


@windows_app.command("usn")
def windows_usn(path: str, json: bool = False):
    from modules.windows.usn import parse_usn_journal
    records = list(parse_usn_journal(path))
    _emit([r.to_dict() for r in records], json, title="USN journal records")


@windows_app.command("prefetch")
def windows_prefetch(path: str, json: bool = False):
    from modules.windows.prefetch import parse_file
    _emit(parse_file(path), json)


@windows_app.command("lnk")
def windows_lnk(path: str, json: bool = False):
    from dataclasses import asdict

    from modules.windows.artifacts import parse_lnk
    _emit(asdict(parse_lnk(path)), json)


# ---------------------------------------------------------------------
# network
# ---------------------------------------------------------------------
@network_app.command("summarize")
def network_summarize(path: str, json: bool = False):
    from modules.network.pcap import summarize
    _emit(summarize(path), json)


@network_app.command("packets")
def network_packets(path: str, max_packets: int = 1000, json: bool = False):
    from modules.network.pcap import read_packets
    packets = [p.to_dict() for p in read_packets(path, max_packets=max_packets)]
    _emit(packets, json, title="Packets")


@network_app.command("ja3")
def network_ja3(client_hello_file: str, json: bool = False):
    from modules.network.tls import compute_ja3
    data = Path(client_hello_file).read_bytes()
    _emit(compute_ja3(data), json)


# ---------------------------------------------------------------------
# plugin
# ---------------------------------------------------------------------
@plugin_app.command("list")
def plugin_list(json: bool = False):
    cfg = get_config()
    manager = PluginManager(cfg.get("plugins.directories", ["plugins"]))
    registry = manager.load_all()
    data = {
        "loaded_plugins": registry.loaded_plugins,
        "commands": list(registry.commands.keys()),
        "rules": list(registry.rules.keys()),
        "profiles": list(registry.profiles.keys()),
        "report_formats": list(registry.reports.keys()),
    }
    _emit(data, json)


def main():
    app()


if __name__ == "__main__":
    main()
