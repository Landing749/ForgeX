"""Disk Module.

Support target: DD, E01, VHD/VHDX, QCOW2, VMDK.
Commands: disk analyze, disk partitions, disk mount, disk info.

Native, dependency-free support:
    - DD (raw) images: read directly.
    - E01 (EWF1): modules.disk.ewf reconstructs the raw image bytes
      from the table/sectors sections.
    - VHD, **fixed** disks only: the file content before the 512-byte
      footer *is* the raw image, sector-for-sector -- read directly.
    - MBR and GPT partition tables (modules.disk.partitions) are then
      parsed from whichever of the above produced raw bytes.

Extension points (not implemented from scratch here):
    - VHD **dynamic**/differencing disks: sectors are stored in
      sparse blocks addressed via a Block Allocation Table following
      the dynamic disk header; reassembling requires walking that BAT.
    - VHDX: a substantially different, more complex container format
      (log-structured with B-tree region tables) than VHD.
    - QCOW2: cluster-table-based sparse format (has zlib/zstd cluster
      compression and backing-file chains); implementing this from
      scratch is closer in scope to the disk-image formats already
      done here, but wasn't reached this pass.
    - VMDK: multiple sub-formats (monolithic flat, sparse "COWD" with
      grain tables, stream-optimized) with real variation between them.
    - Filesystem structures *within* a partition (NTFS/ext4/APFS/etc.)
      are out of scope for this module -- see modules.filesystem and
      modules.windows.mft/usn for what's natively parsed there.

Install optional native tooling for the extension points above with:
    pip install forgex[full]     # pulls in pytsk3-based extras (platform permitting)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SIGNATURES: dict[bytes, str] = {
    b"EVF\x09\x0d\x0a\xff\x00": "E01 (EnCase Evidence File)",
    b"conectix": "VHD",
    b"vhdxfile": "VHDX",
    b"QFI\xfb": "QCOW2",
    b"KDMV": "VMDK (sparse/hosted)",
}

_NATIVE_FORMATS = {"E01 (EnCase Evidence File)", "VHD (fixed)", "DD (raw)"}


@dataclass
class DiskImageInfo:
    path: str
    format: str
    size_bytes: int
    supports_native_parsing: bool
    note: str


def identify_image(path: str | Path) -> DiskImageInfo:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    size = p.stat().st_size
    with p.open("rb") as fh:
        header = fh.read(16)
        footer_cookie = b""
        if size >= 512:
            fh.seek(-512, 2)
            footer_cookie = fh.read(8)

    for sig, fmt in _SIGNATURES.items():
        if header.startswith(sig) or (fmt == "VHD" and footer_cookie == sig):
            if fmt == "VHD":
                fmt = _vhd_variant_label(p)
            return DiskImageInfo(
                path=str(p), format=fmt, size_bytes=size,
                supports_native_parsing=(fmt in _NATIVE_FORMATS),
                note=_backend_note(fmt),
            )

    if p.suffix.lower() in (".dd", ".img", ".raw", ".001"):
        return DiskImageInfo(
            path=str(p), format="DD (raw)", size_bytes=size,
            supports_native_parsing=True, note="Raw image; read directly, no container to unwrap.",
        )

    return DiskImageInfo(
        path=str(p), format="unknown", size_bytes=size,
        supports_native_parsing=False,
        note="Signature not recognized. Supported: DD, E01, VHD/VHDX, QCOW2, VMDK.",
    )


def _vhd_variant_label(path: Path) -> str:
    from modules.disk.vhd import read_footer
    try:
        footer = read_footer(path)
        return f"VHD ({footer.disk_type})"
    except Exception:
        return "VHD (unknown variant)"


def _native_backend_available(_fmt: str) -> bool:
    try:
        import pytsk3  # noqa: F401
        return True
    except ImportError:
        return False


def _backend_note(fmt: str) -> str:
    if fmt in _NATIVE_FORMATS or fmt.startswith("VHD (fixed"):
        return f"{fmt}: raw bytes and MBR/GPT partition table are natively supported (no external dependency)."
    return (
        f"{fmt} signature detected. This container format's own internal "
        f"structure (sparse block/cluster tables) is not natively "
        f"implemented; see this module's docstring for what's covered and "
        f"what remains an extension point. Full support: pytsk3 (+ libewf) "
        f"via `pip install forgex[full]`."
    )


def get_raw_bytes(path: str | Path, offset: int = 0, length: int | None = None) -> bytes:
    """Return raw (dd-equivalent) image bytes for any natively-supported
    container, starting at `offset` for `length` bytes (or to EOF)."""
    info = identify_image(path)
    if info.format == "DD (raw)":
        with Path(path).open("rb") as fh:
            fh.seek(offset)
            return fh.read(length) if length is not None else fh.read()

    if info.format.startswith("E01"):
        from modules.disk.ewf import reconstruct_raw_image
        max_bytes = (offset + length) if length is not None else None
        raw = reconstruct_raw_image(path, max_bytes=max_bytes)
        return raw[offset:offset + length] if length is not None else raw[offset:]

    if info.format.startswith("VHD (fixed"):
        with Path(path).open("rb") as fh:
            fh.seek(offset)
            data = fh.read(length) if length is not None else fh.read()
        footer_start = Path(path).stat().st_size - 512
        if offset + len(data) > footer_start:
            data = data[:max(0, footer_start - offset)]
        return data

    raise NotImplementedError(
        f"{info.format}: raw byte extraction is not natively implemented for this "
        f"container -- see this module's docstring for the extension points."
    )


def analyze(path: str | Path) -> dict[str, Any]:
    info = identify_image(path)
    result: dict[str, Any] = {"image": info.__dict__}
    if info.supports_native_parsing:
        try:
            result["partitions"] = partitions(path)
        except Exception as exc:  # noqa: BLE001 - surface as a warning, don't abort the whole analyze
            result["partitions"] = []
            result["warning"] = str(exc)
    else:
        result["partitions"] = []
        result["warning"] = info.note
    return result


def partitions(path: str | Path) -> list[dict[str, Any]]:
    info = identify_image(path)
    if info.supports_native_parsing:
        from modules.disk.partitions import parse_partition_table

        raw = get_raw_bytes(path, offset=0, length=8 * 1024 * 1024)
        table = parse_partition_table(raw)
        if table.scheme == "MBR":
            return [p.to_dict() for p in table.mbr_partitions]
        return [p.to_dict() for p in table.gpt_partitions]

    try:
        import pytsk3
    except ImportError:
        raise NotImplementedError(
            f"disk partitions for {info.format}: not natively implemented (see module "
            f"docstring) and the optional pytsk3 backend isn't installed "
            f"(pip install forgex[full])."
        )
    img = pytsk3.Img_Info(str(path))
    volume = pytsk3.Volume_Info(img)
    return [
        {"addr": part.addr, "description": part.desc.decode(errors="ignore"),
         "start_sector": part.start, "length_sectors": part.len}
        for part in volume
    ]


def mount(_path: str | Path, _mountpoint: str | Path, _partition_addr: int | None = None) -> None:
    """Mount a partition read-only. Requires OS-level loop/mount support
    (Linux: losetup + mount -o ro; not portable to pure Python)."""
    raise NotImplementedError(
        "disk mount is OS-dependent (losetup/mount on Linux, equivalent "
        "tooling elsewhere) and is intentionally left to the native backend. "
        "Use get_raw_bytes() to extract a partition's byte range instead if "
        "the goal is offline analysis rather than an actual mount."
    )


def info(path: str | Path) -> dict[str, Any]:
    return identify_image(path).__dict__
