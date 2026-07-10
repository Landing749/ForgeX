"""Disk Module.

Support target: DD, E01, VHD/VHDX, QCOW2, VMDK.
Commands: disk analyze, disk partitions, disk mount, disk info.

Real parsing of these container/image formats needs native libraries
(libewf/pyewf for E01, qemu-img/qcow2 tooling for QCOW2, pytsk3 for
partition + filesystem structures). Those are heavy binary
dependencies that don't belong in Forgex's pure-Python core, so this
module defines the stable command interface and does format
*detection* (by magic bytes/signature, which is dependency-free),
while delegating actual extraction to an optional native backend.

Install the optional backend with:
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
    with p.open("rb") as fh:
        header = fh.read(16)

    for sig, fmt in _SIGNATURES.items():
        if header.startswith(sig):
            return DiskImageInfo(
                path=str(p), format=fmt, size_bytes=p.stat().st_size,
                supports_native_parsing=_native_backend_available(fmt),
                note=_backend_note(fmt),
            )

    # Raw DD/dd images have no magic header -- infer from extension.
    if p.suffix.lower() in (".dd", ".img", ".raw", ".001"):
        return DiskImageInfo(
            path=str(p), format="DD (raw)", size_bytes=p.stat().st_size,
            supports_native_parsing=_native_backend_available("DD (raw)"),
            note=_backend_note("DD (raw)"),
        )

    return DiskImageInfo(
        path=str(p), format="unknown", size_bytes=p.stat().st_size,
        supports_native_parsing=False,
        note="Signature not recognized. Supported: DD, E01, VHD/VHDX, QCOW2, VMDK.",
    )


def _native_backend_available(_fmt: str) -> bool:
    try:
        import pytsk3  # noqa: F401
        return True
    except ImportError:
        return False


def _backend_note(fmt: str) -> str:
    return (
        f"{fmt} signature detected. Partition table, filesystem, and file "
        f"extraction require the optional pytsk3 (+ libewf for E01) native "
        f"backend; install with `pip install forgex[full]`."
    )


def analyze(path: str | Path) -> dict[str, Any]:
    info = identify_image(path)
    result: dict[str, Any] = {"image": info.__dict__}
    if info.supports_native_parsing:
        result["partitions"] = partitions(path)
    else:
        result["partitions"] = []
        result["warning"] = info.note
    return result


def partitions(path: str | Path) -> list[dict[str, Any]]:
    try:
        import pytsk3
    except ImportError:
        raise NotImplementedError(
            "disk partitions requires the optional pytsk3 backend "
            "(pip install forgex[full])."
        )
    img = pytsk3.Img_Info(str(path))
    volume = pytsk3.Volume_Info(img)
    return [
        {
            "addr": part.addr,
            "description": part.desc.decode(errors="ignore"),
            "start_sector": part.start,
            "length_sectors": part.len,
        }
        for part in volume
    ]


def mount(_path: str | Path, _mountpoint: str | Path, _partition_addr: int | None = None) -> None:
    """Mount a partition read-only. Requires OS-level loop/mount support
    (Linux: losetup + mount -o ro; not portable to pure Python)."""
    raise NotImplementedError(
        "disk mount is OS-dependent (losetup/mount on Linux, equivalent "
        "tooling elsewhere) and is intentionally left to the native backend."
    )


def info(path: str | Path) -> dict[str, Any]:
    return identify_image(path).__dict__
