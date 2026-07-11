"""Forgex Utilities.

Standalone helpers exposed as `forgex util <name>`:
hash, identify, entropy, strings, hexdump, archive, image, pdf,
office, cert, logs, doctor.

Kept dependency-light (stdlib only) so every utility works out of the
box; a couple (image EXIF, cert parsing) opportunistically use
optional packages when present and degrade gracefully otherwise.
"""
from __future__ import annotations

import platform
import struct
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from core.evidence import compute_hashes
from core.metadata import shannon_entropy

# -- file identify -------------------------------------------------------
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x4d\x5a", "PE executable (MZ)"),
    (b"\x7fELF", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary (64-bit)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary / Java class"),
    (b"PK\x03\x04", "ZIP / OOXML / JAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"%PDF-", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy MS Office (OLE2) document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"regf", "Windows Registry hive"),
    (b"\x45\x6c\x66\x46\x69\x6c\x65", "Windows EVTX log"),
    (b"MDMP", "Windows minidump"),
]


def identify_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open("rb") as fh:
        header = fh.read(64)
    for signature, description in _MAGIC_SIGNATURES:
        if header.startswith(signature):
            return {"path": str(p), "type": description, "header_hex": header[:16].hex()}
    # try_magic: optional python-magic for a finer-grained mime guess
    try:
        import magic  # type: ignore
        return {"path": str(p), "type": magic.from_file(str(p)), "header_hex": header[:16].hex()}
    except ImportError:
        pass
    printable = all(32 <= b < 127 or b in (9, 10, 13) for b in header)
    return {
        "path": str(p),
        "type": "ASCII/UTF-8 text (heuristic)" if printable else "unknown binary",
        "header_hex": header[:16].hex(),
    }


# -- strings ---------------------------------------------------------------
def extract_strings(path: str | Path, min_length: int = 4, encoding: str = "ascii") -> list[str]:
    """Extract printable ASCII (or UTF-16LE, for Windows binaries) strings."""
    data = Path(path).read_bytes()
    results: list[str] = []
    if encoding == "ascii":
        current = bytearray()
        for byte in data:
            if 32 <= byte < 127:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    results.append(current.decode("ascii"))
                current = bytearray()
        if len(current) >= min_length:
            results.append(current.decode("ascii"))
    elif encoding == "utf16le":
        text = data.decode("utf-16le", errors="ignore")
        current = []
        for ch in text:
            if ch.isprintable() and ch != "\x00":
                current.append(ch)
            else:
                if len(current) >= min_length:
                    results.append("".join(current))
                current = []
        if len(current) >= min_length:
            results.append("".join(current))
    else:
        raise ValueError("encoding must be 'ascii' or 'utf16le'")
    return results


# -- hexdump -----------------------------------------------------------
def hexdump(path: str | Path, offset: int = 0, length: int = 256) -> str:
    with Path(path).open("rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


# -- archive -------------------------------------------------------------
def list_archive(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as zf:
            return [{"name": i.filename, "size": i.file_size, "compressed": i.compress_size,
                      "modified": "-".join(map(str, i.date_time))} for i in zf.infolist()]
    try:
        with tarfile.open(p) as tf:
            return [{"name": m.name, "size": m.size, "type": m.type.decode() if isinstance(m.type, bytes) else str(m.type)}
                    for m in tf.getmembers()]
    except tarfile.TarError:
        raise ValueError(f"{p} is not a recognized archive (zip/tar) format")


# -- image -----------------------------------------------------------------
def image_info(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = p.read_bytes()[:64]
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        width, height = struct.unpack(">II", data[16:24])
        return {"format": "PNG", "width": width, "height": height}
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        width, height = struct.unpack("<HH", data[6:10])
        return {"format": "GIF", "width": width, "height": height}
    if data.startswith(b"BM"):
        width, height = struct.unpack("<II", data[18:26])
        return {"format": "BMP", "width": width, "height": height}
    if data.startswith(b"\xff\xd8\xff"):
        return _jpeg_dimensions(p)
    return {"format": "unknown", "note": "Use core.metadata.MetadataEngine for EXIF (requires Pillow)."}


def _jpeg_dimensions(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        fh.read(2)
        while True:
            marker = fh.read(2)
            if len(marker) < 2 or marker[0] != 0xFF:
                break
            if marker[1] in (0xC0, 0xC2):
                fh.read(3)
                height, width = struct.unpack(">HH", fh.read(4))
                return {"format": "JPEG", "width": width, "height": height}
            length = struct.unpack(">H", fh.read(2))[0]
            fh.seek(length - 2, 1)
    return {"format": "JPEG", "width": None, "height": None}


# -- pdf ---------------------------------------------------------------
def pdf_info(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_bytes()
    if not data.startswith(b"%PDF-"):
        raise ValueError("Not a PDF file (missing %PDF- header)")
    version = data[5:8].decode(errors="ignore")
    page_count = data.count(b"/Type /Page") + data.count(b"/Type/Page")
    encrypted = b"/Encrypt" in data
    return {"pdf_version": version, "approx_page_objects": page_count, "encrypted": encrypted,
            "size_bytes": len(data)}


# -- office (OOXML) ------------------------------------------------------
def office_info(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not zipfile.is_zipfile(p):
        return {"format": "legacy OLE2 (.doc/.xls/.ppt)", "note": "Structured parsing needs olefile (optional dep)."}
    with zipfile.ZipFile(p) as zf:
        names = zf.namelist()
        kind = "unknown OOXML"
        if "word/document.xml" in names:
            kind = "Word (.docx)"
        elif any(n.startswith("xl/") for n in names):
            kind = "Excel (.xlsx)"
        elif any(n.startswith("ppt/") for n in names):
            kind = "PowerPoint (.pptx)"
        core_xml = None
        if "docProps/core.xml" in names:
            core_xml = zf.read("docProps/core.xml").decode(errors="ignore")
        return {"format": kind, "entry_count": len(names), "core_properties_xml": core_xml}


# -- cert ------------------------------------------------------------------
def cert_info(path: str | Path) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return {"note": "Certificate parsing requires the optional 'cryptography' package "
                         "(pip install cryptography)."}
    data = Path(path).read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(data, default_backend())
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }


# -- logs -----------------------------------------------------------------
def grep_log(path: str | Path, pattern: str, max_matches: int = 500,
             encoding: str = "utf-8") -> list[str]:
    import re
    regex = re.compile(pattern)
    matches = []
    with Path(path).open("r", encoding=encoding, errors="ignore") as fh:
        for line in fh:
            if regex.search(line):
                matches.append(line.rstrip("\n"))
                if len(matches) >= max_matches:
                    break
    return matches


# -- doctor ------------------------------------------------------------
OPTIONAL_PACKAGES = [
    "magic", "yara", "scapy", "Registry", "Evtx", "PIL", "cryptography", "weasyprint",
]


def doctor() -> dict[str, Any]:
    import importlib

    optional_status = {}
    for pkg in OPTIONAL_PACKAGES:
        try:
            importlib.import_module(pkg)
            optional_status[pkg] = "installed"
        except ImportError:
            optional_status[pkg] = "not installed (optional)"

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "optional_dependencies": optional_status,
    }


def hash_file(path: str | Path, algorithms=("sha256", "md5")) -> dict[str, str]:
    return compute_hashes(Path(path), algorithms)


def entropy_of_file(path: str | Path, sample_bytes: int = 4 * 1024 * 1024) -> float:
    with Path(path).open("rb") as fh:
        data = fh.read(sample_bytes)
    return shannon_entropy(data)
