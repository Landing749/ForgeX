"""Network Module.

Covers: PCAP, DNS, HTTP, TLS, JA3.

Implements a dependency-free reader for the classic libpcap file
format (magic 0xa1b2c3d4 / 0xd4c3b2a1) plus best-effort Ethernet/
IPv4/TCP/UDP/DNS decoding using stdlib `struct` -- enough to build a
network timeline and pull basic IOC-relevant fields (src/dst IP,
ports, DNS queries) without scapy. Full protocol reconstruction
(HTTP request/response reassembly, TLS ClientHello/JA3 fingerprinting,
PCAPNG support) is deep enough to warrant the optional `scapy`
dependency, so those are exposed as extension points that use scapy
when available.
"""
from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAGIC_LE = 0xa1b2c3d4
_MAGIC_BE = 0xd4c3b2a1
_MAGIC_NS_LE = 0xa1b23c4d


@dataclass
class Packet:
    index: int
    timestamp: str
    length: int
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    dns_query: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_global_header(fh) -> tuple[str, bool]:
    raw = fh.read(24)
    if len(raw) < 24:
        raise ValueError("Not a valid pcap file (truncated global header)")
    (magic,) = struct.unpack("<I", raw[:4])
    if magic == _MAGIC_LE:
        return "<", False
    if magic == _MAGIC_NS_LE:
        return "<", True
    (magic_be,) = struct.unpack(">I", raw[:4])
    if magic_be == _MAGIC_LE:
        return ">", False
    raise ValueError(
        "Unrecognized pcap magic bytes. PCAPNG (0x0a0d0d0a) files need the "
        "optional 'scapy' backend via read_packets_scapy()."
    )


def read_packets(path: str | Path, max_packets: int = 100_000) -> Iterator[Packet]:
    with Path(path).open("rb") as fh:
        endian, nanosecond = _read_global_header(fh)
        idx = 0
        while idx < max_packets:
            header = fh.read(16)
            if len(header) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", header)
            data = fh.read(incl_len)
            if len(data) < incl_len:
                break
            frac_seconds = ts_frac / 1_000_000_000 if nanosecond else ts_frac / 1_000_000
            ts = datetime.fromtimestamp(ts_sec + frac_seconds, tz=timezone.utc).isoformat()
            yield _decode_packet(idx, ts, data)
            idx += 1


def _decode_packet(index: int, ts: str, data: bytes) -> Packet:
    pkt = Packet(index=index, timestamp=ts, length=len(data))
    if len(data) < 14:
        return pkt
    eth_type = struct.unpack(">H", data[12:14])[0]
    if eth_type != 0x0800:  # only IPv4 decoded; IPv6/ARP left as raw length-only entries
        return pkt

    ip_start = 14
    if len(data) < ip_start + 20:
        return pkt
    ver_ihl = data[ip_start]
    ihl = (ver_ihl & 0x0F) * 4
    proto = data[ip_start + 9]
    src_ip = socket.inet_ntoa(data[ip_start + 12: ip_start + 16])
    dst_ip = socket.inet_ntoa(data[ip_start + 16: ip_start + 20])
    pkt.src_ip, pkt.dst_ip = src_ip, dst_ip

    transport_start = ip_start + ihl
    if proto == 6 and len(data) >= transport_start + 4:
        pkt.protocol = "TCP"
        pkt.src_port, pkt.dst_port = struct.unpack(">HH", data[transport_start:transport_start + 4])
    elif proto == 17 and len(data) >= transport_start + 4:
        pkt.protocol = "UDP"
        pkt.src_port, pkt.dst_port = struct.unpack(">HH", data[transport_start:transport_start + 4])
        if pkt.src_port == 53 or pkt.dst_port == 53:
            pkt.dns_query = _extract_dns_query(data[transport_start + 8:])
    elif proto == 1:
        pkt.protocol = "ICMP"
    else:
        pkt.protocol = f"proto-{proto}"
    return pkt


def _extract_dns_query(dns_payload: bytes) -> str | None:
    """Best-effort parse of the first question name in a DNS message."""
    if len(dns_payload) < 12:
        return None
    try:
        offset = 12
        labels = []
        while offset < len(dns_payload):
            length = dns_payload[offset]
            if length == 0:
                break
            offset += 1
            labels.append(dns_payload[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        return ".".join(labels) if labels else None
    except (IndexError, UnicodeDecodeError):
        return None


def summarize(path: str | Path, max_packets: int = 100_000) -> dict[str, Any]:
    packets = list(read_packets(path, max_packets))
    conversations: dict[tuple[str, str], int] = {}
    dns_queries: set[str] = set()
    for p in packets:
        if p.src_ip and p.dst_ip:
            key = tuple(sorted([p.src_ip, p.dst_ip]))
            conversations[key] = conversations.get(key, 0) + 1
        if p.dns_query:
            dns_queries.add(p.dns_query)
    return {
        "packet_count": len(packets),
        "top_conversations": sorted(
            [{"hosts": list(k), "packets": v} for k, v in conversations.items()],
            key=lambda x: x["packets"], reverse=True,
        )[:25],
        "dns_queries": sorted(dns_queries),
    }


# -- extension points needing deeper protocol reconstruction ---------------
def read_packets_scapy(path: str | Path):
    """PCAPNG support + full protocol layers via scapy, when installed."""
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise NotImplementedError(
            "PCAPNG and deep protocol parsing require the optional 'scapy' "
            "package (pip install forgex[full])."
        ) from exc
    return PcapReader(str(path))


def compute_ja3(_tls_client_hello_bytes: bytes) -> str:
    raise NotImplementedError(
        "JA3 fingerprinting requires parsing a TLS ClientHello's cipher "
        "suites/extensions/curves; implement via scapy's TLS layer "
        "(pip install forgex[full], scapy.layers.tls) in a plugin."
    )


def reassemble_http(_packets: list[Packet]) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "HTTP request/response reassembly requires TCP stream reassembly; "
        "implement via scapy's TCP session support in a plugin."
    )
