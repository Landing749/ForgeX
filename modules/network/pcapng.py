"""PCAPNG (Next Generation Packet Capture) parser.

Implements the block-based container format directly (IETF
draft-tuexen-opsawg-pcapng): Section Header Block, Interface
Description Block, Enhanced/Simple Packet Block. Reuses
`modules.network.pcap._decode_packet` for the actual Ethernet/IPv4/
TCP/UDP/DNS decode, so both classic pcap and pcapng produce the same
`Packet` shape.

Block framing (every block, any type):
    0   4   Block Type
    4   4   Block Total Length
    8   ... Block Body
    ...-4   Block Total Length (repeated, for backward iteration)

Section Header Block body starts with a 4-byte Byte-Order Magic
(0x1A2B3C4D) that tells you the endianness of every subsequent field
in the file/section -- read naively (assuming little-endian) it will
come out either as that value (file is little-endian) or its byte-swap
0x4D3C2B1A (file is big-endian, switch struct formats accordingly).
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.network.pcap import Packet, _decode_packet

BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_SIMPLE_PACKET = 0x00000003
BLOCK_ENHANCED_PACKET = 0x00000006

BYTE_ORDER_MAGIC = 0x1A2B3C4D


class PcapNgError(Exception):
    pass


def _iter_blocks(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (block_type, block_body) for every top-level block, tracking
    endianness as Section Header Blocks are encountered."""
    endian = "<"
    pos = 0
    n = len(data)
    while pos + 12 <= n:
        block_type = struct.unpack_from(f"{endian}I", data, pos)[0]

        if block_type == BLOCK_SECTION_HEADER:
            # Determine endianness fresh at every Section Header Block.
            magic = struct.unpack_from("<I", data, pos + 8)[0]
            endian = "<" if magic == BYTE_ORDER_MAGIC else ">"
            block_type = BLOCK_SECTION_HEADER

        block_len = struct.unpack_from(f"{endian}I", data, pos + 4)[0]
        if block_len < 12 or pos + block_len > n:
            break
        body = data[pos + 8: pos + block_len - 4]
        yield block_type, body
        pos += block_len


def _parse_shb_options_tsresol(_body: bytes) -> int:
    return 6  # default: microsecond resolution (10^-6); if_tsresol option parsing omitted for brevity


def parse_pcapng_bytes(data: bytes, max_packets: int = 100_000) -> list[Packet]:
    if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != BLOCK_SECTION_HEADER:
        raise PcapNgError("Not a PCAPNG file (missing Section Header Block magic 0x0A0D0D0A)")

    packets: list[Packet] = []
    index = 0
    endian = "<"

    for block_type, body in _iter_blocks(data):
        if len(packets) >= max_packets:
            break

        if block_type == BLOCK_SECTION_HEADER:
            magic = struct.unpack_from("<I", body, 0)[0]
            endian = "<" if magic == BYTE_ORDER_MAGIC else ">"
            continue

        if block_type == BLOCK_ENHANCED_PACKET:
            if len(body) < 20:
                continue
            _iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack_from(f"{endian}IIIII", body, 0)
            packet_data = body[20:20 + cap_len]
            ts_ticks = (ts_high << 32) | ts_low
            # Default resolution 10^-6 (microseconds) per if_tsresol=6 assumption above.
            seconds = ts_ticks / 1_000_000
            try:
                ts_iso = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                ts_iso = None
            pkt = _decode_packet(index, ts_iso or "", packet_data)
            packets.append(pkt)
            index += 1

        elif block_type == BLOCK_SIMPLE_PACKET:
            if len(body) < 4:
                continue
            (_orig_len,) = struct.unpack_from(f"{endian}I", body, 0)
            packet_data = body[4:]
            pkt = _decode_packet(index, "", packet_data)  # SPB carries no timestamp
            packets.append(pkt)
            index += 1

        # Interface Description Blocks and others: metadata only, no packets to emit.

    return packets[:max_packets]


def read_packets(path: str | Path, max_packets: int = 100_000) -> list[Packet]:
    return parse_pcapng_bytes(Path(path).read_bytes(), max_packets=max_packets)


def summarize(path: str | Path, max_packets: int = 100_000) -> dict[str, Any]:
    packets = read_packets(path, max_packets)
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
