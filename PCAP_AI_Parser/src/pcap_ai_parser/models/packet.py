"""
PacketRecord — normalised dataclass representing a single parsed packet.

Both the dpkt and tshark backends populate this same structure so
downstream consumers (DataFrames, ML models, reports) are backend-agnostic.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PacketRecord:
    """A flattened, normalised representation of a single network packet."""

    # ── Capture metadata ─────────────────────────────────────────────────
    packet_number: int = 0
    timestamp: float = 0.0          # Unix epoch seconds (float for µs precision)
    captured_length: int = 0        # bytes actually captured (snap length)
    wire_length: int = 0            # bytes on the wire

    # ── Link layer ───────────────────────────────────────────────────────
    link_type: str = ""             # e.g. "Ethernet", "Loopback"
    src_mac: str = ""               # "aa:bb:cc:dd:ee:ff"
    dst_mac: str = ""
    ethertype: int = 0              # 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP …

    # ── Network layer ────────────────────────────────────────────────────
    network_proto: str = ""         # "IPv4", "IPv6", "ARP", …
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: int = 0             # 4 or 6
    ttl: int = 0                    # TTL / Hop Limit
    ip_flags: int = 0
    ip_frag_offset: int = 0

    # ── Transport layer ──────────────────────────────────────────────────
    transport_proto: str = ""       # "TCP", "UDP", "ICMP", "ICMPv6", …
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP-specific
    tcp_flags: str = ""             # Human-readable: "SYN", "ACK", "FIN|ACK" …
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None

    # UDP-specific
    udp_length: Optional[int] = None

    # ICMP-specific
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ── Application layer ────────────────────────────────────────────────
    app_proto: str = ""             # Best-guess: "HTTP", "DNS", "TLS", …
    payload_length: int = 0
    payload_preview: bytes = field(default_factory=bytes, repr=False)  # first 64 B
    payload: bytes = field(default_factory=bytes, repr=False)          # full application payload

    # ── Parse provenance ─────────────────────────────────────────────────
    parse_backend: str = ""         # "dpkt" | "tshark"
    parse_errors: list[str] = field(default_factory=list)

    # ── Convenience helpers ──────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise to a flat dict suitable for pandas DataFrame rows."""
        d = asdict(self)
        d.pop("payload_preview", None)   # binary — drop from tabular output
        d.pop("payload", None)           # binary — drop from tabular output
        return d

    def __str__(self) -> str:
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        return (
            f"[#{self.packet_number:>6}] {self.transport_proto or self.network_proto}"
            f"  {src!s:<25} → {dst!s:<25}"
            f"  len={self.wire_length}"
        )


# ── TCP flag decoder ─────────────────────────────────────────────────────────

_TCP_FLAG_MAP = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
    0x040: "ECE",
    0x080: "CWR",
    0x100: "NS",
}


def decode_tcp_flags(flags_int: int) -> str:
    """Convert a raw TCP flags integer to a readable string like 'SYN|ACK'."""
    active = [name for bit, name in sorted(_TCP_FLAG_MAP.items()) if flags_int & bit]
    return "|".join(active) if active else "NONE"


# ── Ethertype decoder ────────────────────────────────────────────────────────

_ETHERTYPE_MAP = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
    0x8847: "MPLS",
    0x88CC: "LLDP",
}


def ethertype_to_name(ethertype: int) -> str:
    return _ETHERTYPE_MAP.get(ethertype, f"0x{ethertype:04X}")
