"""
dpkt_parser.py — fast, low-overhead PCAP parser using the dpkt library.

Features
--------
- Reads both legacy PCAP and modern PCAPng files.
- Extracts Ethernet, IPv4/IPv6, TCP, UDP, ICMP, and ICMPv6 headers.
- Guesses application-layer protocol from well-known port numbers.
- Yields PacketRecord instances — one per packet — for streaming pipelines.
- Collects per-file summary statistics without holding all packets in RAM.

Usage
-----
    from pcap_ai_parser.parser.dpkt_parser import DpktParser

    with DpktParser("capture.pcap") as parser:
        for record in parser.parse():
            print(record)

    summary = parser.summary()
"""

from __future__ import annotations

import socket
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Generator, Optional

import dpkt
from loguru import logger

from pcap_ai_parser.models.packet import (
    PacketRecord,
    decode_tcp_flags,
    ethertype_to_name,
)

# ── Well-known port → application protocol mapping ───────────────────────────

_PORT_PROTO: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _guess_app_proto(src_port: Optional[int], dst_port: Optional[int]) -> str:
    """Return the best-guess application protocol from port numbers."""
    for port in (dst_port, src_port):
        if port and port in _PORT_PROTO:
            return _PORT_PROTO[port]
    return ""


def _mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC address to colon-separated hex string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _ip4_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, raw)
    except Exception:
        return ""


def _ip6_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return ""


# ── Main parser class ─────────────────────────────────────────────────────────


class DpktParser:
    """
    Streaming PCAP parser backed by dpkt.

    Supports PCAP (classic) and PCAPng via dpkt's auto-detection.
    Use as a context manager to ensure the file handle is always closed.

    Parameters
    ----------
    path : str | Path
        Path to the .pcap / .pcapng file.
    max_packets : int, optional
        Stop after this many packets (0 = unlimited).
    """

    def __init__(self, path: str | Path, max_packets: int = 0) -> None:
        self.path = Path(path)
        self.max_packets = max_packets
        self._fh = None
        self._reader = None

        # ── Running statistics ────────────────────────────────────────────
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._proto_counter: Counter = Counter()
        self._app_proto_counter: Counter = Counter()
        self._ip_src_counter: Counter = Counter()
        self._ip_dst_counter: Counter = Counter()
        self._errors: list[str] = []

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "DpktParser":
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def open(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.path}")
        self._fh = open(self.path, "rb")
        # Try PCAPng first; fall back to classic PCAP
        try:
            self._reader = dpkt.pcapng.Reader(self._fh)
            logger.debug("Opened as PCAPng: {}", self.path.name)
        except Exception:
            self._fh.seek(0)
            try:
                self._reader = dpkt.pcap.Reader(self._fh)
                logger.debug("Opened as PCAP (classic): {}", self.path.name)
            except Exception as exc:
                self._fh.close()
                raise ValueError(f"Cannot read file as PCAP or PCAPng: {exc}") from exc

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    # ── Core parsing generator ────────────────────────────────────────────

    def parse(self) -> Generator[PacketRecord, None, None]:
        """
        Yield one :class:`PacketRecord` per packet in the capture file.

        Packets that cannot be decoded are still yielded — with the
        ``parse_errors`` field populated — so the caller always sees a
        complete count.
        """
        if self._reader is None:
            raise RuntimeError("Parser not opened. Use DpktParser as a context manager.")

        for pkt_num, (ts, raw_pkt) in enumerate(self._reader, start=1):
            if self.max_packets and pkt_num > self.max_packets:
                break

            record = PacketRecord(
                packet_number=pkt_num,
                timestamp=float(ts),
                captured_length=len(raw_pkt),
                wire_length=len(raw_pkt),
                parse_backend="dpkt",
            )

            try:
                self._parse_ethernet(raw_pkt, record)
            except Exception as exc:
                msg = f"Packet #{pkt_num}: {exc}"
                record.parse_errors.append(msg)
                self._errors.append(msg)
                logger.trace(msg)

            # ── Update statistics ─────────────────────────────────────────
            self._total_packets += 1
            self._total_bytes += record.wire_length
            proto_key = record.transport_proto or record.network_proto or "UNKNOWN"
            self._proto_counter[proto_key] += 1
            if record.app_proto:
                self._app_proto_counter[record.app_proto] += 1
            if record.src_ip:
                self._ip_src_counter[record.src_ip] += 1
            if record.dst_ip:
                self._ip_dst_counter[record.dst_ip] += 1

            yield record

    # ── Layer decoders ────────────────────────────────────────────────────

    def _parse_ethernet(self, raw: bytes, rec: PacketRecord) -> None:
        eth = dpkt.ethernet.Ethernet(raw)
        rec.link_type = "Ethernet"
        rec.src_mac = _mac_to_str(eth.src)
        rec.dst_mac = _mac_to_str(eth.dst)
        rec.ethertype = eth.type
        rec.network_proto = ethertype_to_name(eth.type)

        if isinstance(eth.data, dpkt.ip.IP):
            self._parse_ipv4(eth.data, rec)
        elif isinstance(eth.data, dpkt.ip6.IP6):
            self._parse_ipv6(eth.data, rec)
        elif isinstance(eth.data, dpkt.arp.ARP):
            rec.network_proto = "ARP"

    def _parse_ipv4(self, ip: dpkt.ip.IP, rec: PacketRecord) -> None:
        rec.network_proto = "IPv4"
        rec.ip_version = 4
        rec.src_ip = _ip4_to_str(ip.src)
        rec.dst_ip = _ip4_to_str(ip.dst)
        rec.ttl = ip.ttl
        rec.ip_flags = (ip.rf << 2) | (ip.df << 1) | ip.mf
        rec.ip_frag_offset = ip.offset
        rec.wire_length = ip.len

        self._parse_transport(ip, rec)

    def _parse_ipv6(self, ip6: dpkt.ip6.IP6, rec: PacketRecord) -> None:
        rec.network_proto = "IPv6"
        rec.ip_version = 6
        rec.src_ip = _ip6_to_str(ip6.src)
        rec.dst_ip = _ip6_to_str(ip6.dst)
        rec.ttl = ip6.hlim

        self._parse_transport(ip6, rec)

    def _parse_transport(self, ip, rec: PacketRecord) -> None:
        data = ip.data

        if isinstance(data, dpkt.tcp.TCP):
            rec.transport_proto = "TCP"
            rec.src_port = data.sport
            rec.dst_port = data.dport
            rec.tcp_flags = decode_tcp_flags(data.flags)
            rec.tcp_seq = data.seq
            rec.tcp_ack = data.ack
            rec.tcp_window = data.win
            raw_payload = bytes(data.data) if data.data else b""
            rec.payload = raw_payload
            rec.payload_length = len(raw_payload)
            rec.payload_preview = raw_payload[:64]
            rec.app_proto = _guess_app_proto(data.sport, data.dport)

        elif isinstance(data, dpkt.udp.UDP):
            rec.transport_proto = "UDP"
            rec.src_port = data.sport
            rec.dst_port = data.dport
            rec.udp_length = data.ulen
            raw_payload = bytes(data.data) if data.data else b""
            rec.payload = raw_payload
            rec.payload_length = len(raw_payload)
            rec.payload_preview = raw_payload[:64]
            rec.app_proto = _guess_app_proto(data.sport, data.dport)

        elif isinstance(data, dpkt.icmp.ICMP):
            rec.transport_proto = "ICMP"
            rec.icmp_type = data.type
            rec.icmp_code = data.code
            if hasattr(data, "data") and data.data:
                icmp_inner = getattr(data.data, "data", data.data)
                raw_payload = bytes(icmp_inner) if isinstance(icmp_inner, (bytes, bytearray)) else b""
                rec.payload = raw_payload
                rec.payload_length = len(raw_payload)
                rec.payload_preview = raw_payload[:64]

        elif isinstance(data, dpkt.icmp6.ICMP6):
            rec.transport_proto = "ICMPv6"
            rec.icmp_type = data.type
            rec.icmp_code = data.code

    # ── Summary stats ─────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a summary statistics dict after parsing is complete."""
        return {
            "file": str(self.path),
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "avg_packet_size": (
                round(self._total_bytes / self._total_packets, 2)
                if self._total_packets
                else 0
            ),
            "proto_distribution": dict(self._proto_counter.most_common()),
            "app_proto_distribution": dict(self._app_proto_counter.most_common()),
            "top_src_ips": dict(self._ip_src_counter.most_common(10)),
            "top_dst_ips": dict(self._ip_dst_counter.most_common(10)),
            "parse_errors": len(self._errors),
        }
