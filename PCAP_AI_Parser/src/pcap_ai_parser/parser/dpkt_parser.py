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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional, List, Dict, Any, Tuple

import dpkt
from loguru import logger

from pcap_ai_parser.features import (
    calculate_payload_size,
    calculate_printable_ascii_ratio,
    calculate_shannon_entropy,
    extract_encoding_features,
    extract_ioc_features,
    extract_protocol_context,
)
from pcap_ai_parser.models.packet import (
    PacketRecord,
    decode_tcp_flags,
    ethertype_to_name,
)
from pcap_ai_parser.parser.payload_extractor import PayloadExtractor, ExtractedPayloadInfo

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

        # ── Feature Engineering: Extraction Pipeline ─────────────────────────
        # 1. Payload Characteristics
        if rec.payload:
            rec.payload_size = calculate_payload_size(rec.payload)
            rec.payload_entropy = calculate_shannon_entropy(rec.payload)
            rec.printable_ascii_ratio = calculate_printable_ascii_ratio(rec.payload)
        else:
            rec.payload_size = 0
            rec.payload_entropy = 0.0
            rec.printable_ascii_ratio = 0.0

        # 2. Protocol Context
        p_ctx = extract_protocol_context(
            transport_proto=rec.transport_proto,
            src_port=rec.src_port,
            dst_port=rec.dst_port,
            app_proto=rec.app_proto,
        )
        rec.protocol_category = p_ctx.protocol_category
        rec.is_well_known_port = p_ctx.is_well_known_port
        rec.is_client_to_server = p_ctx.is_client_to_server

        # 3. Encoding Indicators & IOC Features
        if rec.payload:
            enc = extract_encoding_features(rec.payload)
            rec.has_encoding = enc.has_encoding
            rec.has_base64 = enc.has_base64
            rec.has_url_encoding = enc.has_url_encoding
            rec.has_hex_encoding = enc.has_hex_encoding

            iocs = extract_ioc_features(rec.payload)
            rec.total_ioc_count = iocs.total_ioc_count
            rec.has_iocs = iocs.has_iocs
        else:
            rec.has_encoding = False
            rec.has_base64 = False
            rec.has_url_encoding = False
            rec.has_hex_encoding = False
            rec.total_ioc_count = 0
            rec.has_iocs = False

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


# ── Packet & Parser abstractions for Payload Normalization & Triage ──────────

@dataclass
class ParsedPacket:
    """Dataclass holding extracted network metadata and normalized payload details for a single packet."""
    packet_index: int
    timestamp: float
    orig_len: int
    src_ip: str
    dst_ip: str
    ip_version: int
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload_info: Optional[ExtractedPayloadInfo] = None

    @property
    def payload_size(self) -> int:
        """Convenience property for payload size in bytes."""
        return self.payload_info.payload_len if self.payload_info else 0

    @property
    def payload_entropy(self) -> float:
        """Convenience property for payload Shannon entropy."""
        if self.payload_info and self.payload_info.normalization:
            return self.payload_info.normalization.metrics.get("shannon_entropy", 0.0)
        return 0.0

    @property
    def printable_ascii_ratio(self) -> float:
        """Convenience property for payload printable ASCII ratio."""
        if self.payload_info and self.payload_info.normalization:
            return self.payload_info.normalization.metrics.get("printable_ascii_ratio", 0.0)
        return 0.0

    @property
    def protocol_category(self) -> str:
        ctx = extract_protocol_context(self.protocol, self.src_port, self.dst_port)
        return ctx.protocol_category

    @property
    def is_well_known_port(self) -> bool:
        ctx = extract_protocol_context(self.protocol, self.src_port, self.dst_port)
        return ctx.is_well_known_port

    @property
    def total_ioc_count(self) -> int:
        if self.payload_info and self.payload_info.raw_payload:
            return extract_ioc_features(self.payload_info.raw_payload).total_ioc_count
        return 0

    @property
    def has_encoding(self) -> bool:
        if self.payload_info and self.payload_info.raw_payload:
            return extract_encoding_features(self.payload_info.raw_payload).has_encoding
        return False

    def get_5tuple(self) -> Tuple[str, int, str, int, str]:
        """Returns standard 5-tuple identifier (src_ip, src_port, dst_ip, dst_port, protocol)."""
        return (
            self.src_ip,
            self.src_port or 0,
            self.dst_ip,
            self.dst_port or 0,
            self.protocol,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts parsed packet into serializable dictionary format."""
        return {
            "packet_index": self.packet_index,
            "timestamp": self.timestamp,
            "orig_len": self.orig_len,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "protocol_category": self.protocol_category,
            "is_well_known_port": self.is_well_known_port,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_size": self.payload_size,
            "payload_entropy": self.payload_entropy,
            "printable_ascii_ratio": self.printable_ascii_ratio,
            "total_ioc_count": self.total_ioc_count,
            "has_encoding": self.has_encoding,
            "payload_info": self.payload_info.to_dict() if self.payload_info else None,
        }


class DpktPCAPParser:
    """
    PCAP file parser leveraging dpkt for high-throughput packet decoding,
    metadata extraction, and application payload normalization.
    """

    def __init__(self, hex_escape_non_printable: bool = True):
        self.payload_extractor = PayloadExtractor(hex_escape_non_printable=hex_escape_non_printable)

    def parse_file(self, pcap_path: str) -> List[ParsedPacket]:
        """
        Reads a PCAP / PCAPNG file and parses all packet records into ParsedPacket objects.
        """
        packets: List[ParsedPacket] = []
        packet_idx = 0

        with open(pcap_path, "rb") as f:
            try:
                pcap_reader = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap_reader = dpkt.pcapng.Reader(f)

            for ts, buf in pcap_reader:
                packet_idx += 1
                try:
                    parsed = self._parse_single_packet(packet_idx, ts, buf)
                    if parsed:
                        packets.append(parsed)
                except Exception:
                    continue

        return packets

    def _parse_single_packet(self, packet_idx: int, ts: float, buf: bytes) -> Optional[ParsedPacket]:
        """Parses raw packet buffer into a ParsedPacket object."""
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            try:
                ip = dpkt.ip.IP(buf)
                return self._parse_ip_layer(packet_idx, ts, len(buf), ip)
            except Exception:
                return None

        if isinstance(eth.data, dpkt.ip.IP):
            return self._parse_ip_layer(packet_idx, ts, len(buf), eth.data)
        elif isinstance(eth.data, dpkt.ip6.IP6):
            return self._parse_ip6_layer(packet_idx, ts, len(buf), eth.data)
        
        return None

    def _parse_ip_layer(self, packet_idx: int, ts: float, orig_len: int, ip: dpkt.ip.IP) -> ParsedPacket:
        """Decodes IPv4 header and inner transport protocol payload."""
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        protocol_name, src_port, dst_port, raw_payload = self._extract_transport(ip)

        payload_info = self.payload_extractor.extract_payload(
            transport_proto=protocol_name,
            payload_bytes=raw_payload,
            src_port=src_port,
            dst_port=dst_port,
        )

        return ParsedPacket(
            packet_index=packet_idx,
            timestamp=ts,
            orig_len=orig_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=4,
            protocol=protocol_name,
            src_port=src_port,
            dst_port=dst_port,
            payload_info=payload_info,
        )

    def _parse_ip6_layer(self, packet_idx: int, ts: float, orig_len: int, ip6: dpkt.ip6.IP6) -> ParsedPacket:
        """Decodes IPv6 header and inner transport protocol payload."""
        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)

        protocol_name, src_port, dst_port, raw_payload = self._extract_transport(ip6)

        payload_info = self.payload_extractor.extract_payload(
            transport_proto=protocol_name,
            payload_bytes=raw_payload,
            src_port=src_port,
            dst_port=dst_port,
        )

        return ParsedPacket(
            packet_index=packet_idx,
            timestamp=ts,
            orig_len=orig_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=6,
            protocol=protocol_name,
            src_port=src_port,
            dst_port=dst_port,
            payload_info=payload_info,
        )

    def _extract_transport(self, ip_obj: Any) -> Tuple[str, Optional[int], Optional[int], bytes]:
        """Extracts transport protocol name, ports, and payload bytes from IP packet object."""
        data = ip_obj.data

        if isinstance(data, dpkt.tcp.TCP):
            return "TCP", data.sport, data.dport, bytes(data.data)
        elif isinstance(data, dpkt.udp.UDP):
            return "UDP", data.sport, data.dport, bytes(data.data)
        elif isinstance(data, dpkt.icmp.ICMP):
            return "ICMP", None, None, bytes(data.data)
        elif isinstance(data, bytes):
            return "RAW", None, None, data
        else:
            return "OTHER", None, None, bytes(getattr(data, "data", b""))

