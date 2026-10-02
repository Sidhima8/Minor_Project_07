"""
Dpkt-based PCAP parser for bulk processing of network capture files.
"""

from dataclasses import dataclass, field
import socket
from typing import List, Optional, Dict, Any, Tuple
import dpkt  # type: ignore[import-untyped]
from pcap_ai_parser.parser.payload_extractor import PayloadExtractor, ExtractedPayloadInfo


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
            "src_port": self.src_port,
            "dst_port": self.dst_port,
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
        
        Args:
            pcap_path: Absolute or relative file path to the PCAP file.
            
        Returns:
            List of ParsedPacket instances.
        """
        packets: List[ParsedPacket] = []
        packet_idx = 0

        with open(pcap_path, "rb") as f:
            try:
                pcap_reader = dpkt.pcap.Reader(f)
            except Exception:
                # Retry with pcapng reader if standard pcap reader fails
                f.seek(0)
                pcap_reader = dpkt.pcapng.Reader(f)

            for ts, buf in pcap_reader:
                packet_idx += 1
                try:
                    parsed = self._parse_single_packet(packet_idx, ts, buf)
                    if parsed:
                        packets.append(parsed)
                except Exception:
                    # Skip corrupt or unrecognized link-layer frames
                    continue

        return packets

    def _parse_single_packet(self, packet_idx: int, ts: float, buf: bytes) -> Optional[ParsedPacket]:
        """Parses raw packet buffer into a ParsedPacket object."""
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            # Handle raw IP packets without Ethernet headers
            try:
                ip = dpkt.ip.IP(buf)
                return self._parse_ip_layer(packet_idx, ts, len(buf), ip)
            except Exception:
                return None

        # Check for IP or IPv6 layer
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
