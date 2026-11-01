"""
test_dpkt_parser.py — unit tests for the dpkt-based PCAP parser.

Tests cover:
- Sample PCAP generation and basic parsing
- Correct extraction of Ethernet, IPv4, TCP, UDP, ICMP headers
- Port-to-application protocol mapping
- TCP flag decoding
- Summary statistics accuracy
- Edge cases: missing file, empty file, parse errors
"""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

import dpkt
import pytest

from pcap_ai_parser.models.packet import PacketRecord, decode_tcp_flags, ethertype_to_name
from pcap_ai_parser.parser.dpkt_parser import DpktParser


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _write_pcap(path: Path, packets: list[bytes]) -> None:
    """Write a list of raw Ethernet frame bytes to a PCAP file."""
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        ts = time.time()
        for i, pkt in enumerate(packets):
            writer.writepkt(pkt, ts=ts + i * 0.01)


def _make_mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _eth_frame(ip_bytes: bytes) -> bytes:
    eth = dpkt.ethernet.Ethernet()
    eth.src = _make_mac("aa:bb:cc:11:22:33")
    eth.dst = _make_mac("dd:ee:ff:44:55:66")
    eth.type = 0x0800
    eth.data = ip_bytes
    return bytes(eth)


def _tcp_pkt(
    src_ip="192.168.1.1", dst_ip="10.0.0.1",
    sport=54321, dport=80, flags=dpkt.tcp.TH_SYN,
    payload=b"",
) -> bytes:
    tcp = dpkt.tcp.TCP()
    tcp.sport = sport
    tcp.dport = dport
    tcp.seq = 1000
    tcp.ack = 0
    tcp.flags = flags
    tcp.win = 8192
    tcp.data = payload
    tcp.off = 5

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.ttl = 64
    ip.data = tcp
    ip.len = len(ip)
    return bytes(ip)


def _udp_pkt(
    src_ip="192.168.1.1", dst_ip="8.8.8.8",
    sport=12345, dport=53, payload=b"\x00" * 8,
) -> bytes:
    udp = dpkt.udp.UDP()
    udp.sport = sport
    udp.dport = dport
    udp.data = payload
    udp.ulen = 8 + len(payload)

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_UDP
    ip.ttl = 128
    ip.data = udp
    ip.len = len(ip)
    return bytes(ip)


def _icmp_pkt(src_ip="10.0.0.1", dst_ip="8.8.8.8") -> bytes:
    icmp = dpkt.icmp.ICMP()
    icmp.type = dpkt.icmp.ICMP_ECHO
    icmp.code = 0
    icmp.data = dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"test")

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_ICMP
    ip.ttl = 64
    ip.data = icmp
    ip.len = len(ip)
    return bytes(ip)


@pytest.fixture()
def mixed_pcap(tmp_path: Path) -> Path:
    """A PCAP with one TCP, one UDP DNS, and one ICMP packet."""
    pkts = [
        _eth_frame(_tcp_pkt()),                          # TCP SYN to :80
        _eth_frame(_udp_pkt()),                          # UDP DNS query
        _eth_frame(_icmp_pkt()),                         # ICMP echo
        _eth_frame(_tcp_pkt(dport=443, flags=dpkt.tcp.TH_SYN)),   # HTTPS SYN
        _eth_frame(_tcp_pkt(sport=80, dport=54321,                 # HTTP response
                             src_ip="10.0.0.1", dst_ip="192.168.1.1",
                             flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
    ]
    p = tmp_path / "mixed.pcap"
    _write_pcap(p, pkts)
    return p


@pytest.fixture()
def empty_pcap(tmp_path: Path) -> Path:
    p = tmp_path / "empty.pcap"
    _write_pcap(p, [])
    return p


# ── Tests: basic parsing ──────────────────────────────────────────────────────

class TestDpktParserBasic:

    def test_parse_returns_correct_count(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as parser:
            records = list(parser.parse())
        assert len(records) == 5

    def test_packet_numbers_sequential(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as parser:
            nums = [r.packet_number for r in parser.parse()]
        assert nums == list(range(1, 6))

    def test_timestamp_is_positive_float(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as parser:
            records = list(parser.parse())
        for r in records:
            assert isinstance(r.timestamp, float)
            assert r.timestamp > 0

    def test_wire_length_positive(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as parser:
            records = list(parser.parse())
        for r in records:
            assert r.wire_length > 0

    def test_empty_pcap_yields_nothing(self, empty_pcap: Path):
        with DpktParser(empty_pcap) as parser:
            records = list(parser.parse())
        assert records == []

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            with DpktParser(tmp_path / "nonexistent.pcap") as parser:
                list(parser.parse())


# ── Tests: link layer ─────────────────────────────────────────────────────────

class TestLinkLayer:

    def test_ethernet_link_type(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.link_type == "Ethernet"

    def test_src_mac_format(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.src_mac == "aa:bb:cc:11:22:33"

    def test_dst_mac_format(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.dst_mac == "dd:ee:ff:44:55:66"

    def test_ethertype_ipv4(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.ethertype == 0x0800


# ── Tests: network layer ──────────────────────────────────────────────────────

class TestNetworkLayer:

    def test_ipv4_proto(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.network_proto == "IPv4"
        assert rec.ip_version == 4

    def test_src_ip_correct(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.src_ip == "192.168.1.1"

    def test_dst_ip_correct(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.dst_ip == "10.0.0.1"

    def test_ttl_correct(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.ttl == 64


# ── Tests: transport layer ────────────────────────────────────────────────────

class TestTransportLayer:

    def test_tcp_transport_proto(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.transport_proto == "TCP"

    def test_tcp_ports(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.src_port == 54321
        assert rec.dst_port == 80

    def test_tcp_syn_flag(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert "SYN" in rec.tcp_flags
        assert "ACK" not in rec.tcp_flags

    def test_tcp_syn_ack_flag(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            records = list(p.parse())
        # 5th packet is SYN|ACK
        syn_ack = records[4]
        assert "SYN" in syn_ack.tcp_flags
        assert "ACK" in syn_ack.tcp_flags

    def test_udp_proto(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            records = list(p.parse())
        udp_rec = records[1]
        assert udp_rec.transport_proto == "UDP"
        assert udp_rec.src_port == 12345
        assert udp_rec.dst_port == 53

    def test_icmp_proto(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            records = list(p.parse())
        icmp_rec = records[2]
        assert icmp_rec.transport_proto == "ICMP"
        assert icmp_rec.icmp_type == dpkt.icmp.ICMP_ECHO
        assert icmp_rec.icmp_code == 0


# ── Tests: application layer ──────────────────────────────────────────────────

class TestApplicationLayer:

    def test_http_app_proto_from_port_80(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            rec = next(p.parse())
        assert rec.app_proto == "HTTP"

    def test_dns_app_proto_from_port_53(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            records = list(p.parse())
        assert records[1].app_proto == "DNS"

    def test_https_app_proto_from_port_443(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            records = list(p.parse())
        assert records[3].app_proto == "HTTPS"


# ── Tests: summary statistics ─────────────────────────────────────────────────

class TestSummary:

    def test_summary_total_packets(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert stats["total_packets"] == 5

    def test_summary_total_bytes_positive(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert stats["total_bytes"] > 0

    def test_summary_proto_distribution_has_tcp(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert "TCP" in stats["proto_distribution"]
        assert stats["proto_distribution"]["TCP"] == 3

    def test_summary_proto_distribution_has_udp(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert "UDP" in stats["proto_distribution"]

    def test_summary_top_src_ips(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert "192.168.1.1" in stats["top_src_ips"]

    def test_summary_no_parse_errors(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap) as p:
            list(p.parse())
            stats = p.summary()
        assert stats["parse_errors"] == 0


# ── Tests: max_packets ────────────────────────────────────────────────────────

class TestMaxPackets:

    def test_max_packets_limits_output(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap, max_packets=2) as p:
            records = list(p.parse())
        assert len(records) == 2

    def test_max_packets_zero_means_all(self, mixed_pcap: Path):
        with DpktParser(mixed_pcap, max_packets=0) as p:
            records = list(p.parse())
        assert len(records) == 5


# ── Tests: helper functions ───────────────────────────────────────────────────

class TestHelpers:

    def test_decode_tcp_flags_syn(self):
        assert decode_tcp_flags(0x002) == "SYN"

    def test_decode_tcp_flags_syn_ack(self):
        result = decode_tcp_flags(0x012)
        assert "SYN" in result
        assert "ACK" in result

    def test_decode_tcp_flags_fin_ack(self):
        result = decode_tcp_flags(0x011)
        assert "FIN" in result
        assert "ACK" in result

    def test_decode_tcp_flags_none(self):
        assert decode_tcp_flags(0x000) == "NONE"

    def test_ethertype_to_name_ipv4(self):
        assert ethertype_to_name(0x0800) == "IPv4"

    def test_ethertype_to_name_ipv6(self):
        assert ethertype_to_name(0x86DD) == "IPv6"

    def test_ethertype_to_name_arp(self):
        assert ethertype_to_name(0x0806) == "ARP"

    def test_ethertype_to_name_unknown(self):
        assert ethertype_to_name(0xDEAD) == "0xDEAD"

    def test_packet_record_to_dict(self):
        rec = PacketRecord(packet_number=1, src_ip="1.2.3.4", dst_ip="5.6.7.8")
        d = rec.to_dict()
        assert d["src_ip"] == "1.2.3.4"
        assert "payload_preview" not in d  # binary field excluded

    def test_packet_record_str(self):
        rec = PacketRecord(
            packet_number=42,
            transport_proto="TCP",
            src_ip="1.2.3.4", src_port=80,
            dst_ip="5.6.7.8", dst_port=54321,
            wire_length=100,
        )
        s = str(rec)
        assert "#" in s and "42" in s
        assert "TCP" in s
