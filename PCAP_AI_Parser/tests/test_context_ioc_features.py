"""
test_context_ioc_features.py — Unit tests for Context, IOCs, and Encoding Features.
"""

from __future__ import annotations

import pytest

from pcap_ai_parser.features import (
    extract_encoding_features,
    extract_ioc_features,
    extract_protocol_context,
    extract_unified_packet_features,
)
from pcap_ai_parser.models.packet import PacketRecord
from pcap_ai_parser.parser.dpkt_parser import DpktParser


class TestProtocolContextExtraction:
    """Test protocol context feature extraction."""

    def test_http_context(self):
        ctx = extract_protocol_context("TCP", src_port=54321, dst_port=80, app_proto="HTTP")
        assert ctx.transport_proto == "TCP"
        assert ctx.app_proto == "HTTP"
        assert ctx.protocol_category == "WEB"
        assert ctx.is_well_known_port is True
        assert ctx.is_client_to_server is True

    def test_dns_context(self):
        ctx = extract_protocol_context("UDP", src_port=12345, dst_port=53, app_proto="DNS")
        assert ctx.transport_proto == "UDP"
        assert ctx.app_proto == "DNS"
        assert ctx.protocol_category == "DNS"
        assert ctx.is_well_known_port is True

    def test_remote_access_context(self):
        ctx = extract_protocol_context("TCP", src_port=61000, dst_port=22, app_proto="SSH")
        assert ctx.protocol_category == "REMOTE_ACCESS"

    def test_database_context(self):
        ctx = extract_protocol_context("TCP", src_port=45000, dst_port=3306, app_proto="MySQL")
        assert ctx.protocol_category == "DATABASE"

    def test_network_infra_icmp(self):
        ctx = extract_protocol_context("ICMP", src_port=None, dst_port=None)
        assert ctx.protocol_category == "NETWORK_INFRA"

    def test_unknown_high_ports(self):
        ctx = extract_protocol_context("TCP", src_port=55000, dst_port=55001)
        assert ctx.protocol_category == "OTHER"
        assert ctx.is_well_known_port is False


class TestIOCFeaturesExtraction:
    """Test total IOC count per packet and breakdown."""

    def test_ioc_empty_payload(self):
        res = extract_ioc_features(b"")
        assert res.total_ioc_count == 0
        assert res.has_iocs is False
        assert res.url_ioc_count == 0
        assert res.domain_ioc_count == 0
        assert res.ip_ioc_count == 0

    def test_ioc_with_url_and_domain(self):
        payload = b"GET /path HTTP/1.1\r\nHost: c2-command.xyz\r\nReferer: http://malicious.org/dl\r\n\r\n"
        res = extract_ioc_features(payload)
        assert res.has_iocs is True
        assert res.total_ioc_count >= 2
        assert res.url_ioc_count >= 1
        assert res.domain_ioc_count >= 1

    def test_ioc_with_ip_and_cve(self):
        payload = b"Exploit CVE-2021-44228 sent to target 198.51.100.25 via ldap\n"
        res = extract_ioc_features(payload)
        assert res.has_iocs is True
        assert res.cve_ioc_count >= 1
        assert res.ip_ioc_count >= 1
        assert res.total_ioc_count >= 2

    def test_ioc_with_hashes(self):
        payload = b"File md5: d41d8cd98f00b204e9800998ecf8427e sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        res = extract_ioc_features(payload)
        assert res.hash_ioc_count >= 1
        assert res.total_ioc_count >= 1


class TestEncodingIndicatorsExtraction:
    """Test encoding indicator features (e.g. Base64 detection)."""

    def test_encoding_empty(self):
        res = extract_encoding_features(b"")
        assert res.has_encoding is False
        assert res.has_base64 is False
        assert res.has_url_encoding is False
        assert res.has_hex_encoding is False

    def test_encoding_plain_text(self):
        payload = b"This is just normal plain English text with no hidden encodings."
        res = extract_encoding_features(payload)
        assert res.has_base64 is False
        assert res.has_url_encoding is False

    def test_base64_detection(self):
        # Base64 encoded: "http://malicious-c2-server.xyz/beacon.php?id=1337"
        payload = b"POST /api HTTP/1.1\r\n\r\ndata=aHR0cDovL21hbGljaW91cy1jMi1zZXJ2ZXIueHl6L2JlYWNvbi5waHA/aWQ9MTMzNw==\r\n"
        res = extract_encoding_features(payload)
        assert res.has_encoding is True
        assert res.has_base64 is True
        assert res.base64_count >= 1

    def test_url_encoding_detection(self):
        payload = b"GET /search?q=%27%20UNION%20SELECT%20null HTTP/1.1\r\n"
        res = extract_encoding_features(payload)
        assert res.has_encoding is True
        assert res.has_url_encoding is True
        assert res.url_encoding_count >= 1

    def test_hex_encoding_detection(self):
        payload = b"Shellcode: \\x41\\x42\\x43\\x44\\x45\\x46"
        res = extract_encoding_features(payload)
        assert res.has_encoding is True
        assert res.has_hex_encoding is True


class TestUnifiedFeaturesIntegration:
    """Test integration of payload, context, IOCs, and encoding indicators."""

    def test_unified_packet_features(self):
        payload = b"POST /login HTTP/1.1\r\nHost: target-portal.local\r\n\r\ndata=aHR0cDovL2F0dGFja2VyLnh5ei9jMgo="
        unified = extract_unified_packet_features(
            payload=payload,
            transport_proto="TCP",
            src_port=54321,
            dst_port=80,
            app_proto="HTTP",
        )
        assert unified.payload_size == len(payload)
        assert unified.shannon_entropy > 0.0
        assert unified.transport_proto == "TCP"
        assert unified.protocol_category == "WEB"
        assert unified.is_well_known_port is True
        assert unified.has_base64 is True
        assert unified.total_ioc_count >= 1

        d = unified.to_dict()
        assert "payload_size" in d
        assert "protocol_category" in d
        assert "total_ioc_count" in d
        assert "has_base64" in d

    def test_pipeline_streaming_dpkt_parser(self, sample_pcap_path):
        with DpktParser(sample_pcap_path) as parser:
            packets = list(parser.parse())

        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt.protocol_category, str)
            assert isinstance(pkt.total_ioc_count, int)
            assert isinstance(pkt.has_base64, bool)
            assert isinstance(pkt.has_encoding, bool)

            d = pkt.to_dict()
            assert "protocol_category" in d
            assert "total_ioc_count" in d
            assert "has_base64" in d
            assert "has_url_encoding" in d
