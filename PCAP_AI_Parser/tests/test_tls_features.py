"""
test_tls_features.py — Unit tests for TLS Record Detection, Routing, and Feature Extraction.
"""

from __future__ import annotations

import pytest

from pcap_ai_parser.features import (
    TLSFeatures,
    extract_tls_features,
    extract_unified_packet_features,
    is_tls_record,
)
from pcap_ai_parser.intelligence.risk_scorer import HeuristicRiskScorer
from pcap_ai_parser.models.packet import PacketRecord
from pcap_ai_parser.parser.dpkt_parser import DpktParser


# Helper: construct a synthetic TLS ClientHello with SNI
def _make_tls_client_hello(sni_domain: str = "secure.example.com", version: int = 0x0303) -> bytes:
    sni_bytes = sni_domain.encode("ascii")
    # SNI extension: type (2B) + len (2B) + list len (2B) + type 0 (1B) + name len (2B) + name
    sni_ext_data = (
        (len(sni_bytes) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(sni_bytes).to_bytes(2, "big")
        + sni_bytes
    )
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data

    # Extensions container
    ext_container = len(sni_ext).to_bytes(2, "big") + sni_ext

    # Handshake body: version (2) + random (32) + session_id_len (1) + cipher_suites (2+2) + comp (1+1) + ext
    handshake_body = (
        version.to_bytes(2, "big")
        + b"\xaa" * 32
        + b"\x00"  # 0 session id
        + b"\x00\x02\x00\x2f"  # 1 cipher suite (2 bytes)
        + b"\x01\x00"  # 1 compression method
        + ext_container
    )
    # Handshake header: type 0x01 (1B) + len (3B)
    handshake_pkt = b"\x01" + len(handshake_body).to_bytes(3, "big") + handshake_body

    # TLS Record header: type 0x16 (Handshake) + version (2B) + len (2B)
    tls_record = b"\x16" + version.to_bytes(2, "big") + len(handshake_pkt).to_bytes(2, "big") + handshake_pkt
    return tls_record


class TestTLSDetectLogic:
    """Test task 1: Develop logic to detect TLS records within payloads."""

    def test_detect_tls_handshake(self):
        payload = _make_tls_client_hello("login.target.com")
        assert is_tls_record(payload) is True

    def test_detect_tls_application_data(self):
        # 0x17 (ApplicationData), 0x0303 (TLS 1.2), len=64
        payload = b"\x17\x03\x03\x00\x40" + (b"\xff" * 64)
        assert is_tls_record(payload) is True

    def test_detect_tls_alert(self):
        # 0x15 (Alert), 0x0303 (TLS 1.2), len=2
        payload = b"\x15\x03\x03\x00\x02\x02\x28"  # Fatal handshake failure
        assert is_tls_record(payload) is True

    def test_detect_tls_change_cipher_spec(self):
        # 0x14 (ChangeCipherSpec), 0x0301 (TLS 1.0), len=1
        payload = b"\x14\x03\x01\x00\x01\x01"
        assert is_tls_record(payload) is True

    def test_non_tls_http_payload(self):
        http_data = b"GET /api/v1 HTTP/1.1\r\nHost: test.com\r\n\r\n"
        assert is_tls_record(http_data) is False

    def test_non_tls_dns_payload(self):
        dns_data = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        assert is_tls_record(dns_data) is False

    def test_non_tls_raw_binary(self):
        raw_shellcode = bytes([0x90, 0x90, 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68])
        assert is_tls_record(raw_shellcode) is False

    def test_invalid_lengths_and_empty(self):
        assert is_tls_record(b"") is False
        assert is_tls_record(None) is False
        assert is_tls_record(b"\x16\x03") is False
        # Valid header prefix but invalid 0 length
        assert is_tls_record(b"\x16\x03\x03\x00\x00") is False


class TestTLSSeparateFeaturePath:
    """Test task 2: Implement a separate feature extraction path for TLS metadata."""

    def test_extract_client_hello_metadata(self):
        payload = _make_tls_client_hello("portal.example.org", version=0x0303)
        features: TLSFeatures = extract_tls_features(payload)

        assert features.is_tls is True
        assert features.record_type == "Handshake"
        assert features.record_type_code == 0x16
        assert features.version == "TLS 1.2"
        assert features.version_code == 0x0303
        assert features.record_length > 0
        assert features.handshake_type == "ClientHello"
        assert features.handshake_type_code == 0x01
        assert features.sni == "portal.example.org"
        assert features.has_sni is True
        assert features.cipher_suites_count == 1

    def test_extract_application_data_metadata(self):
        # Application data (encrypted stream)
        data = b"\x17\x03\x04\x01\x00" + (b"\xaa" * 256)
        features = extract_tls_features(data)

        assert features.is_tls is True
        assert features.record_type == "ApplicationData"
        assert features.version == "TLS 1.3"
        assert features.version_code == 0x0304
        assert features.record_length == 256
        assert features.handshake_type is None
        assert features.sni is None
        assert features.has_sni is False

    def test_non_tls_returns_empty_features(self):
        features = extract_tls_features(b"NOT A TLS RECORD")
        assert features.is_tls is False
        assert features.record_type == ""
        assert features.version == ""
        assert features.entropy_bypassed is False


class TestEntropyBypassForTLS:
    """Test task 3: Ensure entropy calculation is bypassed or adjusted for TLS records."""

    def test_tls_entropy_bypassed_by_default(self):
        payload = _make_tls_client_hello("api.service.net")
        features = extract_tls_features(payload)
        assert features.entropy_bypassed is True
        # Calculation is skipped/bypassed
        assert features.raw_entropy is None

    def test_tls_entropy_optional_raw_calculation(self):
        payload = _make_tls_client_hello("api.service.net")
        features = extract_tls_features(payload, calculate_raw_entropy=True)
        assert features.entropy_bypassed is True
        assert features.raw_entropy is not None
        assert features.raw_entropy > 0.0

    def test_unified_packet_features_tls_routing(self):
        # When routing through extract_unified_packet_features
        payload = _make_tls_client_hello("auth.secure.com")
        unified = extract_unified_packet_features(
            payload=payload,
            transport_proto="TCP",
            src_port=52000,
            dst_port=443,
        )
        assert unified.is_tls_record is True
        assert unified.tls_record_type == "Handshake"
        assert unified.tls_version == "TLS 1.2"
        assert unified.tls_sni == "auth.secure.com"
        assert unified.entropy_excluded is True
        # Entropy is bypassed (0.0) rather than evaluated as anomaly
        assert unified.shannon_entropy == 0.0
        assert unified.protocol_category in ("WEB", "ENCRYPTED")
        # SNI should be harvested as a domain IOC
        assert unified.total_ioc_count >= 1
        assert unified.domain_ioc_count >= 1

    def test_risk_scorer_ignores_entropy_for_tls_on_non_standard_port(self):
        # A TLS record sent on port 4444 (normally Metasploit port)
        # Even though high-entropy ciphertext is present, it must NOT be flagged as high entropy anomaly
        tls_payload = b"\x17\x03\x03\x00\x80" + bytes(range(128))
        rec = PacketRecord(
            packet_number=1,
            transport_proto="TCP",
            src_port=55123,
            dst_port=4444,
            payload=tls_payload,
            is_tls_record=True,
            entropy_excluded=True,
        )
        scorer = HeuristicRiskScorer()
        assessment = scorer.evaluate(rec)

        # Port 4444 will flag port risk, but entropy anomaly must be excluded
        assert not any("High entropy payload" in f for f in assessment.findings)


class TestTLSRoutingAccuracyInPipeline:
    """Test task 4: Test TLS detection and routing accuracy in streaming parser."""

    def test_dpkt_parser_routes_sample_pcap_tls(self, sample_pcap_path):
        with DpktParser(sample_pcap_path) as parser:
            packets = list(parser.parse())

        # In synthetic sample.pcap, Packet #4 is TLS Client Hello
        tls_packets = [p for p in packets if p.is_tls_record]
        assert len(tls_packets) >= 1

        pkt = tls_packets[0]
        assert pkt.is_tls_record is True
        assert pkt.tls_record_type == "Handshake"
        assert pkt.entropy_excluded is True
        assert pkt.payload_entropy == 0.0  # Bypassed
        assert pkt.protocol_category in ("WEB", "ENCRYPTED")

        # Verify serialization includes all TLS fields
        d = pkt.to_dict()
        assert d["is_tls_record"] is True
        assert d["tls_record_type"] == "Handshake"
        assert d["entropy_excluded"] is True
