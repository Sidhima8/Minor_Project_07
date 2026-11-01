"""
test_payload_features.py — Unit tests for the Payload Characteristics Feature Engineering Module.
"""

from __future__ import annotations

import pytest

from pcap_ai_parser.features import (
    PayloadCharacteristics,
    calculate_payload_size,
    calculate_printable_ascii_ratio,
    calculate_shannon_entropy,
    extract_features_dict,
    extract_payload_characteristics,
)
from pcap_ai_parser.models.packet import PacketRecord
from pcap_ai_parser.parser.dpkt_parser import DpktParser


class TestPayloadSizeCalculation:
    """Test payload size calculation task."""

    def test_payload_size_empty(self):
        assert calculate_payload_size(b"") == 0
        assert calculate_payload_size(None) == 0

    def test_payload_size_various(self):
        assert calculate_payload_size(b"A") == 1
        assert calculate_payload_size(b"Hello World") == 11
        assert calculate_payload_size(bytes(1024)) == 1024

    def test_payload_size_bytearray(self):
        assert calculate_payload_size(bytearray(b"test1234")) == 8


class TestShannonEntropyCalculation:
    """Test Shannon entropy calculation for payloads."""

    def test_entropy_empty(self):
        assert calculate_shannon_entropy(b"") == 0.0
        assert calculate_shannon_entropy(None) == 0.0

    def test_entropy_zero_randomness(self):
        # When all bytes are identical, entropy should be 0.0
        assert calculate_shannon_entropy(b"A" * 100) == 0.0
        assert calculate_shannon_entropy(b"\x00" * 64) == 0.0

    def test_entropy_maximum(self):
        # 256 unique bytes equally distributed has theoretical entropy of 8.0 bits/byte
        all_bytes = bytes(range(256))
        entropy = calculate_shannon_entropy(all_bytes)
        assert entropy == 8.0

    def test_entropy_natural_text(self):
        # Plain text typically ranges between 3.0 and 5.0
        text = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        entropy = calculate_shannon_entropy(text)
        assert 3.0 < entropy < 5.0

    def test_entropy_high_randomness(self):
        # Pseudorandom/encrypted-like bytes should have elevated entropy (> 7.0)
        import random
        random.seed(42)
        rand_bytes = bytes(random.randint(0, 255) for _ in range(1000))
        assert calculate_shannon_entropy(rand_bytes) > 7.0


class TestPrintableAsciiRatioCalculation:
    """Test printable ASCII ratio calculation."""

    def test_ascii_ratio_empty(self):
        assert calculate_printable_ascii_ratio(b"") == 0.0
        assert calculate_printable_ascii_ratio(None) == 0.0

    def test_ascii_ratio_all_printable(self):
        # ASCII printable characters (32-126) + \r (13), \n (10), \t (9)
        payload = b"POST /api/v1/auth HTTP/1.1\r\nHost: api.test.com\tContent: text\n"
        assert calculate_printable_ascii_ratio(payload) == 1.0

    def test_ascii_ratio_zero_printable(self):
        payload = b"\x00\x01\x02\x03\x04\x05\xfe\xff"
        assert calculate_printable_ascii_ratio(payload) == 0.0

    def test_ascii_ratio_mixed(self):
        # 4 printable, 4 non-printable -> 0.5 ratio
        payload = b"ABCD\x00\x01\x02\x03"
        assert calculate_printable_ascii_ratio(payload) == 0.5


class TestPayloadCharacteristicsExtractor:
    """Test extraction container and dict helpers."""

    def test_extract_payload_characteristics_empty(self):
        res = extract_payload_characteristics(b"")
        assert res.payload_size == 0
        assert res.shannon_entropy == 0.0
        assert res.printable_ascii_ratio == 0.0
        assert res.is_empty is True

    def test_extract_payload_characteristics_data(self):
        data = b"Hello, world!"
        res = extract_payload_characteristics(data)
        assert res.payload_size == len(data)
        assert res.shannon_entropy > 0.0
        assert res.printable_ascii_ratio == 1.0
        assert res.is_empty is False

        d = res.to_dict()
        assert d["payload_size"] == len(data)
        assert "shannon_entropy" in d
        assert "printable_ascii_ratio" in d
        assert d["is_empty"] is False

    def test_extract_features_dict_prefix(self):
        d = extract_features_dict(b"Test", prefix="feat_")
        assert "feat_payload_size" in d
        assert "feat_shannon_entropy" in d
        assert "feat_printable_ascii_ratio" in d
        assert "feat_is_empty" in d


class TestPipelineIntegration:
    """Test integration into PacketRecord and parsing pipeline."""

    def test_packet_record_contains_features(self):
        rec = PacketRecord(
            payload_size=128,
            payload_entropy=4.2341,
            printable_ascii_ratio=0.95,
        )
        d = rec.to_dict()
        assert d["payload_size"] == 128
        assert d["payload_entropy"] == 4.2341
        assert d["printable_ascii_ratio"] == 0.95

    def test_dpkt_parser_pipeline_extracts_features(self, sample_pcap_path):
        with DpktParser(sample_pcap_path) as parser:
            packets = list(parser.parse())

        assert len(packets) > 0
        # Packets with payload should have computed size, entropy, and ascii ratio
        payload_packets = [p for p in packets if p.payload_size > 0]
        assert len(payload_packets) > 0

        for pkt in payload_packets:
            assert pkt.payload_size == len(pkt.payload)
            assert pkt.payload_entropy >= 0.0
            assert 0.0 <= pkt.printable_ascii_ratio <= 1.0
