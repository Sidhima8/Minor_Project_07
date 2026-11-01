"""
test_analyzer.py — unit tests for ByteNormalizer and PayloadDecoder.
"""

from __future__ import annotations

import pytest

from pcap_ai_parser.analyzer.byte_normalizer import (
    ByteNormalization,
    extract_printable_strings,
    normalize_payload,
    to_ascii_text,
    to_binary_stream,
    to_decimal_stream,
    to_hex_dump,
    to_hex_stream,
)
from pcap_ai_parser.analyzer.decoder import DecodedArtifact, PayloadDecoder


# ── Tests: Byte Normalizer ───────────────────────────────────────────────────

class TestByteNormalizer:

    def test_to_hex_dump_empty(self):
        assert to_hex_dump(b"") == ""

    def test_to_hex_dump_format(self):
        payload = b"GET / HTTP/1.1\r\n"
        dump = to_hex_dump(payload)
        lines = dump.splitlines()
        assert len(lines) == 1
        assert lines[0].startswith("00000000")
        assert "|GET / HTTP/1.1..|" in lines[0]

    def test_to_hex_dump_multiline(self):
        payload = b"A" * 35  # > 2 lines (16 + 16 + 3)
        dump = to_hex_dump(payload)
        lines = dump.splitlines()
        assert len(lines) == 3
        assert lines[0].startswith("00000000")
        assert lines[1].startswith("00000010")
        assert lines[2].startswith("00000020")

    def test_to_hex_stream(self):
        assert to_hex_stream(b"ABC") == "41 42 43"
        assert to_hex_stream(b"ABC", delimiter=":") == "41:42:43"

    def test_to_decimal_stream(self):
        assert to_decimal_stream(b"ABC") == "65 66 67"
        assert to_decimal_stream(b"\x00\xff") == "0 255"

    def test_to_binary_stream(self):
        assert to_binary_stream(b"\x01\x02") == "00000001 00000010"

    def test_to_ascii_text_replaces_non_printable(self):
        raw = b"Hello\x00\x01World\x7f!"
        assert to_ascii_text(raw, placeholder=".") == "Hello..World.!"

    def test_extract_printable_strings(self):
        data = b"\x00\x01\x02Password123\x00\xff\xfeRootUser\x00"
        strings = extract_printable_strings(data, min_length=4)
        assert "Password123" in strings
        assert "RootUser" in strings

    def test_normalize_payload_full_container(self):
        raw = b"User-Agent: Mozilla/5.0\r\n"
        norm = normalize_payload(raw)
        assert isinstance(norm, ByteNormalization)
        assert norm.total_bytes == len(raw)
        assert "User-Agent" in norm.ascii_text
        assert "User-Agent: Mozilla/5.0" in norm.extracted_strings
        d = norm.to_dict()
        assert d["total_bytes"] == len(raw)


# ── Tests: Payload Decoder ───────────────────────────────────────────────────

class TestPayloadDecoder:

    @pytest.fixture
    def decoder(self) -> PayloadDecoder:
        return PayloadDecoder()

    def test_decode_base64_plain(self, decoder: PayloadDecoder):
        encoded = "SGVsbG8gV29ybGQh"  # "Hello World!"
        artifacts = decoder.decode_base64(encoded)
        assert len(artifacts) >= 1
        assert any(a.decoded_text == "Hello World!" for a in artifacts)
        assert artifacts[0].encoding == "base64"

    def test_decode_base64_embedded(self, decoder: PayloadDecoder):
        payload = "token=eyJhbGciOiJIUzI1NiJ9&user=admin"  # eyJhbGciOiJIUzI1NiJ9 is {"alg":"HS256"}
        artifacts = decoder.decode_base64(payload)
        assert any('{"alg":"HS256"}' in a.decoded_text for a in artifacts)

    def test_decode_url(self, decoder: PayloadDecoder):
        url_payload = "name=admin%40corp.internal&cmd=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        artifacts = decoder.decode_url(url_payload)
        texts = [a.decoded_text for a in artifacts]
        assert any("admin@corp.internal" in t for t in texts)
        assert any("<script>alert(1)</script>" in t for t in texts)

    def test_decode_hex_escaped(self, decoder: PayloadDecoder):
        hex_data = r"payload=\x41\x42\x43\x44\x45\x46"  # "ABCDEF"
        artifacts = decoder.decode_hex(hex_data)
        assert any(a.decoded_text == "ABCDEF" for a in artifacts)

    def test_decode_all_recursive(self, decoder: PayloadDecoder):
        # Base64 string for "admin_secret_key" is "YWRtaW5fc2VjcmV0X2tleQ=="
        # URL encoded version is "%59%57%52%74%61%57%35%66%63%32%56%6a%63%6d%56%30%58%32%74%6c%65%51%3d%3d"
        nested = "query=%59%57%52%74%61%57%35%66%63%32%56%6a%63%6d%56%30%58%32%74%6c%65%51%3d%3d"
        artifacts = decoder.decode_all(nested)
        decoded_texts = [a.decoded_text for a in artifacts]
        assert "admin_secret_key" in decoded_texts
