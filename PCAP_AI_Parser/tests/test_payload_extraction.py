"""
Unit tests for application layer payload extraction and protocol context decoders.
"""

import socket
import dpkt
from pcap_ai_parser.parser.payload_extractor import PayloadExtractor


def test_payload_extractor_http():
    extractor = PayloadExtractor()
    http_get_payload = b"GET /index.html HTTP/1.1\r\nHost: test.org\r\n\r\n"
    
    info = extractor.extract_payload(
        transport_proto="TCP",
        payload_bytes=http_get_payload,
        src_port=49152,
        dst_port=80,
    )

    assert info.protocol_name == "HTTP"
    assert info.is_http is True
    assert info.http_method == "GET"
    assert info.http_uri == "/index.html"
    assert info.http_headers.get("host") == "test.org"
    assert info.payload_len == len(http_get_payload)


def test_payload_extractor_dns():
    extractor = PayloadExtractor()
    dns_obj = dpkt.dns.DNS(
        id=0xabcd,
        qd=[dpkt.dns.DNS.Q(name="example.org", type=dpkt.dns.DNS_A)]
    )
    dns_payload = bytes(dns_obj)

    info = extractor.extract_payload(
        transport_proto="UDP",
        payload_bytes=dns_payload,
        src_port=53100,
        dst_port=53,
    )

    assert info.protocol_name == "DNS"
    assert info.is_dns is True
    assert info.dns_query_name == "example.org"
    assert info.dns_query_type == dpkt.dns.DNS_A


def test_payload_extractor_tls():
    extractor = PayloadExtractor()
    tls_payload = (
        b"\x16\x03\x01\x00\x20"  # Handshake, TLS 1.0, len=32
        + b"\x00" * 32
    )

    info = extractor.extract_payload(
        transport_proto="TCP",
        payload_bytes=tls_payload,
        src_port=49154,
        dst_port=443,
    )

    assert info.protocol_name == "TLS"
    assert info.is_tls is True
    assert info.tls_record_type == "Handshake"
    assert info.tls_version == "TLS 1.0"


def test_payload_extractor_raw_binary():
    extractor = PayloadExtractor()
    raw_payload = b"\x90\x90\xeb\x0e\x5e\x31\xc0\x88\x46\x07"

    info = extractor.extract_payload(
        transport_proto="TCP",
        payload_bytes=raw_payload,
        src_port=49155,
        dst_port=9999,
    )

    assert info.protocol_name == "TCP"
    assert info.is_http is False
    assert info.is_dns is False
    assert info.is_tls is False
    assert info.normalization.has_non_printable is True
    assert "\\x90\\x90\\xeb" in info.normalization.printable_text
