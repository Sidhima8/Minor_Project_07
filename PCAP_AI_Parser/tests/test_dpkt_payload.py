"""
End-to-end unit tests for DpktPCAPParser payload extractions using generated sample PCAP.
"""

from pcap_ai_parser.parser.dpkt_parser import DpktPCAPParser, ParsedPacket


def test_dpkt_parser_sample_pcap(sample_pcap_path):
    parser = DpktPCAPParser(hex_escape_non_printable=True)
    packets = parser.parse_file(sample_pcap_path)

    # 7 packets generated in synthetic sample pcap
    assert len(packets) == 7

    # Validate Packet 1 (HTTP GET)
    pkt1 = packets[0]
    assert pkt1.protocol == "TCP"
    assert pkt1.dst_port == 80
    assert pkt1.payload_info.is_http is True
    assert pkt1.payload_info.http_method == "GET"
    assert "example.com" in pkt1.payload_info.normalization.printable_text

    # Validate Packet 2 (HTTP POST)
    pkt2 = packets[1]
    assert pkt2.payload_info.is_http is True
    assert pkt2.payload_info.http_method == "POST"
    assert "username=admin" in pkt2.payload_info.normalization.printable_text

    # Validate Packet 3 (DNS Query)
    pkt3 = packets[2]
    assert pkt3.protocol == "UDP"
    assert pkt3.dst_port == 53
    assert pkt3.payload_info.is_dns is True
    assert pkt3.payload_info.dns_query_name == "api.malicious-domain.com"

    # Validate Packet 4 (TLS Client Hello)
    pkt4 = packets[3]
    assert pkt4.dst_port == 443
    assert pkt4.payload_info.is_tls is True
    assert pkt4.payload_info.tls_record_type == "Handshake"

    # Validate Packet 5 (Raw Shellcode Binary)
    pkt5 = packets[4]
    assert pkt5.dst_port == 4444
    assert pkt5.payload_info.normalization.has_non_printable is True
    assert pkt5.payload_info.normalization.metrics["shannon_entropy"] > 3.0

    # Validate Packet 6 (SYN packet with empty payload)
    pkt6 = packets[5]
    assert pkt6.payload_info.payload_len == 0
    assert pkt6.payload_info.normalization.metrics["is_empty"] is True

    # Validate Packet 7 (ICMP Ping Echo)
    pkt7 = packets[6]
    assert pkt7.protocol == "ICMP"
    assert "abcdefghijklmnopqrstuvw" in pkt7.payload_info.normalization.printable_text
