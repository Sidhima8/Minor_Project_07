"""
Payload Normalization & Triage Command Line Interface (CLI) for PacketParser-AI.
"""

import argparse
import json
import sys
from typing import List
from pcap_ai_parser.parser.dpkt_parser import DpktPCAPParser, ParsedPacket


def main():
    parser = argparse.ArgumentParser(
        description="PacketParser-AI: Preprocessing and Payload Normalization Triage for Network Forensics"
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the input PCAP / PCAPNG file to parse."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output parsed packet summary in JSON format."
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=20,
        help="Maximum number of packets to print in text preview (default: 20)."
    )
    parser.add_argument(
        "--no-hex-escape",
        action="store_true",
        help="Replace non-printable characters with dot '.' instead of hex escape '\\xHH'."
    )
    args = parser.parse_args()

    dpkt_parser = DpktPCAPParser(hex_escape_non_printable=not args.no_hex_escape)

    try:
        packets: List[ParsedPacket] = dpkt_parser.parse_file(args.pcap_file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing PCAP file {args.pcap_file}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        json_output = [pkt.to_dict() for pkt in packets]
        print(json.dumps(json_output, indent=2))
        return

    print("=" * 80)
    print(f" PacketParser-AI Triage Report for: {args.pcap_file}")
    print(f" Total Packets Parsed: {len(packets)}")
    print("=" * 80)

    preview_packets = packets[: args.max_packets]
    for pkt in preview_packets:
        payload_info = pkt.payload_info
        norm = payload_info.normalization if payload_info else None

        print(f"\n[Packet #{pkt.packet_index}] Timestamp: {pkt.timestamp:.6f} | Len: {pkt.orig_len} bytes")
        print(f"  5-Tuple: {pkt.src_ip}:{pkt.src_port or 0} -> {pkt.dst_ip}:{pkt.dst_port or 0} ({pkt.protocol})")
        
        if payload_info:
            print(f"  Decoded Protocol: {payload_info.protocol_name}")
            if payload_info.is_http:
                print(f"  HTTP Info: Method={payload_info.http_method}, URI={payload_info.http_uri}")
            elif payload_info.is_dns:
                print(f"  DNS Query: Name={payload_info.dns_query_name}, Type={payload_info.dns_query_type}")
            elif payload_info.is_tls:
                print(f"  TLS Header: Record={payload_info.tls_record_type}, Version={payload_info.tls_version}, SNI={payload_info.tls_sni}")

            if norm:
                m = norm.metrics
                print(f"  Payload Size: {norm.payload_size} bytes | Entropy: {m['shannon_entropy']} | Printable Ratio: {m['printable_ascii_ratio']} | Unique Byte Ratio: {m['unique_byte_ratio']}")
                if norm.extracted_strings:
                    print(f"  Extracted Strings ({len(norm.extracted_strings)}): {norm.extracted_strings[:3]}")
                if norm.printable_text:
                    preview_text = norm.printable_text[:120] + ("..." if len(norm.printable_text) > 120 else "")
                    print(f"  Printable Preview: {preview_text}")

    if len(packets) > args.max_packets:
        print(f"\n... [{len(packets) - args.max_packets} more packets hidden. Use --max-packets to view all]")

    print("\n" + "=" * 80)
    print(" Payload Extraction & Text Normalization Complete.")
    print("=" * 80)


if __name__ == "__main__":
    main()
