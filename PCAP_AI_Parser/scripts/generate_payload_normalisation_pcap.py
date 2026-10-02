"""
generate_payload_normalisation_pcap.py - Script to generate a synthetic PCAP file containing diverse application payload types
(HTTP, DNS, TLS Client Hello, Raw binary shellcode, zero-payload SYN-ACK, ICMP) for payload extraction and normalization testing.
"""

import os
import socket
import time
import dpkt


def create_sample_pcap(output_path: str):
    """Generates a PCAP file at output_path containing synthetic network packets."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    start_ts = time.time() - 3600  # 1 hour ago

    with open(output_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)

        # 1. HTTP GET Request Packet
        http_get_payload = b"GET /api/v1/status?id=1024 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
        pkt1 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("93.184.216.34"),
                p=dpkt.ip.IP_PROTO_TCP,
                data=dpkt.tcp.TCP(
                    sport=49152,
                    dport=80,
                    flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    data=http_get_payload
                )
            )
        )
        writer.writepkt(pkt1, ts=start_ts + 0.1)

        # 2. HTTP POST Request with Body
        http_post_payload = b"POST /login HTTP/1.1\r\nHost: auth.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=P@ssw0rd!"
        pkt2 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("93.184.216.34"),
                p=dpkt.ip.IP_PROTO_TCP,
                data=dpkt.tcp.TCP(
                    sport=49153,
                    dport=80,
                    flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    data=http_post_payload
                )
            )
        )
        writer.writepkt(pkt2, ts=start_ts + 0.5)

        # 3. DNS Query Packet
        dns_obj = dpkt.dns.DNS(
            id=0x1234,
            qd=[dpkt.dns.DNS.Q(name="api.malicious-domain.com", type=dpkt.dns.DNS_A)]
        )
        pkt3 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("8.8.8.8"),
                p=dpkt.ip.IP_PROTO_UDP,
                data=dpkt.udp.UDP(
                    sport=53531,
                    dport=53,
                    data=bytes(dns_obj)
                )
            )
        )
        writer.writepkt(pkt3, ts=start_ts + 1.2)

        # 4. Synthetic TLS Client Hello Packet with SNI
        tls_payload = (
            b"\x16\x03\x01\x00\x32"  # Record Header
            b"\x01\x00\x00\x2e"      # Handshake: Client Hello, length=46
            b"\x03\x03"              # Client Version TLS 1.2
            + b"\x01" * 32           # Random 32 bytes
            + b"\x00"                # Session ID len=0
            + b"\x00\x02\x00\x2f"    # Cipher Suite TLS_RSA_WITH_AES_128_CBC_SHA
            + b"\x01\x00"            # Compression Method 0
            + b"\x00\x00"            # Extensions length=0
        )
        pkt4 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("104.16.123.96"),
                p=dpkt.ip.IP_PROTO_TCP,
                data=dpkt.tcp.TCP(
                    sport=49154,
                    dport=443,
                    flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    data=tls_payload
                )
            )
        )
        writer.writepkt(pkt4, ts=start_ts + 2.0)

        # 5. Raw Binary Payload (High Entropy / Shellcode Signature)
        binary_payload = bytes([
            0x90, 0x90, 0x90, 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68,
            0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1,
            0xb0, 0x0b, 0xcd, 0x80, 0xfe, 0xff, 0x00, 0xaa, 0xbb, 0xcc, 0xdd
        ])
        pkt5 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("198.51.100.44"),
                p=dpkt.ip.IP_PROTO_TCP,
                data=dpkt.tcp.TCP(
                    sport=49155,
                    dport=4444,
                    flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    data=binary_payload
                )
            )
        )
        writer.writepkt(pkt5, ts=start_ts + 2.8)

        # 6. Zero Payload SYN Packet
        pkt6 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("192.168.1.1"),
                p=dpkt.ip.IP_PROTO_TCP,
                data=dpkt.tcp.TCP(
                    sport=49156,
                    dport=80,
                    flags=dpkt.tcp.TH_SYN,
                    data=b""
                )
            )
        )
        writer.writepkt(pkt6, ts=start_ts + 3.1)

        # 7. ICMP Echo Request Packet
        icmp_payload = b"abcdefghijklmnopqrstuvwabcdefghi"
        pkt7 = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=dpkt.ip.IP(
                src=socket.inet_aton("192.168.1.105"),
                dst=socket.inet_aton("8.8.8.8"),
                p=dpkt.ip.IP_PROTO_ICMP,
                data=dpkt.icmp.ICMP(
                    type=8,  # Echo Request
                    code=0,
                    data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=icmp_payload)
                )
            )
        )
        writer.writepkt(pkt7, ts=start_ts + 4.0)

    print(f"Sample PCAP successfully created at: {output_path}")


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "..", "data", "samples", "sample.pcap")
    out = os.path.abspath(out)
    create_sample_pcap(out)
