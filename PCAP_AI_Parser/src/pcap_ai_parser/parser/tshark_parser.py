"""
tshark_parser.py — deep-inspection PCAP parser via tshark subprocess.

Why tshark?
-----------
- Wireshark's full protocol dissector library handles 3 000+ protocols.
- Output as newline-delimited JSON (``-T ek``) for reliable streaming.
- Complements dpkt for protocols beyond raw L2–L4 headers
  (e.g. HTTP/2, TLS handshake details, DNS names, QUIC).

Prerequisites
-------------
  tshark must be installed and on PATH:
    Arch:    sudo pacman -S wireshark-cli
    Debian:  sudo apt install tshark
    macOS:   brew install wireshark

Usage
-----
    from pcap_ai_parser.parser.tshark_parser import TsharkParser

    with TsharkParser("capture.pcap") as parser:
        for record in parser.parse():
            print(record)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Generator

from loguru import logger

from pcap_ai_parser.models.packet import PacketRecord, decode_tcp_flags


def _safe_str(val, default="") -> str:
    """Unwrap tshark array-wrapped values to a plain string."""
    if isinstance(val, list):
        return val[0] if val else default
    return str(val) if val is not None else default


def _safe_int(val, default=0) -> int:
    """Parse a plain decimal or hex (0x…) string to int."""
    s = _safe_str(val)
    if not s:
        return default
    try:
        # handles "0x0800", "64", "54321" etc.
        return int(s, 0)
    except (TypeError, ValueError):
        return default


def _safe_hex(val, default=0) -> int:
    """Parse a hex string like '0x0800' or '0x0002' to int."""
    return _safe_int(val, default)


class TsharkParser:
    """
    Streaming PCAP parser that delegates dissection to tshark.

    Launches tshark as a subprocess with ``-T ek`` (Elasticsearch/NDJSON)
    output and parses the resulting JSON stream, yielding PacketRecord
    instances for each packet.

    Parameters
    ----------
    path : str | Path
        Path to the capture file.
    tshark_bin : str
        Name / path of the tshark executable (default: ``"tshark"``).
    extra_fields : list[str], optional
        Additional ``-e`` field specifiers to request from tshark.
    """

    # Default tshark fields to request
    _DEFAULT_FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "eth.src",
        "eth.dst",
        "eth.type",
        "ip.src",
        "ip.dst",
        "ip.ttl",
        "ip.flags",
        "ip.version",
        "ipv6.src",
        "ipv6.dst",
        "ipv6.hlim",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "tcp.seq",
        "tcp.ack",
        "tcp.window_size",
        "udp.srcport",
        "udp.dstport",
        "udp.length",
        "icmp.type",
        "icmp.code",
        "icmpv6.type",
        "icmpv6.code",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "_ws.col.Protocol",
        "_ws.col.Info",
    ]

    _WINDOWS_TSHARK_PATHS = [
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]

    def __init__(
        self,
        path: str | Path,
        tshark_bin: str = "tshark",
        extra_fields: list[str] | None = None,
    ) -> None:
        self.path = Path(path)
        resolved = self.resolve_binary(tshark_bin)
        self.tshark_bin = resolved or tshark_bin
        self._fields = self._DEFAULT_FIELDS + (extra_fields or [])
        self._proc: subprocess.Popen | None = None

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "TsharkParser":
        return self

    def __exit__(self, *_) -> None:
        self._terminate()

    # ── Validation ────────────────────────────────────────────────────────

    @classmethod
    def resolve_binary(cls, tshark_bin: str = "tshark") -> str | None:
        """Return resolved path to tshark if found, else None."""
        if shutil.which(tshark_bin):
            return tshark_bin
        p = Path(tshark_bin)
        if p.exists() and p.is_file():
            return str(p)
        for win_path in cls._WINDOWS_TSHARK_PATHS:
            if win_path.exists():
                return str(win_path)
        return None

    @classmethod
    def check_available(cls, tshark_bin: str = "tshark") -> bool:
        """Return True if tshark is installed and executable."""
        return cls.resolve_binary(tshark_bin) is not None

    # ── Launch & stream ───────────────────────────────────────────────────

    def _build_cmd(self) -> list[str]:
        field_args: list[str] = []
        for f in self._fields:
            field_args += ["-e", f]

        return [
            self.tshark_bin,
            "-r", str(self.path),
            "-T", "ek",          # Elasticsearch/NDJSON output (machine-readable JSON)
            "-n",                 # Disable network name resolution (faster)
            *field_args,
        ]

    def parse(self) -> Generator[PacketRecord, None, None]:
        """
        Stream packets from tshark stdout as PacketRecord instances.

        Raises
        ------
        FileNotFoundError
            If the capture file does not exist.
        RuntimeError
            If tshark is not installed or fails to launch.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.path}")

        if not self.check_available(self.tshark_bin):
            raise RuntimeError(
                "tshark not found. Install with: sudo pacman -S wireshark-cli"
            )

        cmd = self._build_cmd()
        logger.debug("Launching tshark: {}", " ".join(cmd))

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue

            # tshark -T ek emits two kinds of lines:
            # 1. {"index": {...}}   — metadata line (skip)
            # 2. {"timestamp": ..., "layers": {...}}  — data line (parse)
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.trace("Skipping non-JSON line: {!r}", line[:80])
                continue

            if "layers" not in obj:
                continue  # metadata / index line

            try:
                record = self._decode_layer(obj)
                yield record
            except Exception as exc:
                logger.trace("Decode error: {}", exc)

        self._proc.wait()
        if self._proc.returncode not in (0, None):
            stderr = self._proc.stderr.read()
            logger.warning("tshark exited with code {}: {}", self._proc.returncode, stderr[:200])

    def _terminate(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._proc = None

    # ── Packet decoder ────────────────────────────────────────────────────

    def _decode_layer(self, obj: dict) -> PacketRecord:
        layers = obj.get("layers", {})

        rec = PacketRecord(parse_backend="tshark")

        # ── Frame ─────────────────────────────────────────────────────────
        rec.packet_number = _safe_int(layers.get("frame_number"))
        # frame_time_epoch arrives as a list-wrapped string e.g. ["1790406310.198851000"]
        rec.timestamp = float(_safe_str(layers.get("frame_time_epoch")) or 0)
        rec.wire_length = _safe_int(layers.get("frame_len"))
        rec.captured_length = _safe_int(layers.get("frame_cap_len"))

        # ── Ethernet ──────────────────────────────────────────────────────
        rec.link_type = "Ethernet"
        rec.src_mac = _safe_str(layers.get("eth_src"))
        rec.dst_mac = _safe_str(layers.get("eth_dst"))
        # eth_type arrives as hex string "0x0800" — use _safe_hex (int(s, 0))
        rec.ethertype = _safe_hex(layers.get("eth_type"))

        # ── IPv4 ──────────────────────────────────────────────────────────
        if layers.get("ip_src"):
            rec.network_proto = "IPv4"
            rec.ip_version = 4
            rec.src_ip = _safe_str(layers.get("ip_src"))
            rec.dst_ip = _safe_str(layers.get("ip_dst"))
            rec.ttl = _safe_int(layers.get("ip_ttl"))
            rec.ip_flags = _safe_hex(layers.get("ip_flags"))

        # ── IPv6 ──────────────────────────────────────────────────────────
        elif layers.get("ipv6_src"):
            rec.network_proto = "IPv6"
            rec.ip_version = 6
            rec.src_ip = _safe_str(layers.get("ipv6_src"))
            rec.dst_ip = _safe_str(layers.get("ipv6_dst"))
            rec.ttl = _safe_int(layers.get("ipv6_hlim"))

        # ── ARP ───────────────────────────────────────────────────────────
        elif layers.get("arp_src_proto_ipv4"):
            rec.network_proto = "ARP"
            rec.src_ip = _safe_str(layers.get("arp_src_proto_ipv4"))
            rec.dst_ip = _safe_str(layers.get("arp_dst_proto_ipv4"))

        # ── TCP ───────────────────────────────────────────────────────────
        if layers.get("tcp_srcport"):
            rec.transport_proto = "TCP"
            rec.src_port = _safe_int(layers.get("tcp_srcport"))
            rec.dst_port = _safe_int(layers.get("tcp_dstport"))
            # tcp_flags arrives as hex string "0x0002"
            raw_flags = _safe_hex(layers.get("tcp_flags"))
            rec.tcp_flags = decode_tcp_flags(raw_flags)
            rec.tcp_seq = _safe_int(layers.get("tcp_seq"))
            rec.tcp_ack = _safe_int(layers.get("tcp_ack"))
            rec.tcp_window = _safe_int(layers.get("tcp_window_size"))

        # ── UDP ───────────────────────────────────────────────────────────
        elif layers.get("udp_srcport"):
            rec.transport_proto = "UDP"
            rec.src_port = _safe_int(layers.get("udp_srcport"))
            rec.dst_port = _safe_int(layers.get("udp_dstport"))
            rec.udp_length = _safe_int(layers.get("udp_length"))

        # ── ICMP ──────────────────────────────────────────────────────────
        elif layers.get("icmp_type"):
            rec.transport_proto = "ICMP"
            rec.icmp_type = _safe_int(layers.get("icmp_type"))
            rec.icmp_code = _safe_int(layers.get("icmp_code"))

        # ── ICMPv6 ────────────────────────────────────────────────────────
        elif layers.get("icmpv6_type"):
            rec.transport_proto = "ICMPv6"
            rec.icmp_type = _safe_int(layers.get("icmpv6_type"))
            rec.icmp_code = _safe_int(layers.get("icmpv6_code"))

        # ── App proto — tshark 4.x lowercases all field keys ─────────────
        # _ws.col.Protocol → _ws_col_protocol  (note: fully lowercased)
        rec.app_proto = _safe_str(layers.get("_ws_col_protocol"))

        return rec

