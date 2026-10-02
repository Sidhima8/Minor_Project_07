"""
Payload extraction logic for L4/L7 protocols (HTTP, DNS, TLS, Generic TCP/UDP/ICMP).
"""

from dataclasses import dataclass, field
import socket
from typing import Optional, Dict, Any
import dpkt
from pcap_ai_parser.utils.normalizer import normalize_payload_to_printable, PayloadNormalizationResult


@dataclass
class ExtractedPayloadInfo:
    """Dataclass holding extracted payload details and protocol context metadata."""
    protocol_name: str
    raw_payload: bytes
    payload_len: int
    normalization: PayloadNormalizationResult
    is_http: bool = False
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    is_dns: bool = False
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[int] = None
    is_tls: bool = False
    tls_record_type: Optional[str] = None
    tls_version: Optional[str] = None
    tls_sni: Optional[str] = None
    protocol_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts extraction info to serializable dictionary."""
        return {
            "protocol_name": self.protocol_name,
            "payload_len": self.payload_len,
            "is_http": self.is_http,
            "http_method": self.http_method,
            "http_uri": self.http_uri,
            "http_headers": self.http_headers,
            "is_dns": self.is_dns,
            "dns_query_name": self.dns_query_name,
            "dns_query_type": self.dns_query_type,
            "is_tls": self.is_tls,
            "tls_record_type": self.tls_record_type,
            "tls_version": self.tls_version,
            "tls_sni": self.tls_sni,
            "normalization": self.normalization.to_dict(),
        }


class PayloadExtractor:
    """
    Parser module for inspecting packet payloads, classifying protocol contexts,
    and delegating to text normalization and metrics utilities.
    """

    TLS_RECORD_TYPES = {
        0x14: "ChangeCipherSpec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "ApplicationData",
        0x18: "Heartbeat",
    }

    TLS_VERSIONS = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    def __init__(self, hex_escape_non_printable: bool = True):
        self.hex_escape_non_printable = hex_escape_non_printable

    def extract_payload(
        self,
        transport_proto: str,
        payload_bytes: bytes,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
    ) -> ExtractedPayloadInfo:
        """
        Extracts and decodes application payload bytes from transport packet.
        
        Args:
            transport_proto: Transport protocol string ('TCP', 'UDP', 'ICMP', 'RAW').
            payload_bytes: Raw payload byte array.
            src_port: Source port number (optional).
            dst_port: Destination port number (optional).
            
        Returns:
            ExtractedPayloadInfo dataclass instance.
        """
        if not payload_bytes:
            norm = normalize_payload_to_printable(b"", self.hex_escape_non_printable)
            return ExtractedPayloadInfo(
                protocol_name=transport_proto,
                raw_payload=b"",
                payload_len=0,
                normalization=norm,
            )

        # Default protocol context setup
        protocol_name = transport_proto
        is_http = False
        http_method = None
        http_uri = None
        http_headers: Dict[str, str] = {}
        
        is_dns = False
        dns_query_name = None
        dns_query_type = None
        
        is_tls = False
        tls_record_type = None
        tls_version = None
        tls_sni = None

        # 1. Attempt TLS record parsing for TCP traffic
        if transport_proto == "TCP":
            tls_info = self._parse_tls_header(payload_bytes)
            if tls_info["is_tls"]:
                is_tls = True
                protocol_name = "TLS"
                tls_record_type = tls_info["record_type"]
                tls_version = tls_info["version"]
                tls_sni = tls_info["sni"]

        # 2. Attempt HTTP parsing for TCP non-TLS traffic
        if transport_proto == "TCP" and not is_tls:
            http_info = self._parse_http(payload_bytes)
            if http_info["is_http"]:
                is_http = True
                protocol_name = "HTTP"
                http_method = http_info["method"]
                http_uri = http_info["uri"]
                http_headers = http_info["headers"]

        # 3. Attempt DNS parsing for UDP (or TCP port 53)
        if (transport_proto == "UDP" or (transport_proto == "TCP" and (src_port == 53 or dst_port == 53))):
            dns_info = self._parse_dns(payload_bytes)
            if dns_info["is_dns"]:
                is_dns = True
                protocol_name = "DNS"
                dns_query_name = dns_info["query_name"]
                dns_query_type = dns_info["query_type"]

        # 4. Perform payload normalization and feature computation
        norm = normalize_payload_to_printable(payload_bytes, self.hex_escape_non_printable)

        return ExtractedPayloadInfo(
            protocol_name=protocol_name,
            raw_payload=payload_bytes,
            payload_len=len(payload_bytes),
            normalization=norm,
            is_http=is_http,
            http_method=http_method,
            http_uri=http_uri,
            http_headers=http_headers,
            is_dns=is_dns,
            dns_query_name=dns_query_name,
            dns_query_type=dns_query_type,
            is_tls=is_tls,
            tls_record_type=tls_record_type,
            tls_version=tls_version,
            tls_sni=tls_sni,
            protocol_context={
                "src_port": src_port,
                "dst_port": dst_port,
            },
        )

    def _parse_http(self, data: bytes) -> Dict[str, Any]:
        """Attempts HTTP Request / Response parsing using dpkt."""
        res: Dict[str, Any] = {"is_http": False, "method": None, "uri": None, "headers": {}}
        if not data:
            return res

        # Try HTTP Request
        try:
            req = dpkt.http.Request(data)
            res["is_http"] = True
            res["method"] = req.method
            res["uri"] = req.uri
            res["headers"] = {k.lower(): v for k, v in req.headers.items()}
            return res
        except (dpkt.dpkt.Error, dpkt.NeedData, Exception):
            pass

        # Try HTTP Response
        try:
            resp = dpkt.http.Response(data)
            res["is_http"] = True
            res["method"] = f"HTTP/{resp.version} {resp.status}"
            res["uri"] = resp.reason
            res["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            return res
        except (dpkt.dpkt.Error, dpkt.NeedData, Exception):
            pass

        # Fallback heuristic check for plain text HTTP headers
        lines = data.split(b"\r\n")
        if len(lines) > 0 and lines[0]:
            parts = lines[0].split(b" ")
            if len(parts) >= 2 and parts[0].decode("ascii", "ignore") in (
                "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH"
            ):
                res["is_http"] = True
                res["method"] = parts[0].decode("ascii", "ignore")
                res["uri"] = parts[1].decode("ascii", "ignore") if len(parts) > 1 else "/"
                return res

        return res

    def _parse_dns(self, data: bytes) -> Dict[str, Any]:
        """Attempts DNS Packet parsing using dpkt."""
        res: Dict[str, Any] = {"is_dns": False, "query_name": None, "query_type": None}
        if len(data) < 12:
            return res

        try:
            dns = dpkt.dns.DNS(data)
            res["is_dns"] = True
            if dns.qd:
                res["query_name"] = dns.qd[0].name
                res["query_type"] = dns.qd[0].type
            return res
        except Exception:
            return res

    def _parse_tls_header(self, data: bytes) -> Dict[str, Any]:
        """Identifies TLS Record headers (Content Type, Version, Record Length) and SNI domain."""
        res: Dict[str, Any] = {"is_tls": False, "record_type": None, "version": None, "sni": None}
        if len(data) < 5:
            return res

        content_type = data[0]
        if content_type not in self.TLS_RECORD_TYPES:
            return res

        version_val = (data[1] << 8) | data[2]
        if version_val not in self.TLS_VERSIONS:
            return res

        record_len = (data[3] << 8) | data[4]
        if record_len <= 0 or (record_len + 5 > len(data) and len(data) < 16):
            return res

        res["is_tls"] = True
        res["record_type"] = self.TLS_RECORD_TYPES[content_type]
        res["version"] = self.TLS_VERSIONS[version_val]

        # Extract SNI if Handshake Client Hello (0x16, Handshake type 0x01)
        if content_type == 0x16 and len(data) > 43:
            sni = self._extract_tls_sni(data[5:])
            if sni:
                res["sni"] = sni

        return res

    def _extract_tls_sni(self, handshake_data: bytes) -> Optional[str]:
        """Parses TLS Client Hello handshake data for SNI domain extension."""
        try:
            if not handshake_data or handshake_data[0] != 0x01:  # Client Hello
                return None
            
            # Skip Handshake type (1) + length (3) + version (2) + random (32)
            idx = 38
            if len(handshake_data) <= idx:
                return None

            # Skip Session ID
            session_id_len = handshake_data[idx]
            idx += 1 + session_id_len
            if len(handshake_data) <= idx + 2:
                return None

            # Skip Cipher Suites
            cipher_len = (handshake_data[idx] << 8) | handshake_data[idx + 1]
            idx += 2 + cipher_len
            if len(handshake_data) <= idx + 1:
                return None

            # Skip Compression Methods
            comp_len = handshake_data[idx]
            idx += 1 + comp_len
            if len(handshake_data) <= idx + 2:
                return None

            # Parse Extensions Length
            ext_total_len = (handshake_data[idx] << 8) | handshake_data[idx + 1]
            idx += 2
            ext_end = min(idx + ext_total_len, len(handshake_data))

            while idx + 4 <= ext_end:
                ext_type = (handshake_data[idx] << 8) | handshake_data[idx + 1]
                ext_len = (handshake_data[idx + 2] << 8) | handshake_data[idx + 3]
                idx += 4

                if ext_type == 0x0000:  # Server Name Indication extension
                    if idx + ext_len <= ext_end:
                        sni_data = handshake_data[idx : idx + ext_len]
                        if len(sni_data) > 5:
                            # Server Name List Length (2) + Server Name Type (1) + Name Length (2)
                            name_len = (sni_data[3] << 8) | sni_data[4]
                            if len(sni_data) >= 5 + name_len:
                                return sni_data[5 : 5 + name_len].decode("ascii", errors="ignore")
                idx += ext_len
        except Exception:
            pass

        return None
