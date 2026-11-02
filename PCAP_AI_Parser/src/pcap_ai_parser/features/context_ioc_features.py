"""
context_ioc_features.py — Feature Engineering Module for Context, IOCs, and Encoding Indicators.

Expected group tasks implemented:
1. Protocol context extraction (transport proto, app proto, category, well-known ports, directionality).
2. Total IOC count per packet and breakdown (URLs, domains, IPs, hashes, CVEs).
3. Encoding indicators (Base64 detection, URL encoding, Hex encoding).
4. Integration with existing payload characteristics for unified feature vectors.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from pcap_ai_parser.analyzer.decoder import PayloadDecoder
from pcap_ai_parser.features.payload_features import (
    PayloadCharacteristics,
    extract_payload_characteristics,
)
from pcap_ai_parser.features.tls_features import (
    extract_tls_features,
    is_tls_record,
)
from pcap_ai_parser.intelligence.ioc_extractor import IOCExtractor, IOCRecord

# ── Protocol Category Mapping ────────────────────────────────────────────────

_PORT_CATEGORIES: Dict[int, str] = {
    80: "WEB",
    443: "WEB",
    8080: "WEB",
    8443: "WEB",
    53: "DNS",
    25: "MAIL",
    110: "MAIL",
    143: "MAIL",
    465: "MAIL",
    587: "MAIL",
    993: "MAIL",
    995: "MAIL",
    22: "REMOTE_ACCESS",
    23: "REMOTE_ACCESS",
    3389: "REMOTE_ACCESS",
    5900: "REMOTE_ACCESS",
    1433: "DATABASE",
    3306: "DATABASE",
    5432: "DATABASE",
    6379: "DATABASE",
    27017: "DATABASE",
    9200: "DATABASE",
    20: "FILE_TRANSFER",
    21: "FILE_TRANSFER",
    445: "FILE_TRANSFER",
    67: "NETWORK_INFRA",
    68: "NETWORK_INFRA",
    123: "NETWORK_INFRA",
    161: "NETWORK_INFRA",
    162: "NETWORK_INFRA",
    514: "NETWORK_INFRA",
    1194: "ENCRYPTED",
}

_APP_CATEGORIES: Dict[str, str] = {
    "HTTP": "WEB",
    "HTTPS": "WEB",
    "HTTP-ALT": "WEB",
    "HTTPS-ALT": "WEB",
    "DNS": "DNS",
    "SSH": "REMOTE_ACCESS",
    "TELNET": "REMOTE_ACCESS",
    "RDP": "REMOTE_ACCESS",
    "VNC": "REMOTE_ACCESS",
    "FTP": "FILE_TRANSFER",
    "FTP-DATA": "FILE_TRANSFER",
    "SMB": "FILE_TRANSFER",
    "SMTP": "MAIL",
    "POP3": "MAIL",
    "IMAP": "MAIL",
    "SMTPS": "MAIL",
    "SMTP-SUBMISSION": "MAIL",
    "IMAPS": "MAIL",
    "POP3S": "MAIL",
    "MySQL": "DATABASE",
    "PostgreSQL": "DATABASE",
    "MSSQL": "DATABASE",
    "Redis": "DATABASE",
    "MongoDB": "DATABASE",
    "Elasticsearch": "DATABASE",
    "DHCP": "NETWORK_INFRA",
    "NTP": "NETWORK_INFRA",
    "SNMP": "NETWORK_INFRA",
    "SNMP-TRAP": "NETWORK_INFRA",
    "SYSLOG": "NETWORK_INFRA",
    "TLS": "ENCRYPTED",
    "OpenVPN": "ENCRYPTED",
}


# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class ProtocolContextFeatures:
    """Protocol and flow context features extracted from a packet."""

    transport_proto: str
    app_proto: str
    protocol_category: str
    is_well_known_port: bool
    is_client_to_server: bool
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IOCFeatures:
    """Indicators of Compromise (IOC) features per packet."""

    total_ioc_count: int
    has_iocs: bool
    url_ioc_count: int
    domain_ioc_count: int
    ip_ioc_count: int
    hash_ioc_count: int
    cve_ioc_count: int
    extracted_iocs: List[IOCRecord] = field(default_factory=list, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("extracted_iocs", None)
        return d


@dataclass
class EncodingFeatures:
    """Encoding indicator features extracted from payload."""

    has_encoding: bool
    has_base64: bool
    base64_count: int
    has_url_encoding: bool
    url_encoding_count: int
    has_hex_encoding: bool
    hex_encoding_count: int
    total_encoded_artifacts: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedPacketFeatures:
    """Complete feature engineering vector combining payload, context, IOCs, and encodings."""

    # Payload Characteristics
    payload_size: int
    shannon_entropy: float
    printable_ascii_ratio: float
    is_empty: bool

    # Protocol Context
    transport_proto: str
    app_proto: str
    protocol_category: str
    is_well_known_port: bool
    is_client_to_server: bool

    # IOC Features
    total_ioc_count: int
    has_iocs: bool
    url_ioc_count: int
    domain_ioc_count: int
    ip_ioc_count: int
    hash_ioc_count: int
    cve_ioc_count: int

    # Encoding Indicators
    has_encoding: bool
    has_base64: bool
    base64_count: int
    has_url_encoding: bool
    url_encoding_count: int
    has_hex_encoding: bool
    hex_encoding_count: int
    total_encoded_artifacts: int

    # TLS Record Handling & Routing Path
    is_tls_record: bool = False
    tls_record_type: str = ""
    tls_version: str = ""
    tls_sni: str = ""
    entropy_excluded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Feature Extraction Functions ─────────────────────────────────────────────

def extract_protocol_context(
    transport_proto: str,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    app_proto: str = "",
) -> ProtocolContextFeatures:
    """
    Extract protocol context and network flow direction features.

    Parameters
    ----------
    transport_proto : str
        L4 protocol name ('TCP', 'UDP', 'ICMP', etc.)
    src_port : Optional[int]
        Source port number
    dst_port : Optional[int]
        Destination port number
    app_proto : str
        Known or guessed application protocol ('HTTP', 'DNS', 'TLS', etc.)

    Returns
    -------
    ProtocolContextFeatures
        Dataclass with category, well-known port flag, and directionality.
    """
    proto = (transport_proto or "UNKNOWN").upper()
    app = (app_proto or "").upper()

    # Determine category
    category = "OTHER"
    if app and app in _APP_CATEGORIES:
        category = _APP_CATEGORIES[app]
    elif dst_port and dst_port in _PORT_CATEGORIES:
        category = _PORT_CATEGORIES[dst_port]
    elif src_port and src_port in _PORT_CATEGORIES:
        category = _PORT_CATEGORIES[src_port]
    elif proto in ("ICMP", "ICMPV6", "ARP"):
        category = "NETWORK_INFRA"

    # Well-known port check (< 1024)
    is_well_known = False
    if (src_port is not None and 0 < src_port < 1024) or (dst_port is not None and 0 < dst_port < 1024):
        is_well_known = True

    # Client to server heuristic (destination port is a service port < source port or < 1024)
    is_client_to_server = False
    if src_port and dst_port:
        if dst_port < src_port or dst_port < 1024 or dst_port in _PORT_CATEGORIES:
            is_client_to_server = True

    return ProtocolContextFeatures(
        transport_proto=proto,
        app_proto=app,
        protocol_category=category,
        is_well_known_port=is_well_known,
        is_client_to_server=is_client_to_server,
        src_port=src_port,
        dst_port=dst_port,
    )


def extract_ioc_features(
    payload: bytes | str | None,
    decoded_texts: Optional[List[str]] = None,
    extractor: Optional[IOCExtractor] = None,
) -> IOCFeatures:
    """
    Extract Indicators of Compromise (IOC) and calculate total counts per packet.

    Parameters
    ----------
    payload : bytes | str | None
        Raw application payload or text.
    decoded_texts : Optional[List[str]]
        Decoded payload text fragments (e.g. from Base64 or URL decoding).
    extractor : Optional[IOCExtractor]
        Re-usable IOCExtractor instance.

    Returns
    -------
    IOCFeatures
        Container with total IOC count, flag, and category breakdown.
    """
    if not payload and not decoded_texts:
        return IOCFeatures(
            total_ioc_count=0,
            has_iocs=False,
            url_ioc_count=0,
            domain_ioc_count=0,
            ip_ioc_count=0,
            hash_ioc_count=0,
            cve_ioc_count=0,
            extracted_iocs=[],
        )

    if extractor is None:
        extractor = IOCExtractor()

    raw_bytes = payload if isinstance(payload, (bytes, bytearray)) else (payload or "").encode("utf-8", "ignore")
    iocs = extractor.extract_from_payload(raw_bytes, decoded_texts=decoded_texts)

    url_count = sum(1 for ioc in iocs if ioc.ioc_type == "URL")
    domain_count = sum(1 for ioc in iocs if ioc.ioc_type == "DOMAIN")
    ip_count = sum(1 for ioc in iocs if ioc.ioc_type in ("IPV4", "IPV6"))
    hash_count = sum(1 for ioc in iocs if ioc.ioc_type in ("MD5", "SHA1", "SHA256"))
    cve_count = sum(1 for ioc in iocs if ioc.ioc_type == "CVE")

    total = len(iocs)

    return IOCFeatures(
        total_ioc_count=total,
        has_iocs=total > 0,
        url_ioc_count=url_count,
        domain_ioc_count=domain_count,
        ip_ioc_count=ip_count,
        hash_ioc_count=hash_count,
        cve_ioc_count=cve_count,
        extracted_iocs=iocs,
    )


def _is_probable_base64(token: str) -> bool:
    """Filter out plain English words mistakenly matched by loose Base64 regex."""
    if len(token) < 8:
        return False
    # If padded with '=' or contains standard base64 symbols
    if token.endswith("=") or "+" in token or "/" in token:
        return True
    # Real base64 payloads typically mix digits and letters, or mixed case over sufficient length
    has_digit = any(c.isdigit() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    if has_digit and (has_upper or has_lower):
        return True
    if len(token) >= 16 and has_upper and has_lower:
        return True
    return False


def extract_encoding_features(
    payload: bytes | str | None,
    decoder: Optional[PayloadDecoder] = None,
) -> EncodingFeatures:
    """
    Detect encoding indicators (Base64, URL percent-encoding, Hex sequences) in packet payload.

    Parameters
    ----------
    payload : bytes | str | None
        Raw application payload or text.
    decoder : Optional[PayloadDecoder]
        Re-usable PayloadDecoder instance.

    Returns
    -------
    EncodingFeatures
        Booleans and counts for Base64, URL, and Hex encoding indicators.
    """
    if not payload:
        return EncodingFeatures(
            has_encoding=False,
            has_base64=False,
            base64_count=0,
            has_url_encoding=False,
            url_encoding_count=0,
            has_hex_encoding=False,
            hex_encoding_count=0,
            total_encoded_artifacts=0,
        )

    if decoder is None:
        decoder = PayloadDecoder()

    artifacts = decoder.decode_all(payload)

    # Filter base64 candidates using probable base64 heuristic to avoid natural language words
    valid_b64_artifacts = [
        a for a in artifacts if a.encoding == "base64" and _is_probable_base64(a.original)
    ]
    b64_count = len(valid_b64_artifacts)

    url_count = sum(1 for a in artifacts if a.encoding == "url")
    hex_count = sum(1 for a in artifacts if a.encoding in ("hex_escaped", "hex_raw"))
    total_artifacts = b64_count + url_count + hex_count

    return EncodingFeatures(
        has_encoding=total_artifacts > 0,
        has_base64=b64_count > 0,
        base64_count=b64_count,
        has_url_encoding=url_count > 0,
        url_encoding_count=url_count,
        has_hex_encoding=hex_count > 0,
        hex_encoding_count=hex_count,
        total_encoded_artifacts=total_artifacts,
    )


def extract_unified_packet_features(
    payload: bytes | bytearray | memoryview | None,
    transport_proto: str = "UNKNOWN",
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    app_proto: str = "",
    decoder: Optional[PayloadDecoder] = None,
    ioc_extractor: Optional[IOCExtractor] = None,
) -> UnifiedPacketFeatures:
    """
    Extract full unified feature engineering vector for a single packet:
    Payload Characteristics + Protocol Context + IOC Counts + Encoding Indicators.

    Returns
    -------
    UnifiedPacketFeatures
        Flat structured container ready for machine learning feature matrices and Pandas DataFrames.
    """
    # 1. Payload Characteristics
    p_chars = extract_payload_characteristics(payload)

    # 2. Protocol Context
    p_ctx = extract_protocol_context(
        transport_proto=transport_proto,
        src_port=src_port,
        dst_port=dst_port,
        app_proto=app_proto,
    )

    # 3. Encoding Indicators
    if decoder is None:
        decoder = PayloadDecoder()
    enc_features = extract_encoding_features(payload, decoder=decoder)

    # 4. IOC Features (incorporating decoded texts if any encodings were found)
    decoded_texts = []
    if enc_features.has_encoding:
        artifacts = decoder.decode_all(payload)
        decoded_texts = [a.decoded_text for a in artifacts]

    ioc_features = extract_ioc_features(payload, decoded_texts=decoded_texts, extractor=ioc_extractor)

    # 5. TLS Record Routing & Entropy Bypass Path
    is_tls = is_tls_record(payload)
    tls_record_type = ""
    tls_version = ""
    tls_sni = ""
    entropy_excluded = False

    if is_tls:
        # Route to specialized TLS feature path
        tls_feat = extract_tls_features(payload)
        tls_record_type = tls_feat.record_type
        tls_version = tls_feat.version
        tls_sni = tls_feat.sni or ""
        entropy_excluded = True
        # Entropy is bypassed/adjusted for TLS records (excluded as primary indicator)
        shannon_entropy = 0.0

        if p_ctx.protocol_category == "OTHER":
            p_ctx.protocol_category = "ENCRYPTED"
        if not p_ctx.app_proto or p_ctx.app_proto == "UNKNOWN":
            p_ctx.app_proto = "TLS"

        # If SNI domain was extracted, ensure domain and total IOC count reflect it
        if tls_sni and not any(ioc.value == tls_sni for ioc in ioc_features.extracted_iocs):
            ioc_features.total_ioc_count += 1
            ioc_features.domain_ioc_count += 1
            ioc_features.has_iocs = True
    else:
        shannon_entropy = p_chars.shannon_entropy

    return UnifiedPacketFeatures(
        # Payload
        payload_size=p_chars.payload_size,
        shannon_entropy=shannon_entropy,
        printable_ascii_ratio=p_chars.printable_ascii_ratio,
        is_empty=p_chars.is_empty,
        # Context
        transport_proto=p_ctx.transport_proto,
        app_proto=p_ctx.app_proto,
        protocol_category=p_ctx.protocol_category,
        is_well_known_port=p_ctx.is_well_known_port,
        is_client_to_server=p_ctx.is_client_to_server,
        # IOCs
        total_ioc_count=ioc_features.total_ioc_count,
        has_iocs=ioc_features.has_iocs,
        url_ioc_count=ioc_features.url_ioc_count,
        domain_ioc_count=ioc_features.domain_ioc_count,
        ip_ioc_count=ioc_features.ip_ioc_count,
        hash_ioc_count=ioc_features.hash_ioc_count,
        cve_ioc_count=ioc_features.cve_ioc_count,
        # Encodings
        has_encoding=enc_features.has_encoding,
        has_base64=enc_features.has_base64,
        base64_count=enc_features.base64_count,
        has_url_encoding=enc_features.has_url_encoding,
        url_encoding_count=enc_features.url_encoding_count,
        has_hex_encoding=enc_features.has_hex_encoding,
        hex_encoding_count=enc_features.hex_encoding_count,
        total_encoded_artifacts=enc_features.total_encoded_artifacts,
        # TLS Routing Path
        is_tls_record=is_tls,
        tls_record_type=tls_record_type,
        tls_version=tls_version,
        tls_sni=tls_sni,
        entropy_excluded=entropy_excluded,
    )
