"""
tls_features.py — TLS Record Detection, Routing, and Feature Extraction Path.

Expected group tasks implemented:
1. Develop logic to detect TLS records within payloads (header verification: Content-Type, Version, Length).
2. Implement a separate feature extraction path for TLS metadata (Record Type, Version, SNI, Handshake details).
3. Ensure entropy calculation is bypassed or adjusted for TLS records (excluding high entropy as a threat indicator).
4. Provide structured routing helpers for packet pipelines and machine learning feature extraction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ── TLS Protocol Definitions ──────────────────────────────────────────────────

TLS_RECORD_TYPES: Dict[int, str] = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}

TLS_HANDSHAKE_TYPES: Dict[int, str] = {
    0x00: "HelloRequest",
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x04: "NewSessionTicket",
    0x08: "EncryptedExtensions",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0D: "CertificateRequest",
    0x0E: "ServerHelloDone",
    0x0F: "CertificateVerify",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
}

TLS_VERSIONS: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


# ── TLS Feature Dataclass ────────────────────────────────────────────────────

@dataclass
class TLSFeatures:
    """Features extracted via the specialized TLS record path."""

    is_tls: bool
    record_type: str = ""                   # e.g., "Handshake", "ApplicationData", "Alert"
    record_type_code: int = 0               # e.g., 0x16, 0x17
    version: str = ""                       # e.g., "TLS 1.2", "TLS 1.3"
    version_code: int = 0                   # e.g., 0x0303
    record_length: int = 0                  # Length declared in TLS record header
    handshake_type: Optional[str] = None    # e.g., "ClientHello", "ServerHello"
    handshake_type_code: Optional[int] = None
    sni: Optional[str] = None               # Server Name Indication hostname
    has_sni: bool = False
    cipher_suites_count: int = 0
    entropy_bypassed: bool = True           # Indicates entropy calculation is bypassed/excluded
    raw_entropy: Optional[float] = None     # Raw entropy if explicitly requested, otherwise None

    def to_dict(self) -> Dict[str, Any]:
        """Convert TLS features to serializable dictionary."""
        return asdict(self)


# ── TLS Detection Logic ──────────────────────────────────────────────────────

def is_tls_record(data: bytes | bytearray | memoryview | None) -> bool:
    """
    Detect whether raw byte buffer begins with a valid TLS record.

    A valid TLS record header has at least 5 bytes:
    - Byte 0: ContentType in {0x14, 0x15, 0x16, 0x17, 0x18}
    - Bytes 1-2: ProtocolVersion in {0x0300, 0x0301, 0x0302, 0x0303, 0x0304}
    - Bytes 3-4: Record Length (1 <= Length <= 18432)

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application payload bytes.

    Returns
    -------
    bool
        True if the data matches valid TLS record structure, False otherwise.
    """
    if not data or len(data) < 5:
        return False

    content_type = data[0]
    if content_type not in TLS_RECORD_TYPES:
        return False

    version_val = (data[1] << 8) | data[2]
    if version_val not in TLS_VERSIONS:
        return False

    record_len = (data[3] << 8) | data[4]
    # Standard max TLS fragment is 2^14 (16384) + 2048 padding/compression
    if record_len <= 0 or record_len > 18432:
        return False

    return True


# ── TLS SNI & Handshake Parsers ──────────────────────────────────────────────

def _extract_sni_from_handshake(handshake_data: bytes) -> Optional[str]:
    """
    Parse TLS Client Hello handshake data for the Server Name Indication (SNI) extension.
    """
    try:
        if not handshake_data or handshake_data[0] != 0x01:  # Client Hello type
            return None

        # Skip: Handshake type (1) + length (3) + client version (2) + random (32) = 38 bytes
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

        # Parse Extensions
        ext_total_len = (handshake_data[idx] << 8) | handshake_data[idx + 1]
        idx += 2
        ext_end = min(idx + ext_total_len, len(handshake_data))

        while idx + 4 <= ext_end:
            ext_type = (handshake_data[idx] << 8) | handshake_data[idx + 1]
            ext_len = (handshake_data[idx + 2] << 8) | handshake_data[idx + 3]
            idx += 4

            if ext_type == 0x0000:  # Server Name Indication
                if idx + ext_len <= ext_end:
                    sni_data = handshake_data[idx : idx + ext_len]
                    if len(sni_data) > 5:
                        # Server Name List Length (2) + Name Type (1) + Name Length (2)
                        name_len = (sni_data[3] << 8) | sni_data[4]
                        if len(sni_data) >= 5 + name_len:
                            return sni_data[5 : 5 + name_len].decode("ascii", errors="ignore")
            idx += ext_len
    except Exception:
        pass

    return None


def _extract_cipher_suites_count(handshake_data: bytes) -> int:
    """Extract number of offered cipher suites from Client Hello."""
    try:
        if not handshake_data or handshake_data[0] != 0x01 or len(handshake_data) < 40:
            return 0
        idx = 38
        session_id_len = handshake_data[idx]
        idx += 1 + session_id_len
        if len(handshake_data) > idx + 2:
            cipher_len = (handshake_data[idx] << 8) | handshake_data[idx + 1]
            return cipher_len // 2
    except Exception:
        pass
    return 0


# ── Separate Feature Extraction Path for TLS ─────────────────────────────────

def extract_tls_features(
    data: bytes | bytearray | memoryview | None,
    calculate_raw_entropy: bool = False,
) -> TLSFeatures:
    """
    Dedicated feature extraction path for TLS records.

    Excludes entropy as a primary threat indicator:
    Because TLS records are encrypted and naturally exhibit maximum entropy (7.5-8.0 bits/byte),
    entropy calculation is bypassed or flagged as excluded to eliminate false-positive anomalies.

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application payload bytes.
    calculate_raw_entropy : bool, optional
        Whether to compute raw entropy in background for logging (default False, bypass calculation).

    Returns
    -------
    TLSFeatures
        Dataclass containing TLS metadata, SNI, and entropy bypass confirmation.
    """
    if not is_tls_record(data):
        return TLSFeatures(is_tls=False, entropy_bypassed=False)

    assert data is not None  # guaranteed by is_tls_record
    content_type = data[0]
    version_val = (data[1] << 8) | data[2]
    record_len = (data[3] << 8) | data[4]

    record_type = TLS_RECORD_TYPES.get(content_type, f"Unknown (0x{content_type:02X})")
    version = TLS_VERSIONS.get(version_val, f"Unknown (0x{version_val:04X})")

    handshake_type_name: Optional[str] = None
    handshake_type_code: Optional[int] = None
    sni: Optional[str] = None
    cipher_suites_count = 0

    # If Handshake Record (0x16), inspect handshake payload
    if content_type == 0x16 and len(data) >= 6:
        handshake_type_code = data[5]
        handshake_type_name = TLS_HANDSHAKE_TYPES.get(
            handshake_type_code, f"Unknown (0x{handshake_type_code:02X})"
        )

        if handshake_type_code == 0x01:  # ClientHello
            sni = _extract_sni_from_handshake(data[5:])
            cipher_suites_count = _extract_cipher_suites_count(data[5:])

    # Compute raw entropy only if explicitly requested, otherwise bypass
    raw_entropy_val = None
    if calculate_raw_entropy:
        from pcap_ai_parser.features.payload_features import calculate_shannon_entropy
        raw_entropy_val = calculate_shannon_entropy(data)

    return TLSFeatures(
        is_tls=True,
        record_type=record_type,
        record_type_code=content_type,
        version=version,
        version_code=version_val,
        record_length=record_len,
        handshake_type=handshake_type_name,
        handshake_type_code=handshake_type_code,
        sni=sni,
        has_sni=sni is not None,
        cipher_suites_count=cipher_suites_count,
        entropy_bypassed=True,
        raw_entropy=raw_entropy_val,
    )
