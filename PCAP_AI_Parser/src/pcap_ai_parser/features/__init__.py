"""
Feature engineering subpackage for PCAP AI Parser.

Modules:
- payload_features: Payload characteristics (size, Shannon entropy, printable ASCII ratio).
- context_ioc_features: Protocol context, IOC counts, encoding indicators, and unified feature vectors.
- tls_features: Dedicated TLS record detection, TLS metadata extraction path, and entropy bypass.
"""

from pcap_ai_parser.features.payload_features import (
    PayloadCharacteristics,
    calculate_payload_size,
    calculate_printable_ascii_ratio,
    calculate_shannon_entropy,
    extract_features_dict,
    extract_payload_characteristics,
)

from pcap_ai_parser.features.context_ioc_features import (
    EncodingFeatures,
    IOCFeatures,
    ProtocolContextFeatures,
    UnifiedPacketFeatures,
    extract_encoding_features,
    extract_ioc_features,
    extract_protocol_context,
    extract_unified_packet_features,
)

from pcap_ai_parser.features.tls_features import (
    TLSFeatures,
    TLS_HANDSHAKE_TYPES,
    TLS_RECORD_TYPES,
    TLS_VERSIONS,
    extract_tls_features,
    is_tls_record,
)

__all__ = [
    # Payload Characteristics
    "PayloadCharacteristics",
    "calculate_payload_size",
    "calculate_shannon_entropy",
    "calculate_printable_ascii_ratio",
    "extract_payload_characteristics",
    "extract_features_dict",
    # Context, IOC, and Encoding Features
    "ProtocolContextFeatures",
    "IOCFeatures",
    "EncodingFeatures",
    "UnifiedPacketFeatures",
    "extract_protocol_context",
    "extract_ioc_features",
    "extract_encoding_features",
    "extract_unified_packet_features",
    # TLS Features & Routing Path
    "TLSFeatures",
    "TLS_RECORD_TYPES",
    "TLS_HANDSHAKE_TYPES",
    "TLS_VERSIONS",
    "is_tls_record",
    "extract_tls_features",
]
