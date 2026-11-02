"""
PCAP AI Parser — AI-powered packet capture analysis pipeline.

Backends:
  - dpkt  : fast, low-level packet parsing
  - tshark: deep protocol dissection via Wireshark engine
"""

__version__ = "0.1.0"
__author__ = "rohinish"

from pcap_ai_parser.features import (
    EncodingFeatures,
    IOCFeatures,
    PayloadCharacteristics,
    ProtocolContextFeatures,
    TLSFeatures,
    UnifiedPacketFeatures,
    calculate_payload_size,
    calculate_printable_ascii_ratio,
    calculate_shannon_entropy,
    extract_encoding_features,
    extract_features_dict,
    extract_ioc_features,
    extract_payload_characteristics,
    extract_protocol_context,
    extract_tls_features,
    extract_unified_packet_features,
    is_tls_record,
)

__all__ = [
    "__version__",
    "__author__",
    "PayloadCharacteristics",
    "ProtocolContextFeatures",
    "IOCFeatures",
    "EncodingFeatures",
    "TLSFeatures",
    "UnifiedPacketFeatures",
    "calculate_payload_size",
    "calculate_shannon_entropy",
    "calculate_printable_ascii_ratio",
    "extract_payload_characteristics",
    "extract_protocol_context",
    "extract_ioc_features",
    "extract_encoding_features",
    "extract_tls_features",
    "extract_unified_packet_features",
    "extract_features_dict",
    "is_tls_record",
]
