"""
PCAP AI Parser — AI-powered packet capture analysis pipeline.

Backends:
  - dpkt  : fast, low-level packet parsing
  - tshark: deep protocol dissection via Wireshark engine
"""

__version__ = "0.1.0"
__author__ = "rohinish"

from pcap_ai_parser.features import (
    PayloadCharacteristics,
    calculate_payload_size,
    calculate_shannon_entropy,
    calculate_printable_ascii_ratio,
    extract_payload_characteristics,
)

__all__ = [
    "__version__",
    "__author__",
    "PayloadCharacteristics",
    "calculate_payload_size",
    "calculate_shannon_entropy",
    "calculate_printable_ascii_ratio",
    "extract_payload_characteristics",
]

