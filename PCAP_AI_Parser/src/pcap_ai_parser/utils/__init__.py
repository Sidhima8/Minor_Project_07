"""
Utility modules for text normalization, payload metrics, and feature engineering.
"""
from pcap_ai_parser.utils.metrics import (
    calculate_shannon_entropy,
    calculate_printable_ascii_ratio,
    calculate_unique_byte_ratio,
    compute_payload_metrics,
)
from pcap_ai_parser.utils.normalizer import (
    normalize_payload_to_printable,
    extract_printable_strings,
    generate_hex_dump,
    PayloadNormalizationResult,
)

__all__ = [
    "calculate_shannon_entropy",
    "calculate_printable_ascii_ratio",
    "calculate_unique_byte_ratio",
    "compute_payload_metrics",
    "normalize_payload_to_printable",
    "extract_printable_strings",
    "generate_hex_dump",
    "PayloadNormalizationResult",
]
