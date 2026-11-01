"""
payload_features.py — Feature Engineering Module for Packet Payload Characteristics.

This module extracts statistical and structural features from raw network packet payloads,
including:
- Payload Size: Length in bytes of the application payload.
- Shannon Entropy: Quantifies byte randomness/uncertainty (0.0 to 8.0 bits/byte).
  Low entropy (<3.0) indicates padding or repetitive text;
  Normal entropy (3.0-6.8) indicates plaintext/structured protocols;
  High entropy (>7.2) indicates encryption, compression, or packed shellcode.
- Printable ASCII Ratio: Proportion of printable ASCII and standard whitespace
  characters [0.0 to 1.0], useful for distinguishing text/web protocols from binary/encrypted streams.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Dict, Sequence


@dataclass
class PayloadCharacteristics:
    """Statistical and structural characteristics extracted from a packet payload."""

    payload_size: int
    shannon_entropy: float
    printable_ascii_ratio: float
    is_empty: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert characteristics to a dictionary suitable for tabular/ML feature pipelines."""
        return {
            "payload_size": self.payload_size,
            "shannon_entropy": self.shannon_entropy,
            "printable_ascii_ratio": self.printable_ascii_ratio,
            "is_empty": self.is_empty,
        }


def calculate_payload_size(data: bytes | bytearray | memoryview | None) -> int:
    """
    Calculate the byte size of a packet payload.

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application layer payload bytes.

    Returns
    -------
    int
        Length in bytes (0 if None or empty).
    """
    if not data:
        return 0
    return len(data)


def calculate_shannon_entropy(data: bytes | bytearray | memoryview | None) -> float:
    """
    Compute Shannon entropy of the payload in bits per byte [0.0 to 8.0].

    Formula:
        H(X) = - \\sum_{i} P(x_i) * log2(P(x_i))

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application layer payload bytes.

    Returns
    -------
    float
        Shannon entropy rounded to 4 decimal places.
        Returns 0.0 for empty payloads or single-byte repetitions.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def calculate_printable_ascii_ratio(data: bytes | bytearray | memoryview | None) -> float:
    """
    Calculate the proportion of printable ASCII characters and common whitespace [0.0 to 1.0].

    Printable ASCII includes byte values 32 through 126 inclusive (space to ~),
    as well as standard whitespace:
    - Tab (9 / \\t)
    - Line feed (10 / \\n)
    - Carriage return (13 / \\r)

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application layer payload bytes.

    Returns
    -------
    float
        Ratio between 0.0 and 1.0 rounded to 4 decimal places.
        Returns 0.0 for empty payloads.
    """
    if not data:
        return 0.0

    total_len = len(data)
    # 32 to 126: printable ASCII characters
    # 9 (\t), 10 (\n), 13 (\r): whitespace
    printable_count = sum(
        1 for b in data if (32 <= b <= 126) or b in (9, 10, 13)
    )

    return round(printable_count / total_len, 4)


def extract_payload_characteristics(data: bytes | bytearray | memoryview | None) -> PayloadCharacteristics:
    """
    Extract all payload characteristics into a structured PayloadCharacteristics object.

    Parameters
    ----------
    data : bytes | bytearray | memoryview | None
        Raw application layer payload bytes.

    Returns
    -------
    PayloadCharacteristics
        Container with payload_size, shannon_entropy, printable_ascii_ratio, and is_empty.
    """
    size = calculate_payload_size(data)
    if size == 0:
        return PayloadCharacteristics(
            payload_size=0,
            shannon_entropy=0.0,
            printable_ascii_ratio=0.0,
            is_empty=True,
        )

    entropy = calculate_shannon_entropy(data)
    ascii_ratio = calculate_printable_ascii_ratio(data)

    return PayloadCharacteristics(
        payload_size=size,
        shannon_entropy=entropy,
        printable_ascii_ratio=ascii_ratio,
        is_empty=False,
    )


def extract_features_dict(data: bytes | bytearray | memoryview | None, prefix: str = "") -> Dict[str, Any]:
    """
    Convenience function returning a flat dict with optional key prefix for pandas/ML pipelines.
    """
    chars = extract_payload_characteristics(data)
    d = chars.to_dict()
    if prefix:
        return {f"{prefix}{k}": v for k, v in d.items()}
    return d
