"""
entropy.py — Shannon entropy calculation and entropy-based anomaly detection.

Shannon entropy quantifies the randomness / uncertainty of byte distributions
in a packet payload. For 8-bit octets, maximum entropy is 8.0 bits/byte.

Interpretation:
- 0.0 - 3.0 : Low entropy (repetitive patterns, null-padded buffers)
- 3.0 - 6.5 : Normal entropy (plain English text, HTML, JSON, HTTP headers)
- 6.5 - 7.2 : Elevated entropy (compressed text, code, binary assets)
- 7.2 - 8.0 : High entropy (encrypted payloads, packed malware, shellcode, crypto tokens)
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass


@dataclass
class EntropyResult:
    """Shannon entropy analysis result for a payload."""

    entropy: float
    classification: str
    is_suspicious: bool
    description: str

    def to_dict(self) -> dict:
        return {
            "entropy": round(self.entropy, 4),
            "classification": self.classification,
            "is_suspicious": self.is_suspicious,
            "description": self.description,
        }


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence in bits per byte.
    Returns a float in range [0.0, 8.0].
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


def analyze_entropy(data: bytes) -> EntropyResult:
    """
    Compute Shannon entropy and return structured classification.
    """
    if not data:
        return EntropyResult(
            entropy=0.0,
            classification="EMPTY",
            is_suspicious=False,
            description="Empty payload (0 bytes)",
        )

    h = calculate_entropy(data)

    if h < 3.0:
        return EntropyResult(
            entropy=h,
            classification="LOW",
            is_suspicious=False,
            description="Low entropy (repetitive patterns or sparse data)",
        )
    elif h < 6.8:
        return EntropyResult(
            entropy=h,
            classification="NORMAL",
            is_suspicious=False,
            description="Normal entropy (plaintext, headers, or structured protocols)",
        )
    elif h < 7.3:
        return EntropyResult(
            entropy=h,
            classification="ELEVATED",
            is_suspicious=False,
            description="Elevated entropy (compressed or lightly encoded stream)",
        )
    else:
        return EntropyResult(
            entropy=h,
            classification="HIGH",
            is_suspicious=True,
            description="High entropy (potential encryption, packed malware, or shellcode)",
        )
