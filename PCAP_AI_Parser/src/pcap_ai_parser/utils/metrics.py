"""
Payload statistical metrics calculations: Shannon entropy, printable ASCII ratio, and unique byte ratio.
"""

import math
from typing import Dict, Any


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon Entropy of a byte stream in bits per byte [0.0 to 8.0].
    
    Args:
        data: Raw payload bytes.
        
    Returns:
        Shannon entropy value between 0.0 (uniform/empty) and 8.0 (maximum entropy / random / encrypted).
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts: dict[int, int] = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1

    entropy = 0.0
    for count in byte_counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_printable_ascii_ratio(data: bytes) -> float:
    """
    Computes the proportion of printable ASCII bytes (and standard whitespace) in the byte stream.
    
    Args:
        data: Raw payload bytes.
        
    Returns:
        Ratio float between 0.0 and 1.0.
    """
    if not data:
        return 0.0

    # Printable ASCII range: 32 (space) to 126 (~), plus \t (9), \n (10), \r (13)
    printable_count = sum(
        1 for b in data if (32 <= b <= 126) or b in (9, 10, 13)
    )

    return round(printable_count / len(data), 4)


def calculate_unique_byte_ratio(data: bytes) -> float:
    """
    Computes the ratio of unique byte values to total payload size.
    
    Args:
        data: Raw payload bytes.
        
    Returns:
        Ratio float between 0.0 and 1.0.
    """
    if not data:
        return 0.0

    unique_count = len(set(data))
    return round(unique_count / len(data), 4)


def compute_payload_metrics(data: bytes) -> Dict[str, Any]:
    """
    Generates a full dictionary of payload metrics.
    
    Args:
        data: Raw payload bytes.
        
    Returns:
        Dict containing payload_size, shannon_entropy, printable_ascii_ratio, unique_byte_ratio, is_empty.
    """
    payload_size = len(data)
    return {
        "payload_size": payload_size,
        "shannon_entropy": calculate_shannon_entropy(data),
        "printable_ascii_ratio": calculate_printable_ascii_ratio(data),
        "unique_byte_ratio": calculate_unique_byte_ratio(data),
        "is_empty": payload_size == 0,
    }
