"""
Unit tests for text normalization and statistical payload metrics.
"""

import math
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
)


def test_calculate_shannon_entropy():
    # Empty payload
    assert calculate_shannon_entropy(b"") == 0.0

    # Uniform single-symbol payload
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0

    # Equal distribution of 2 symbols
    # - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0 bit
    assert calculate_shannon_entropy(b"ABABABAB") == 1.0

    # All 256 unique byte values (maximum entropy = 8.0)
    all_bytes = bytes(range(256))
    assert calculate_shannon_entropy(all_bytes) == 8.0


def test_calculate_printable_ascii_ratio():
    assert calculate_printable_ascii_ratio(b"") == 0.0
    
    # 100% printable ASCII
    assert calculate_printable_ascii_ratio(b"Hello World 123!\r\n\t") == 1.0
    
    # 50% printable, 50% non-printable
    mixed = b"HTTP\x00\x01\x02\x03"
    assert calculate_printable_ascii_ratio(mixed) == 0.5


def test_calculate_unique_byte_ratio():
    assert calculate_unique_byte_ratio(b"") == 0.0
    
    # All same byte: 1 unique / 4 len = 0.25
    assert calculate_unique_byte_ratio(b"AAAA") == 0.25
    
    # All distinct bytes: 4 unique / 4 len = 1.0
    assert calculate_unique_byte_ratio(b"ABCD") == 1.0


def test_extract_printable_strings():
    data = b"\x00\x01Hello World!\x00\x02\x03TEST1234\x00abc"
    
    # Default min_len = 4
    extracted = extract_printable_strings(data, min_len=4)
    assert extracted == ["Hello World!", "TEST1234"]

    # min_len = 3
    extracted_3 = extract_printable_strings(data, min_len=3)
    assert extracted_3 == ["Hello World!", "TEST1234", "abc"]


def test_generate_hex_dump():
    data = b"GET / HTTP/1.1\r\n"
    hex_dump = generate_hex_dump(data)
    
    assert "00000000" in hex_dump
    assert "47 45 54 20" in hex_dump  # "GET "
    assert "|GET / HTTP/1.1..|" in hex_dump


def test_normalize_payload_to_printable():
    # Empty payload
    res_empty = normalize_payload_to_printable(b"")
    assert res_empty.payload_size == 0
    assert res_empty.printable_text == ""
    assert res_empty.has_non_printable is False

    # Mixed binary payload with hex escaping
    binary_data = b"POST /login \x00\x01\x02admin"
    res_escaped = normalize_payload_to_printable(binary_data, hex_escape_non_printable=True)
    assert res_escaped.payload_size == len(binary_data)
    assert res_escaped.has_non_printable is True
    assert "\\x00\\x01\\x02" in res_escaped.printable_text
    assert "admin" in res_escaped.extracted_strings

    # Dot replacement mode
    res_dot = normalize_payload_to_printable(binary_data, hex_escape_non_printable=False)
    assert "...admin" in res_dot.printable_text
