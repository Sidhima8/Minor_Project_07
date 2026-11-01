"""
byte_normalizer.py — converts raw packet payload octets into multi-base representations.

Implements byte-level transformations required by the PacketParser-AI specification:
- Hexadecimal dump (canonical Wireshark / xxd layout with offset, hex octets, and ASCII preview)
- Hex stream (space or custom delimited hex pairs)
- Decimal stream (8-bit integer octets: 0-255)
- Binary stream (8-bit binary representation: 00000000 - 11111111)
- Printable ASCII text with placeholder substitution for non-printable octets
- Extraction of contiguous printable strings (similar to Unix `strings`)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field


@dataclass
class ByteNormalization:
    """Normalized multi-base representations of an arbitrary byte payload."""

    total_bytes: int
    hex_dump: str
    hex_stream: str
    decimal_stream: str
    binary_stream: str
    ascii_text: str
    extracted_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def to_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Produce a canonical hex dump representation.

    Example line:
    00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
    """
    if not data:
        return ""

    lines: list[str] = []
    half = bytes_per_line // 2

    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]

        # Hex representation
        hex_left = " ".join(f"{b:02x}" for b in chunk[:half])
        hex_right = " ".join(f"{b:02x}" for b in chunk[half:])
        hex_combined = f"{hex_left:<{half * 3 - 1}}  {hex_right:<{(bytes_per_line - half) * 3 - 1}}"

        # ASCII representation
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        lines.append(f"{offset:08x}  {hex_combined}  |{ascii_chars}|")

    return "\n".join(lines)


def to_hex_stream(data: bytes, delimiter: str = " ") -> str:
    """Convert bytes to a delimiter-separated hex string."""
    return delimiter.join(f"{b:02x}" for b in data)


def to_decimal_stream(data: bytes, delimiter: str = " ") -> str:
    """Convert bytes to a delimiter-separated 8-bit decimal string."""
    return delimiter.join(str(b) for b in data)


def to_binary_stream(data: bytes, delimiter: str = " ") -> str:
    """Convert bytes to a delimiter-separated 8-bit binary bitstream."""
    return delimiter.join(f"{b:08b}" for b in data)


def to_ascii_text(data: bytes, placeholder: str = ".") -> str:
    """Convert bytes to ASCII, replacing non-printable characters with placeholder."""
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else placeholder for b in data)


_PRINTABLE_REGEX = re.compile(rb"[\x20-\x7e]{%d,}" % 4)


def extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """
    Extract contiguous printable ASCII strings of at least min_length bytes.
    Matches behaviour of the Unix `strings` command.
    """
    if not data or min_length < 1:
        return []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [match.group(0).decode("ascii", errors="replace") for match in pattern.finditer(data)]


def normalize_payload(data: bytes, min_string_len: int = 4) -> ByteNormalization:
    """
    Run full normalization pipeline over raw payload bytes.
    """
    return ByteNormalization(
        total_bytes=len(data),
        hex_dump=to_hex_dump(data),
        hex_stream=to_hex_stream(data),
        decimal_stream=to_decimal_stream(data),
        binary_stream=to_binary_stream(data),
        ascii_text=to_ascii_text(data),
        extracted_strings=extract_printable_strings(data, min_length=min_string_len),
    )
