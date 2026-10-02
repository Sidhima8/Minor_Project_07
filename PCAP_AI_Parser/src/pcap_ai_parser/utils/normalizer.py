"""
Text normalization module for converting binary packet payloads into structured, printable representations.
"""

from dataclasses import dataclass, field
import re
from typing import List, Dict, Any
from pcap_ai_parser.utils.metrics import compute_payload_metrics


@dataclass
class PayloadNormalizationResult:
    """Dataclass holding normalized payload representations and statistical metadata."""
    raw_bytes: bytes
    payload_size: int
    printable_text: str
    extracted_strings: List[str]
    hex_dump: str
    clean_text: str
    has_non_printable: bool
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts result to serializable dictionary format."""
        return {
            "payload_size": self.payload_size,
            "printable_text": self.printable_text,
            "extracted_strings": self.extracted_strings,
            "hex_dump": self.hex_dump,
            "clean_text": self.clean_text,
            "has_non_printable": self.has_non_printable,
            "metrics": self.metrics,
        }


def extract_printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    """
    Extracts contiguous sequences of printable ASCII characters of length >= min_len.
    Emulates the behavior of the GNU 'strings' command line utility.
    
    Args:
        data: Raw payload bytes.
        min_len: Minimum string length threshold (default: 4).
        
    Returns:
        List of extracted printable ASCII strings.
    """
    if not data:
        return []

    # Match contiguous printable ASCII characters (bytes 32 to 126) of length min_len or more
    pattern = re.compile(rf"[ -~]{{{min_len},}}".encode("ascii"))
    matches = pattern.findall(data)
    return [m.decode("ascii") for m in matches]


def generate_hex_dump(data: bytes, width: int = 16, max_bytes: int = 512) -> str:
    """
    Generates a standard 16-byte width hex dump with ASCII sidebar preview.
    
    Args:
        data: Raw payload bytes.
        width: Number of bytes per line (default: 16).
        max_bytes: Maximum number of bytes to dump to prevent excessive log bloat.
        
    Returns:
        Formatted multi-line hex dump string.
    """
    if not data:
        return "<EMPTY PAYLOAD>"

    truncated = False
    target_data = data
    if len(data) > max_bytes:
        target_data = data[:max_bytes]
        truncated = True

    lines = []
    for i in range(0, len(target_data), width):
        chunk = target_data[i : i + width]
        
        # Hex representation split into 8-byte halves for readability
        hex_bytes = [f"{b:02x}" for b in chunk]
        if len(hex_bytes) > 8:
            hex_part = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
        else:
            hex_part = " ".join(hex_bytes)

        # Pad hex_part for incomplete final line
        # Total hex width for 16 bytes: (8 * 3 - 1) + 2 + (8 * 3 - 1) = 23 + 2 + 23 = 48 chars
        padding_needed = (width * 3 + (1 if width > 8 else 0)) - len(hex_part) - 1
        if padding_needed > 0:
            hex_part += " " * padding_needed

        # ASCII representation sidebar (. for non-printable)
        ascii_part = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in chunk
        )

        lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")

    if truncated:
        lines.append(f"... [Truncated {len(data) - max_bytes} bytes]")

    return "\n".join(lines)


def normalize_payload_to_printable(
    data: bytes,
    hex_escape_non_printable: bool = True,
    max_preview_len: int = 2000,
) -> PayloadNormalizationResult:
    """
    Normalizes binary payload data into structured printable text, extracts strings,
    generates hex dumps, and computes payload metrics.
    
    Args:
        data: Raw payload bytes.
        hex_escape_non_printable: If True, non-printable bytes are represented as '\\xHH'.
                                  If False, non-printable bytes are replaced with '.'.
        max_preview_len: Maximum character length for printable_text preview string.
        
    Returns:
        PayloadNormalizationResult dataclass instance.
    """
    if not data:
        return PayloadNormalizationResult(
            raw_bytes=b"",
            payload_size=0,
            printable_text="",
            extracted_strings=[],
            hex_dump="<EMPTY PAYLOAD>",
            clean_text="",
            has_non_printable=False,
            metrics=compute_payload_metrics(b""),
        )

    payload_size = len(data)
    has_non_printable = False
    printable_chars = []

    for b in data:
        # Standard printable ASCII range (32 to 126)
        if 32 <= b <= 126:
            printable_chars.append(chr(b))
        elif b == 10:  # LF
            printable_chars.append("\\n" if hex_escape_non_printable else "\n")
        elif b == 13:  # CR
            printable_chars.append("\\r" if hex_escape_non_printable else "\r")
        elif b == 9:   # TAB
            printable_chars.append("\\t" if hex_escape_non_printable else "\t")
        else:
            has_non_printable = True
            if hex_escape_non_printable:
                printable_chars.append(f"\\x{b:02x}")
            else:
                printable_chars.append(".")

    printable_text = "".join(printable_chars)
    if len(printable_text) > max_preview_len:
        printable_text = printable_text[:max_preview_len] + f"... [Truncated {len(printable_text) - max_preview_len} chars]"

    # UTF-8 decode with replacement for clean text
    clean_text = data.decode("utf-8", errors="replace")

    # Extract printable contiguous strings (min length = 4)
    extracted_strings = extract_printable_strings(data, min_len=4)

    # Format hex dump
    hex_dump = generate_hex_dump(data)

    # Compute statistical metrics
    metrics = compute_payload_metrics(data)

    return PayloadNormalizationResult(
        raw_bytes=data,
        payload_size=payload_size,
        printable_text=printable_text,
        extracted_strings=extracted_strings,
        hex_dump=hex_dump,
        clean_text=clean_text,
        has_non_printable=has_non_printable,
        metrics=metrics,
    )
