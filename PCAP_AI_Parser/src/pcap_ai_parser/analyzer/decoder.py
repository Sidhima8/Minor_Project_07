"""
decoder.py — automated multi-layer encoding identification and decoding.

Detects and unwraps common payload encodings:
- Base64 (including URL-safe Base64 and padding-tolerant strings)
- URL / Percent-encoding (%20, %3D, etc.)
- Hex string encoding (e.g., 0x..., \\x..., or raw even-length hex sequences)
- Recursive decoding (e.g. Base64 nested inside URL-encoded queries)
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import asdict, dataclass


@dataclass
class DecodedArtifact:
    """Represents a discovered and successfully decoded payload fragment."""

    encoding: str
    original: str
    decoded_bytes: bytes
    decoded_text: str
    depth: int = 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("decoded_bytes", None)
        return d


class PayloadDecoder:
    """
    Automated payload decoding engine.
    Finds embedded encoded structures and recursively decodes them up to max_depth.
    """

    # Matches Base64 strings of at least 8 characters with optional standard padding
    _BASE64_PATTERN = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )

    # Matches URL-encoded tokens (%XX)
    _URL_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")

    # Matches hex sequences (\x41\x42... or 0x4142... or continuous hex >= 8 chars)
    _HEX_PREFIX_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
    _RAW_HEX_PATTERN = re.compile(r"\b[0-9a-fA-F]{8,}\b")

    def __init__(self, max_depth: int = 3, min_base64_len: int = 8) -> None:
        self.max_depth = max_depth
        self.min_base64_len = min_base64_len

    @staticmethod
    def _is_meaningful_text(text: str) -> bool:
        """Check if decoded string consists predominantly of printable characters."""
        if not text:
            return False
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
        return (printable / len(text)) >= 0.75

    def decode_url(self, raw_text: str, depth: int = 1) -> list[DecodedArtifact]:
        """Detect and decode URL/percent-encoded sequences."""
        artifacts: list[DecodedArtifact] = []
        if "%" not in raw_text:
            return artifacts

        matches = self._URL_PATTERN.findall(raw_text)
        # Also test the entire string if it contains %
        candidates = set(matches)
        if len(candidates) > 0 and raw_text not in candidates:
            candidates.add(raw_text)

        for candidate in candidates:
            try:
                unquoted = urllib.parse.unquote(candidate)
                if unquoted != candidate and self._is_meaningful_text(unquoted):
                    artifacts.append(
                        DecodedArtifact(
                            encoding="url",
                            original=candidate,
                            decoded_bytes=unquoted.encode("utf-8", errors="replace"),
                            decoded_text=unquoted,
                            depth=depth,
                        )
                    )
            except Exception:
                continue
        return artifacts

    def decode_base64(self, raw_text: str, depth: int = 1) -> list[DecodedArtifact]:
        """Detect and decode Base64 strings."""
        artifacts: list[DecodedArtifact] = []
        matches = self._BASE64_PATTERN.findall(raw_text)

        for candidate in set(matches):
            if len(candidate) < self.min_base64_len:
                continue

            # Standard base64 padding normalization
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                # Attempt to decode as UTF-8 or ASCII
                try:
                    decoded_text = decoded_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    decoded_text = decoded_bytes.decode("latin1", errors="replace")

                if self._is_meaningful_text(decoded_text):
                    artifacts.append(
                        DecodedArtifact(
                            encoding="base64",
                            original=candidate,
                            decoded_bytes=decoded_bytes,
                            decoded_text=decoded_text,
                            depth=depth,
                        )
                    )
            except Exception:
                continue

        return artifacts

    def decode_hex(self, raw_text: str, depth: int = 1) -> list[DecodedArtifact]:
        """Detect and decode explicit hex sequences (e.g. \\x41\\x42 or 48656c6c6f)."""
        artifacts: list[DecodedArtifact] = []

        # 1. \x escaped sequences
        for m in set(self._HEX_PREFIX_PATTERN.findall(raw_text)):
            clean_hex = m.replace("\\x", "")
            try:
                b = bytes.fromhex(clean_hex)
                t = b.decode("utf-8", errors="replace")
                if self._is_meaningful_text(t):
                    artifacts.append(
                        DecodedArtifact(
                            encoding="hex_escaped",
                            original=m,
                            decoded_bytes=b,
                            decoded_text=t,
                            depth=depth,
                        )
                    )
            except Exception:
                pass

        # 2. Raw hex tokens of even length
        for m in set(self._RAW_HEX_PATTERN.findall(raw_text)):
            if len(m) % 2 != 0:
                continue
            # Avoid decoding numbers or pure zeros
            if set(m) <= {"0"}:
                continue
            try:
                b = bytes.fromhex(m)
                t = b.decode("utf-8", errors="replace")
                if self._is_meaningful_text(t):
                    artifacts.append(
                        DecodedArtifact(
                            encoding="hex_raw",
                            original=m,
                            decoded_bytes=b,
                            decoded_text=t,
                            depth=depth,
                        )
                    )
            except Exception:
                pass

        return artifacts

    def decode_all(self, data: bytes | str) -> list[DecodedArtifact]:
        """
        Run all decoders recursively up to max_depth.
        """
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin1", errors="replace")
        else:
            text = str(data)

        results: list[DecodedArtifact] = []
        seen_decoded_texts: set[str] = {text}

        current_level_texts = [text]

        for depth in range(1, self.max_depth + 1):
            next_level_texts = []
            for target in current_level_texts:
                layer_artifacts = (
                    self.decode_url(target, depth=depth)
                    + self.decode_base64(target, depth=depth)
                    + self.decode_hex(target, depth=depth)
                )
                for art in layer_artifacts:
                    if art.decoded_text not in seen_decoded_texts:
                        seen_decoded_texts.add(art.decoded_text)
                        results.append(art)
                        next_level_texts.append(art.decoded_text)

            if not next_level_texts:
                break
            current_level_texts = next_level_texts

        return results
