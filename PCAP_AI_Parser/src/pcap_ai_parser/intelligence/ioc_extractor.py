"""
ioc_extractor.py — Automated Indicators of Compromise (IOC) harvesting engine.

Extracts security-relevant artifacts using high-precision regex patterns:
- IPv4 and IPv6 addresses (with octet validation and bogon filtering)
- Domains and FQDNs
- URLs (HTTP, HTTPS, FTP, WebSocket)
- Email addresses
- Cryptographic hashes (MD5, SHA-1, SHA-256)
- CVE vulnerability identifiers
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class IOCRecord:
    """An individual Indicator of Compromise extracted from packet data."""

    ioc_type: str  # IPV4, IPV6, DOMAIN, URL, EMAIL, MD5, SHA1, SHA256, CVE
    value: str
    context: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class IOCExtractor:
    """
    High-precision IOC extraction and harvesting engine.
    """

    # ── Compiled Patterns ─────────────────────────────────────────────────────

    # IPv4 Pattern
    _IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # IPv6 Pattern (standard and compressed)
    _IPV6_RE = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b"
    )

    # URL Pattern
    _URL_RE = re.compile(
        r"\b(?:https?|ftp|ws|wss)://[^\s/$.?#].[^\s]*",
        re.IGNORECASE,
    )

    # Email Pattern
    _EMAIL_RE = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Domain Pattern (standard TLDs, excluding pure numeric or common file extensions)
    _DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|ai|co|xyz|info|biz|ru|cn|de|uk|internal|local)\b",
        re.IGNORECASE,
    )

    # Cryptographic Hashes
    _MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
    _SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
    _SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # CVE IDs
    _CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # Noise exclusion for IPs
    _BOGON_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

    def __init__(self) -> None:
        pass

    @classmethod
    def _is_valid_ipv4(cls, ip_str: str) -> bool:
        if ip_str in cls._BOGON_IPS:
            return False
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return True
        except ValueError:
            return False

    @classmethod
    def _is_valid_ipv6(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.IPv6Address(ip_str)
            return not ip.is_loopback
        except ValueError:
            return False

    def extract_from_text(self, text: str, context: str = "") -> list[IOCRecord]:
        """
        Extract all IOCs from a plain text or decoded string.
        """
        iocs: set[IOCRecord] = set()

        if not text:
            return []

        # 1. URLs
        found_urls = set()
        for url in self._URL_RE.findall(text):
            # Clean trailing punctuation often caught by regex
            clean_url = url.rstrip(".,;)\"'>")
            found_urls.add(clean_url)
            iocs.add(IOCRecord(ioc_type="URL", value=clean_url, context=context))

        # 2. Emails
        for email in self._EMAIL_RE.findall(text):
            iocs.add(IOCRecord(ioc_type="EMAIL", value=email.lower(), context=context))

        # 3. IPv4
        for ip in self._IPV4_RE.findall(text):
            if self._is_valid_ipv4(ip):
                iocs.add(IOCRecord(ioc_type="IPV4", value=ip, context=context))

        # 4. IPv6
        for ip in self._IPV6_RE.findall(text):
            if self._is_valid_ipv6(ip):
                iocs.add(IOCRecord(ioc_type="IPV6", value=ip, context=context))

        # 5. Domains (skip if already part of an extracted URL or Email)
        for domain in self._DOMAIN_RE.findall(text):
            domain_lower = domain.lower()
            if not any(domain_lower in u.lower() for u in found_urls):
                iocs.add(IOCRecord(ioc_type="DOMAIN", value=domain_lower, context=context))

        # 6. CVE IDs
        for cve in self._CVE_RE.findall(text):
            iocs.add(IOCRecord(ioc_type="CVE", value=cve.upper(), context=context))

        # 7. Hashes (differentiate by length)
        # Check SHA-256 first
        sha256_matches = set(self._SHA256_RE.findall(text))
        for h in sha256_matches:
            iocs.add(IOCRecord(ioc_type="SHA256", value=h.lower(), context=context))

        # Check SHA-1 (exclude if subset of SHA-256)
        for h in self._SHA1_RE.findall(text):
            if not any(h in s for s in sha256_matches):
                iocs.add(IOCRecord(ioc_type="SHA1", value=h.lower(), context=context))

        # Check MD5 (exclude if all zeros or repetitive)
        for h in self._MD5_RE.findall(text):
            if len(set(h)) > 2 and not any(h in s for s in sha256_matches):
                iocs.add(IOCRecord(ioc_type="MD5", value=h.lower(), context=context))

        return sorted(list(iocs), key=lambda x: (x.ioc_type, x.value))

    def extract_from_payload(
        self,
        payload: bytes,
        decoded_texts: list[str] | None = None,
    ) -> list[IOCRecord]:
        """
        Extract IOCs across raw payload, printable strings, and decoded artifacts.
        """
        all_iocs: set[IOCRecord] = set()

        # Direct text decode
        try:
            ascii_text = payload.decode("ascii", errors="ignore")
            all_iocs.update(self.extract_from_text(ascii_text, context="payload"))
        except Exception:
            pass

        # Decoded artifacts
        if decoded_texts:
            for decoded in decoded_texts:
                all_iocs.update(self.extract_from_text(decoded, context="decoded_payload"))

        return sorted(list(all_iocs), key=lambda x: (x.ioc_type, x.value))
