"""
risk_scorer.py — Heuristic Threat Intelligence & Risk Scoring Engine.

Computes an explainable risk score (0–100) and severity rating
(CLEAN, LOW, MEDIUM, HIGH, CRITICAL) for each packet based on:
1. Plaintext credential exposures
2. Web attack signatures (SQLi, XSS, Path Traversal, Command Injection)
3. High Shannon entropy anomalies (packed payloads, shellcode, crypto)
4. Suspicious / high-risk networking ports (C2 default ports, Telnet, IRC)
5. Harvested IOCs (malicious hashes, CVE identifiers, suspicious URLs)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from pcap_ai_parser.intelligence.entropy import analyze_entropy
from pcap_ai_parser.intelligence.ioc_extractor import IOCExtractor, IOCRecord
from pcap_ai_parser.models.packet import PacketRecord


@dataclass
class RiskAssessment:
    """Heuristic risk scoring evaluation output."""

    score: int
    severity: str  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    findings: list[str] = field(default_factory=list)
    entropy: float = 0.0
    iocs: list[IOCRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "findings": self.findings,
            "entropy": round(self.entropy, 4),
            "iocs": [ioc.to_dict() for ioc in self.iocs],
        }


class HeuristicRiskScorer:
    """
    Rule-based heuristic risk scoring and pattern matching engine.
    """

    # ── Suspicious signature definitions ──────────────────────────────────────

    _CREDENTIAL_PATTERNS = [
        (re.compile(r"(?:password|passwd|pwd)\s*=\s*[^\s&;]+", re.I), "Plaintext password transmission", 40),
        (re.compile(r"authorization:\s*basic\s+[a-za-z0-9+/=]+", re.I), "Plaintext HTTP Basic Authentication", 35),
        (re.compile(r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[^\s&;]+", re.I), "API Key / Token exposure in payload", 35),
    ]

    _EXPLOIT_PATTERNS = [
        (re.compile(r"(?:union\s+all\s+select|select\s+.*\s+from|'\s*or\s*'1'='1|benchmark\(|sleep\(\d+\))", re.I), "SQL Injection (SQLi) pattern", 45),
        (re.compile(r"(?:<script.*?>|javascript:|onload\s*=|onerror\s*=)", re.I), "Cross-Site Scripting (XSS) payload", 35),
        (re.compile(r"(?:\.\./\.\./|\.\.\\\.\.\\)", re.I), "Directory / Path Traversal attempt", 35),
        (re.compile(r"(?:/bin/(?:ba)?sh|cmd\.exe|powershell\.exe|whoami|cat\s+/etc/passwd)", re.I), "Command Injection / Shell Execution signature", 50),
    ]

    _SUSPICIOUS_PORTS = {
        21: ("FTP (unencrypted control channel)", 15),
        23: ("Telnet (unencrypted terminal session)", 25),
        1337: ("Port 1337 (commonly used for C2 / Netcat reverse shells)", 35),
        4444: ("Port 4444 (Metasploit default listener port)", 45),
        6667: ("IRC (frequent Botnet command-and-control channel)", 30),
        31337: ("Port 31337 ('Back Orifice' legacy trojan / exploit port)", 40),
    }

    def __init__(self) -> None:
        self.ioc_extractor = IOCExtractor()

    def evaluate(
        self,
        record: PacketRecord,
        decoded_texts: list[str] | None = None,
    ) -> RiskAssessment:
        """
        Evaluate a single PacketRecord and assign a heuristic risk score.
        """
        score = 0
        findings: list[str] = []

        # 1. Port-based heuristics
        ports = [p for p in (record.src_port, record.dst_port) if p]
        for p in ports:
            if p in self._SUSPICIOUS_PORTS:
                desc, pts = self._SUSPICIOUS_PORTS[p]
                score += pts
                findings.append(desc)

        # 2. Entropy analysis
        entropy_res = analyze_entropy(record.payload)
        entropy_val = entropy_res.entropy

        # Only flag high entropy if not on standard TLS ports (443, 8443)
        is_tls_port = any(p in (443, 8443, 993, 995, 465) for p in ports)
        if entropy_res.is_suspicious and not is_tls_port and len(record.payload) >= 32:
            score += 35
            findings.append(f"High entropy payload ({entropy_val} bits/byte) on non-TLS port -- possible shellcode/encryption")

        # 3. Payload string & exploit analysis
        text_corpus = []
        if record.payload:
            try:
                text_corpus.append(record.payload.decode("latin1"))
            except Exception:
                pass
        if decoded_texts:
            text_corpus.extend(decoded_texts)

        combined_text = "\n".join(text_corpus)

        # Plaintext credentials
        for pat, desc, pts in self._CREDENTIAL_PATTERNS:
            if pat.search(combined_text):
                score += pts
                findings.append(desc)

        # Exploit signatures
        for pat, desc, pts in self._EXPLOIT_PATTERNS:
            if pat.search(combined_text):
                score += pts
                findings.append(desc)

        # 4. IOC Harvesting & Scoring
        iocs = self.ioc_extractor.extract_from_payload(
            record.payload, decoded_texts=decoded_texts
        )

        # Check for CVE or Hash IOCs
        for ioc in iocs:
            if ioc.ioc_type == "CVE":
                score += 30
                findings.append(f"Referenced vulnerability identifier: {ioc.value}")
            elif ioc.ioc_type in ("MD5", "SHA256") and not is_tls_port:
                score += 15
                findings.append(f"Discovered cryptographic hash in cleartext: {ioc.value}")

        # Obfuscated IOC detection (IOC discovered inside decoded payload)
        if decoded_texts:
            decoded_combined = "\n".join(decoded_texts)
            decoded_iocs = self.ioc_extractor.extract_from_text(decoded_combined)
            if decoded_iocs:
                score += 30
                findings.append("Discovered obfuscated/encoded IOCs within decoded payload")

        # 5. Cap score at 100
        final_score = min(100, score)

        # Classify Severity
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 50:
            severity = "HIGH"
        elif final_score >= 25:
            severity = "MEDIUM"
        elif final_score > 0:
            severity = "LOW"
        else:
            severity = "CLEAN"

        return RiskAssessment(
            score=final_score,
            severity=severity,
            findings=findings,
            entropy=entropy_val,
            iocs=iocs,
        )
