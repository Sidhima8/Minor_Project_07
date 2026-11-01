"""
test_intelligence.py — unit tests for Shannon entropy, IOC extraction, and heuristic risk scoring.
"""

from __future__ import annotations

import pytest

from pcap_ai_parser.intelligence.entropy import (
    analyze_entropy,
    calculate_entropy,
)
from pcap_ai_parser.intelligence.ioc_extractor import IOCExtractor, IOCRecord
from pcap_ai_parser.intelligence.risk_scorer import (
    HeuristicRiskScorer,
    RiskAssessment,
)
from pcap_ai_parser.models.packet import PacketRecord


# ── Tests: Shannon Entropy ───────────────────────────────────────────────────

class TestEntropy:

    def test_entropy_empty(self):
        assert calculate_entropy(b"") == 0.0

    def test_entropy_zero_randomness(self):
        # Repetitive single byte has zero entropy
        assert calculate_entropy(b"A" * 500) == 0.0

    def test_entropy_maximum_possible(self):
        # All 256 byte values equally represented has exactly 8.0 entropy
        full_spectrum = bytes(range(256)) * 4
        h = calculate_entropy(full_spectrum)
        assert pytest.approx(h, 0.01) == 8.0

    def test_entropy_natural_text(self):
        text = b"The quick brown fox jumps over the lazy dog"
        h = calculate_entropy(text)
        assert 3.0 < h < 5.0

    def test_analyze_entropy_classification(self):
        empty_res = analyze_entropy(b"")
        assert empty_res.classification == "EMPTY"
        assert not empty_res.is_suspicious

        # Pseudo-random high entropy byte sequence
        import os
        random_bytes = os.urandom(4096)
        res = analyze_entropy(random_bytes)
        assert res.entropy > 7.3
        assert res.classification == "HIGH"
        assert res.is_suspicious


# ── Tests: IOC Extractor ─────────────────────────────────────────────────────

class TestIOCExtractor:

    @pytest.fixture
    def extractor(self) -> IOCExtractor:
        return IOCExtractor()

    def test_extract_ipv4(self, extractor: IOCExtractor):
        text = "Connecting to 198.51.100.24 and 10.0.0.1 (ignore 999.888.777.666)"
        iocs = extractor.extract_from_text(text)
        ips = [i.value for i in iocs if i.ioc_type == "IPV4"]
        assert "198.51.100.24" in ips
        assert "10.0.0.1" in ips
        assert "999.888.777.666" not in ips

    def test_extract_url_and_domains(self, extractor: IOCExtractor):
        text = "Visit http://evil-c2-server.com/beacon and download malware.xyz"
        iocs = extractor.extract_from_text(text)
        urls = [i.value for i in iocs if i.ioc_type == "URL"]
        domains = [i.value for i in iocs if i.ioc_type == "DOMAIN"]
        assert "http://evil-c2-server.com/beacon" in urls
        assert "malware.xyz" in domains

    def test_extract_email(self, extractor: IOCExtractor):
        text = "Contact victim-support@target-corp.com immediately"
        iocs = extractor.extract_from_text(text)
        emails = [i.value for i in iocs if i.ioc_type == "EMAIL"]
        assert "victim-support@target-corp.com" in emails

    def test_extract_hashes(self, extractor: IOCExtractor):
        md5_sample = "d41d8cd98f00b204e9800998ecf8427e"
        sha256_sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"Sample hashes: {md5_sample} and {sha256_sample}"
        iocs = extractor.extract_from_text(text)
        hashes = {i.ioc_type: i.value for i in iocs}
        assert hashes.get("MD5") == md5_sample
        assert hashes.get("SHA256") == sha256_sample

    def test_extract_cve(self, extractor: IOCExtractor):
        text = "Exploit references CVE-2021-44228 (Log4Shell) and CVE-2023-38606"
        iocs = extractor.extract_from_text(text)
        cves = [i.value for i in iocs if i.ioc_type == "CVE"]
        assert "CVE-2021-44228" in cves
        assert "CVE-2023-38606" in cves


# ── Tests: Heuristic Risk Scorer ─────────────────────────────────────────────

class TestHeuristicRiskScorer:

    @pytest.fixture
    def scorer(self) -> HeuristicRiskScorer:
        return HeuristicRiskScorer()

    def test_evaluate_clean_packet(self, scorer: HeuristicRiskScorer):
        rec = PacketRecord(
            packet_number=1,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=53210,
            dst_port=53,
            transport_proto="UDP",
            payload=b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        )
        res = scorer.evaluate(rec)
        assert res.score == 0
        assert res.severity == "CLEAN"
        assert len(res.findings) == 0

    def test_evaluate_credential_exposure(self, scorer: HeuristicRiskScorer):
        rec = PacketRecord(
            packet_number=2,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=80,
            transport_proto="TCP",
            payload=b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=SuperSecretPassword123",
        )
        res = scorer.evaluate(rec)
        assert res.score >= 40
        assert res.severity in ("MEDIUM", "HIGH")
        assert any("password" in f.lower() for f in res.findings)

    def test_evaluate_sqli_attack(self, scorer: HeuristicRiskScorer):
        rec = PacketRecord(
            packet_number=3,
            src_ip="10.0.0.99",
            dst_ip="192.168.1.50",
            src_port=44120,
            dst_port=80,
            transport_proto="TCP",
            payload=b"GET /items?id=1' UNION ALL SELECT null, username, password FROM users-- HTTP/1.1\r\n",
        )
        res = scorer.evaluate(rec)
        assert res.score >= 45
        assert any("SQL Injection" in f for f in res.findings)

    def test_evaluate_command_injection_critical(self, scorer: HeuristicRiskScorer):
        rec = PacketRecord(
            packet_number=4,
            src_ip="10.0.0.99",
            dst_ip="192.168.1.50",
            src_port=4444,  # Metasploit port (+45)
            dst_port=55112,
            transport_proto="TCP",
            payload=b"whoami; /bin/sh -i; password=admin",  # Command injection (+50) + creds (+40)
        )
        res = scorer.evaluate(rec)
        assert res.score >= 80
        assert res.severity == "CRITICAL"
        assert len(res.findings) >= 2
