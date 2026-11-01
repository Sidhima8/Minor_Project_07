"""pytest configuration — shared fixtures."""
from pathlib import Path
import pytest
from scripts.generate_payload_normalisation_pcap import create_sample_pcap


@pytest.fixture
def sample_pcap_path(tmp_path: Path) -> str:
    """Fixture providing a synthetic PCAP file for testing."""
    pcap_file = tmp_path / "sample.pcap"
    create_sample_pcap(str(pcap_file))
    return str(pcap_file)
