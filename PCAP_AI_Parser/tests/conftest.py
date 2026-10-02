"""pytest configuration — shared fixtures."""
import pytest

"""or"""

"""
Pytest configuration and shared fixtures.
"""

import os
import tempfile
import pytest
try:
    from scripts.generate_payload_normalisation_pcap import create_sample_pcap
except ImportError:
    from scripts.generate_sample_pcap import create_sample_pcap


@pytest.fixture(scope="session")
def sample_pcap_path():
    """Generates a temporary sample PCAP file for testing session."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
    
    create_sample_pcap(tmp_path)
    yield tmp_path
    
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
