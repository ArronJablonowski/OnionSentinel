"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from relay_pcap_broker_fixtures import (
    Path,
    RELAY_PATH,
    REPO_ROOT,
    contextlib,
    fcntl,
    hashlib,
    importlib,
    io,
    json,
    load_relay,
    mock,
    os,
    subprocess,
    sys,
    tarfile,
    tempfile,
    time,
    unittest,
)

from relay_pcap_broker_fixtures_relaypcapbrokertest import RelayPcapBrokerTestFixtures
from cases_relay_pcap_broker_relaypcapbrokertest_mac_transfer_uses_only_a_preprovisioned_host_pin import RelayPcapBrokerTestMacTransferUsesOnlyAPreprovisionedHostPinCases
from cases_relay_pcap_broker_relaypcapbrokertest_artifact_upload_failure_records_fulfillment_metadata import RelayPcapBrokerTestArtifactUploadFailureRecordsFulfillmentMetadataCases


class RelayPcapBrokerTest(
    RelayPcapBrokerTestMacTransferUsesOnlyAPreprovisionedHostPinCases,
    RelayPcapBrokerTestArtifactUploadFailureRecordsFulfillmentMetadataCases,
    RelayPcapBrokerTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
