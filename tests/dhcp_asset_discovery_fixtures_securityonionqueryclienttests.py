from __future__ import annotations

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class SecurityOnionQueryClientTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.query_client = load_module("security_onion_query_client_test", QUERY_CLIENT)
