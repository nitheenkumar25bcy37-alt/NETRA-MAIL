"""Keep test imports and API writes out of real investigation storage."""
import os
import tempfile
from pathlib import Path

_test_storage = tempfile.TemporaryDirectory(prefix="netra-tests-")
_root = Path(_test_storage.name)
os.environ["NETRA_DATABASE_PATH"] = str(_root / "ledger.db")
os.environ["NETRA_EVIDENCE_STORAGE_DIR"] = str(_root / "evidence")
os.environ["NETRA_REQUIRE_API_AUTH"] = "false"
os.environ["NETRA_API_IDENTITIES"] = "[]"
os.environ["NETRA_IP_INTEL_URL"] = ""
for _flag in ("NETRA_REGISTRATION_ENABLED", "NETRA_NETWORK_ENRICHMENT_ENABLED", "NETRA_TOR_ENABLED", "NETRA_THREATFOX_ENABLED"):
    os.environ[_flag] = "false"
os.environ["NETRA_EVIDENCE_KEYS_JSON"] = "{}"
os.environ["NETRA_EVIDENCE_ACTIVE_KEY"] = ""
os.environ["NETRA_REQUIRE_EVIDENCE_ENCRYPTION"] = "false"


def pytest_unconfigure(config):
    _test_storage.cleanup()
