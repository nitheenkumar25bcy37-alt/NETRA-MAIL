from __future__ import annotations

import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

EVIDENCE_STORAGE_DIR = Path(
    os.getenv("NETRA_EVIDENCE_STORAGE_DIR", str(DATA_DIR / "evidence"))
).expanduser()

DATABASE_PATH = os.getenv(
    "NETRA_DATABASE_PATH",
    str(BASE_DIR / "forensic_ledger.db"),
)

MODEL_PATH = os.getenv(
    "NETRA_MODEL_PATH",
    str(BASE_DIR.parent / "data" / "phishing_model.joblib"),
)


# ---------------------------------------------------------------------------
# Safe environment parsing
# ---------------------------------------------------------------------------

def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """
    Read an integer environment variable safely.

    Invalid values fall back to the default.
    Values outside the permitted range are clamped.
    """

    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        return default

    return max(minimum, min(value, maximum))


def _env_bool(name: str, default: bool) -> bool:
    """
    Read a boolean environment variable safely.

    Accepted true values:
        1, true, yes, on

    Accepted false values:
        0, false, no, off
    """

    raw = os.getenv(name)

    if raw is None:
        return default

    normalized = raw.strip().lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    return default


def _env_origins(
    name: str,
    default: str,
) -> list[str]:
    """
    Parse a comma-separated CORS origin list.

    Empty entries are discarded.
    """

    raw = os.getenv(name, default)

    return [
        origin.strip()
        for origin in raw.split(",")
        if origin.strip()
    ]


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

# Incoming email:
# 1 MB minimum, 50 MB maximum.
MAX_EMAIL_SIZE_MB = _env_int(
    "NETRA_MAX_EMAIL_SIZE_MB",
    10,
    minimum=1,
    maximum=50,
)

MAX_EMAIL_SIZE_BYTES = MAX_EMAIL_SIZE_MB * 1024 * 1024


# Evidence:
# 1 MB minimum, 100 MB maximum.
MAX_EVIDENCE_SIZE_MB = _env_int(
    "NETRA_MAX_EVIDENCE_SIZE_MB",
    MAX_EMAIL_SIZE_MB,
    minimum=1,
    maximum=100,
)

MAX_EVIDENCE_SIZE_BYTES = MAX_EVIDENCE_SIZE_MB * 1024 * 1024


# Extracted text:
# 1 KB minimum, 5 MB maximum.
MAX_TEXT_SIZE_KB = _env_int(
    "NETRA_MAX_TEXT_SIZE_KB",
    512,
    minimum=1,
    maximum=5 * 1024,
)

MAX_TEXT_SIZE_BYTES = MAX_TEXT_SIZE_KB * 1024


# MIME structure:
# Prevent pathological MIME trees.
MAX_MIME_PARTS = _env_int(
    "NETRA_MAX_MIME_PARTS",
    200,
    minimum=1,
    maximum=2_000,
)


# URLs extracted from one email.
MAX_URLS = _env_int(
    "NETRA_MAX_URLS",
    100,
    minimum=1,
    maximum=2_000,
)


# Headers examined from one message.
MAX_HEADERS = _env_int(
    "NETRA_MAX_HEADERS",
    200,
    minimum=1,
    maximum=2_000,
)


# Archive members inspected by the static attachment analyzer.
MAX_ARCHIVE_MEMBERS = _env_int(
    "NETRA_MAX_ARCHIVE_MEMBERS",
    500,
    minimum=1,
    maximum=5_000,
)


# ---------------------------------------------------------------------------
# Request rate limiting
# ---------------------------------------------------------------------------

RATE_LIMIT_REQUESTS = _env_int(
    "NETRA_RATE_LIMIT_REQUESTS",
    60,
    minimum=1,
    maximum=10_000,
)

RATE_LIMIT_WINDOW_SECONDS = _env_int(
    "NETRA_RATE_LIMIT_WINDOW_SECONDS",
    60,
    minimum=1,
    maximum=86_400,
)

# Maximum number of unique rate-limit keys retained in memory.
RATE_LIMIT_MAX_KEYS = _env_int(
    "NETRA_RATE_LIMIT_MAX_KEYS",
    10_000,
    minimum=100,
    maximum=100_000,
)


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

GEOIP_ENABLED = _env_bool(
    "NETRA_GEOIP_ENABLED",
    True,
)

AI_ENABLED = _env_bool(
    "NETRA_AI_ENABLED",
    True,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

NETRA_EXTENSION_ID = os.getenv(
    "NETRA_EXTENSION_ID",
    "",
).strip()

if (
    not NETRA_EXTENSION_ID
    and os.getenv("NETRA_DEPLOYMENT_MODE", "local").strip().lower() != "hosted"
):
    from backend.local_extension import detect_unpacked_extension_id

    NETRA_EXTENSION_ID = detect_unpacked_extension_id(BASE_DIR.parent)

NETRA_EXTENSION_ORIGIN = (
    f"chrome-extension://{NETRA_EXTENSION_ID}"
    if NETRA_EXTENSION_ID
    else ""
)

# Hosted NETRA deployments accept the extension's narrow analysis endpoint
# without asking each browser profile for a shared secret. Administrative,
# investigation, evidence, reporting and dashboard routes remain authenticated.
ALLOW_EXTENSION_SUBMISSIONS = _env_bool(
    "NETRA_ALLOW_EXTENSION_SUBMISSIONS",
    os.getenv("NETRA_DEPLOYMENT_MODE", "local").strip().lower() == "hosted",
)

ALLOWED_ORIGINS = _env_origins(
    "NETRA_ALLOWED_ORIGINS",
    (
        "http://localhost:3000,"
        "http://localhost:8000,"
        "http://localhost:8501,"
        "http://127.0.0.1:3000,"
        "http://127.0.0.1:8000,"
        "http://127.0.0.1:8501"
    ),
)

if NETRA_EXTENSION_ORIGIN:
    if NETRA_EXTENSION_ORIGIN not in ALLOWED_ORIGINS:
        ALLOWED_ORIGINS.append(
            NETRA_EXTENSION_ORIGIN
        )


# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

APP_VERSION = "4.8.0"


# ---------------------------------------------------------------------------
# Required local directories
# ---------------------------------------------------------------------------

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

EVIDENCE_STORAGE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# Networked deployments must enable this and inject the secret via a secret
# manager. Local demonstrations retain their frictionless default.
API_AUTH_REQUIRED = _env_bool("NETRA_REQUIRE_API_AUTH", False)
API_ACCESS_KEY = os.getenv("NETRA_API_ACCESS_KEY", "").strip()
