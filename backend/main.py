"""
NETRA-Mail
----------
Local FastAPI backend for NETRA-Mail.

Features:
- Gmail live-extension analysis
- Local .EML analysis
- NLP phishing detection
- Local ML phishing detection
- URL intelligence
- Domain intelligence
- Header authentication analysis
- Optional GeoIP intelligence
- Explainable threat scoring
- Privacy sanitization
- Evidence sealing
- Tamper-evident forensic ledger
- SOC dashboard case retrieval

Run from project root:

    uvicorn backend.main:app --reload --port 8000

"""

import asyncio
import hashlib
import json
import inspect
import ipaddress
import os
import re
import uuid
import logging

from datetime import datetime, timezone
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any, Dict, List

import uvicorn

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel
from backend.security import RequestRateLimiter, validate_identifier, valid_api_key
from backend.access_control import AccessPolicy, Principal
from backend.request_limits import RequestBodyLimit
from backend.audit_context import actor as audit_actor

logger = logging.getLogger("netra")
from backend.deployment_guard import validate_hosted_environment
validate_hosted_environment()
access_policy = AccessPolicy(os.getenv("NETRA_API_IDENTITIES", "[]"))


# ================================================================
# IMPORTS
# ================================================================

try:

    from backend.compliance import IndiaPrivacyPreserver
    from backend.attachment_analyzer import AttachmentAnalyzer

    from backend.config import (
        APP_VERSION,
        DATABASE_PATH,
        GEOIP_ENABLED,
        MAX_EMAIL_SIZE_BYTES,
        MAX_EVIDENCE_SIZE_BYTES,
        EVIDENCE_STORAGE_DIR,
        ALLOWED_ORIGINS,
        MAX_TEXT_SIZE_BYTES,
        RATE_LIMIT_REQUESTS,
        RATE_LIMIT_WINDOW_SECONDS,
        RATE_LIMIT_MAX_KEYS,
        API_AUTH_REQUIRED,
        API_ACCESS_KEY,
        ALLOW_EXTENSION_SUBMISSIONS,
        NETRA_EXTENSION_ORIGIN,
    )

    from backend.database import ForensicLedgerDB
    from backend.decision_engine import DecisionEngine
    from backend.domain_intel import DomainForensics
    from backend.geoip_mapper import GeoIPMapper
    from backend.header_analyzer import HeaderForensicAnalyzer
    from backend.llm_agent import ThreatExplainerAgent
    from backend.ml_classifier import LocalMLClassifier
    from backend.nlp_engine import NLPEngine
    from backend.multilingual_detector import MultilingualLanguageDetector
    from backend.parser import ForensicEmailParser
    from backend.threat_engine import ThreatScoringEngine
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from backend.services.campaign_service import CampaignService
    from backend.services.case_service import CaseService
    from backend.evidence_service import EvidenceService
    from backend.report_service import ReportService
    from backend.intelligence.ip_provider import IPIntelligenceProvider
    from backend.intelligence.domain_provider import DomainIntelligenceProvider

    try:
        from backend.url_analyzer import URLAnalyzer
    except Exception:
        URLAnalyzer = None

    try:
        from backend.evidence import create_evidence_seal
    except Exception:
        create_evidence_seal = None

except ImportError:

    from compliance import IndiaPrivacyPreserver
    from attachment_analyzer import AttachmentAnalyzer

    from config import (
        APP_VERSION,
        DATABASE_PATH,
        GEOIP_ENABLED,
        MAX_EMAIL_SIZE_BYTES,
        MAX_EVIDENCE_SIZE_BYTES,
        EVIDENCE_STORAGE_DIR,
        ALLOWED_ORIGINS,
        MAX_TEXT_SIZE_BYTES,
        RATE_LIMIT_REQUESTS,
        RATE_LIMIT_WINDOW_SECONDS,
        RATE_LIMIT_MAX_KEYS,
        API_AUTH_REQUIRED,
        API_ACCESS_KEY,
        ALLOW_EXTENSION_SUBMISSIONS,
        NETRA_EXTENSION_ORIGIN,
    )

    from database import ForensicLedgerDB
    from decision_engine import DecisionEngine
    from domain_intel import DomainForensics
    from geoip_mapper import GeoIPMapper
    from header_analyzer import HeaderForensicAnalyzer
    from llm_agent import ThreatExplainerAgent
    from ml_classifier import LocalMLClassifier
    from nlp_engine import NLPEngine
    from multilingual_detector import MultilingualLanguageDetector
    from parser import ForensicEmailParser
    from threat_engine import ThreatScoringEngine
    from services.analysis_orchestrator import AnalysisOrchestrator
    from services.campaign_service import CampaignService
    from services.case_service import CaseService
    from evidence_service import EvidenceService
    from report_service import ReportService
    from intelligence.ip_provider import IPIntelligenceProvider
    from intelligence.domain_provider import DomainIntelligenceProvider

    try:
        from url_analyzer import URLAnalyzer
    except Exception:
        URLAnalyzer = None

    try:
        from evidence import create_evidence_seal
    except Exception:
        create_evidence_seal = None


# ================================================================
# REQUEST RATE LIMITING
# ================================================================

rate_limiter = RequestRateLimiter(
    limit=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    max_keys=RATE_LIMIT_MAX_KEYS,
)


def _client_rate_limit_key(request: Request) -> str:
    """Return a stable client key without trusting forwarded headers."""
    identity = getattr(request.state, "principal", None)
    if identity is not None:
        return f"principal:{identity.subject}"
    client = request.client
    if client and client.host:
        return f"ip:{client.host}"
    return "anonymous"


def _enforce_rate_limit(request: Request) -> None:
    """Reject clients that exceed the configured analysis request limit."""
    if getattr(request.state, "rate_limit_checked", False):
        return
    key = _client_rate_limit_key(request)
    if rate_limiter.allow(key):
        return

    raise HTTPException(
        status_code=429,
        detail=(
            "Rate limit exceeded. "
            f"Maximum {RATE_LIMIT_REQUESTS} requests are allowed "
            f"per {RATE_LIMIT_WINDOW_SECONDS} seconds."
        ),
        headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
    )


async def _read_limited_upload(file: UploadFile, maximum_bytes: int) -> bytes:
    """Read an upload in bounded chunks and reject it before memory is exhausted."""
    chunks: list[bytes] = []
    total = 0
    chunk_size = 256 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise HTTPException(status_code=413, detail="Upload exceeds the configured size limit.")
        chunks.append(chunk)
    return b"".join(chunks)


# ================================================================
# APPLICATION
# ================================================================

app = FastAPI(
    title="NETRA-Mail AI Threat Intelligence API",
    description=(
        "Explainable email phishing detection, "
        "forensic analysis, threat intelligence, "
        "privacy protection and tamper-evident evidence."
    ),
    version=str(APP_VERSION),
)


@app.middleware("http")
async def deployment_access_control(request: Request, call_next):
    """Protect investigation data when the service is deployed beyond localhost.

    Set NETRA_REQUIRE_API_AUTH=true and NETRA_API_ACCESS_KEY through the
    deployment secret manager. Health and documentation endpoints remain open
    for monitoring and local API discovery.
    """
    public_paths = {"/health", "/ready"}
    if request.url.path not in public_paths:
        origin = request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return Response(content='{"detail":"Origin not permitted"}', status_code=403, media_type="application/json")
        identity = None
        supplied = request.headers.get("X-NETRA-API-Key", "")
        if access_policy.enabled:
            identity = access_policy.authenticate(supplied)
        elif API_AUTH_REQUIRED and valid_api_key(supplied, API_ACCESS_KEY):
            identity = Principal("deployment-admin", "admin")
        elif not API_AUTH_REQUIRED:
            host = request.client.host if request.client else ""
            # Explicitly local mode. Never infer locality from forwarded headers.
            if host in {"127.0.0.1", "::1", "testclient"}:
                identity = Principal("local-operator", "admin")
        if (
            identity is None
            and ALLOW_EXTENSION_SUBMISSIONS
            and NETRA_EXTENSION_ORIGIN
            and origin == NETRA_EXTENSION_ORIGIN
            and request.method == "POST"
            and request.url.path == "/api/v2/mailbox/analyze"
        ):
            identity = Principal("gmail-extension", "submitter")
        if identity is not None and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            request.state.principal = identity
            try:
                _enforce_rate_limit(request)
            except HTTPException as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
            request.state.rate_limit_checked = True
        if identity is None:
            return Response(
                content='{"detail":"Authentication required"}',
                status_code=401,
                media_type="application/json",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if not access_policy.allowed(identity, request.method, request.url.path):
            return Response(content='{"detail":"Insufficient permissions"}', status_code=403, media_type="application/json")
        if identity.role == "submitter" and request.method == "GET" and request.url.path.startswith("/api/v2/emails/"):
            email_id = request.url.path.strip("/").split("/")[3]
            if db.analysis_owner(email_id) != identity.subject:
                return Response(content='{"detail":"Email analysis was not found"}', status_code=404, media_type="application/json")
        request.state.principal = identity
    context_token = audit_actor.set(getattr(getattr(request.state, "principal", None), "subject", "anonymous"))
    try:
        response = await call_next(request)
    finally:
        audit_actor.reset(context_token)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ================================================================
# CORS
# ================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestBodyLimit, maximum_bytes=max(MAX_EMAIL_SIZE_BYTES, MAX_EVIDENCE_SIZE_BYTES) + 65536)


# ================================================================
# GLOBAL COMPONENTS
# ================================================================

parser = ForensicEmailParser()
v2_orchestrator = AnalysisOrchestrator(parser)
v2_results = {}
ip_intelligence_provider = IPIntelligenceProvider()
domain_intelligence_provider = DomainIntelligenceProvider()

try:
    db = ForensicLedgerDB(DATABASE_PATH)
except TypeError:
    db = ForensicLedgerDB()

campaign_service = CampaignService(db)
case_service = CaseService(db)
evidence_service = EvidenceService(db, str(EVIDENCE_STORAGE_DIR))
report_service = ReportService(db, evidence_service, str(EVIDENCE_STORAGE_DIR))


# ================================================================
# REQUEST MODEL
# ================================================================

class EmailAnalysisRequest(BaseModel):

    subject: str = ""

    sender: str = ""

    recipient: str = ""

    reply_to: str = ""

    body: str = ""

    html: str = ""

    headers: str = ""

    received_headers: str = ""


class V2TextAnalysisRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    reply_to: str = ""
    body: str = ""
    html: str = ""
    headers: str = ""


class CampaignRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None


class CaseRequest(BaseModel):
    title: str
    description: str = ""
    status: str = "open"
    severity: str = "medium"
    priority: str = "normal"
    analyst: str = "analyst"


class CaseUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    priority: str | None = None
    analyst: str | None = None


class NoteRequest(BaseModel):
    note: str
    actor: str = "analyst"


class TagRequest(BaseModel):
    tag: str


class CaseEmailRequest(BaseModel):
    email_id: str


def _build_v2_message(request: V2TextAnalysisRequest) -> bytes:
    message = EmailMessage()
    for key, value in {
        "Subject": request.subject,
        "From": request.sender,
        "To": request.recipient,
        "Reply-To": request.reply_to,
    }.items():
        if value:
            message[key] = value
    for line in request.headers.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() not in {"subject", "from", "to", "reply-to"} and key.strip():
            message[key.strip()] = value.strip()
    message.set_content(request.body or "")
    if request.html:
        message.add_alternative(request.html, subtype="html")
    return message.as_bytes()


# ================================================================
# GENERAL HELPERS
# ================================================================

def _now_iso() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


def _normalize_score(
    value: Any,
) -> int:

    try:

        return max(
            0,
            min(
                100,
                int(
                    round(
                        float(value)
                    )
                ),
            ),
        )

    except Exception:

        return 0


def _extract_domain(
    value: str,
) -> str:

    if not value:

        return ""

    match = re.search(
        r"@([A-Za-z0-9.-]+)",
        str(value),
    )

    if not match:

        return ""

    return (
        match.group(1)
        .lower()
        .strip(".")
    )


def _combine_email_text(
    subject: str = "",
    sender: str = "",
    body: str = "",
    html: str = "",
) -> str:

    return (
        f"{subject}\n"
        f"{sender}\n"
        f"{body}\n"
        f"{html}"
    ).strip()


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        if data and data.strip():
            self.parts.append(data.strip())


def _visible_html_text(html: str) -> str:
    from backend.parser import ForensicEmailParser
    return ForensicEmailParser._extract_html_details(html or "")["visible_text"]


def _safe_text_from_parsed(
    parsed: Dict[str, Any],
) -> str:

    body = parsed.get(
        "body",
        {},
    ) or {}

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    return _combine_email_text(
        subject=str(
            metadata.get(
                "subject",
                "",
            )
        ),
        sender=str(
            metadata.get(
                "from",
                "",
            )
        ),
        body=str(
            body.get(
                "plain",
                "",
            )
        ),
        html=str(
            _visible_html_text(body.get("html", ""))
        ),
    )


# ================================================================
# DOMAIN EXTRACTION
# ================================================================

def _extract_domains(
    parsed: Dict[str, Any],
) -> List[Dict[str, str]]:

    domains = []

    seen = set()

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    sources = [

        (
            metadata.get(
                "from",
                "",
            ),
            "from",
        ),

        (
            metadata.get(
                "reply_to",
                "",
            ),
            "reply_to",
        ),

        (
            metadata.get(
                "return_path",
                "",
            ),
            "return_path",
        ),

    ]

    for value, source in sources:

        domain = _extract_domain(
            value
        )

        if (
            domain
            and domain not in seen
        ):

            seen.add(domain)

            domains.append(
                {
                    "domain": domain,
                    "source": source,
                }
            )

    # ------------------------------------------------------------
    # URL HOSTNAMES
    # ------------------------------------------------------------

    try:

        from urllib.parse import urlparse

        for url in parsed.get(
            "urls",
            [],
        ) or []:

            try:

                hostname = (
                    urlparse(
                        str(url)
                    ).hostname
                    or ""
                ).lower()

                if (
                    hostname
                    and hostname not in seen
                ):

                    seen.add(hostname)

                    domains.append(
                        {
                            "domain": hostname,
                            "source": "url",
                        }
                    )

            except Exception:

                continue

    except Exception:

        pass

    # ------------------------------------------------------------
    # RECEIVED HOSTNAMES
    # ------------------------------------------------------------

    for hop in parsed.get(
        "network_chain",
        [],
    ) or []:

        raw_header = str(
            hop.get(
                "raw_header",
                "",
            )
        )

        matches = re.findall(
            r"\bfrom\s+([A-Za-z0-9._-]+)",
            raw_header,
            flags=re.IGNORECASE,
        )

        for hostname in matches:

            hostname = (
                hostname
                .lower()
                .strip(".")
            )

            if re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}",
                hostname,
            ):

                continue

            if (
                hostname
                and "." in hostname
                and hostname not in seen
            ):

                seen.add(hostname)

                domains.append(
                    {
                        "domain": hostname,
                        "source": "received",
                    }
                )

    return domains


# ================================================================
# NLP
# ================================================================

def _build_nlp_result(
    text: str,
) -> Dict[str, Any]:

    try:

        raw = NLPEngine.analyze_text(
            text or ""
        )

    except Exception as exc:

        return {

            "score": 0,

            "categories": {
                "urgency": [],
                "financial_fraud": [],
                "credential_harvesting": [],
                "social_engineering": [],
            },

            "matched_indicator_count": 0,

            "attack_classification": [],

            "risk_level": "LOW",

            "error": type(exc).__name__,

        }

    raw = raw or {}

    # ------------------------------------------------------------
    # INDIA-FIRST MULTILINGUAL ANALYSIS
    # ------------------------------------------------------------
    try:
        multilingual = MultilingualLanguageDetector.analyze(text or "")
    except Exception as exc:
        multilingual = {
            "language": "Unknown",
            "language_code": "und",
            "language_confidence": 0.0,
            "script": "unknown",
            "is_multilingual": False,
            "detection_method": "error",
            "detected_scripts": [],
            "multilingual_findings": {},
            "multilingual_score": 0,
            "error": type(exc).__name__,
        }

    def get_category(
        primary: str,
        alternate: str,
    ) -> List[str]:

        value = raw.get(
            primary,
            raw.get(
                alternate,
                [],
            ),
        )

        if not isinstance(
            value,
            list,
        ):

            return []

        return sorted(
            set(
                str(x)
                for x in value
                if x
            )
        )

    raw_categories = raw.get("categories", raw)
    if not isinstance(raw_categories, dict):
        raw_categories = {}

    def get_raw_category(primary: str, alternate: str):
        value = raw_categories.get(primary, raw_categories.get(alternate, []))
        return value if isinstance(value, list) else []

    urgency = get_raw_category(
        "urgency",
        "urgency_cues",
    )

    financial = get_raw_category(
        "financial_fraud",
        "financial_fraud_cues",
    )

    credentials = get_raw_category(
        "credential_harvesting",
        "credential_harvesting_cues",
    )

    social = get_raw_category(
        "social_engineering",
        "social_engineering_cues",
    )

    categories = {

        "urgency":
            urgency,

        "financial_fraud":
            financial,

        "credential_harvesting":
            credentials,

        "social_engineering":
            social,

    }

    engine_score = raw.get(
        "score",
        None,
    )

    if engine_score is not None:

        score = _normalize_score(
            engine_score
        )

    else:

        score = 0

        score += min(
            25,
            len(urgency) * 5,
        )

        score += min(
            30,
            len(financial) * 7,
        )

        score += min(
            30,
            len(credentials) * 7,
        )

        score += min(
            20,
            len(social) * 5,
        )

        score = min(
            100,
            score,
        )

    # Merge language-specific findings into the existing explainable NLP model.
    multilingual_score = _normalize_score(multilingual.get("multilingual_score", 0))
    multilingual_findings = multilingual.get("multilingual_findings", {})
    if not isinstance(multilingual_findings, dict):
        multilingual_findings = {}

    for category_name, values in multilingual_findings.items():
        if category_name not in categories or not isinstance(values, list):
            continue
        categories[category_name] = sorted(set(
            categories[category_name] + [str(value) for value in values if value]
        ))

    urgency = categories["urgency"]
    financial = categories["financial_fraud"]
    credentials = categories["credential_harvesting"]
    social = categories["social_engineering"]
    score = max(score, multilingual_score)

    normalized_text = text.lower()
    legitimate_reset_context = (
        "if you did not request" in normalized_text
        or "if you didn't request" in normalized_text
        or "if this was not you" in normalized_text
        or "if this wasn't you" in normalized_text
        or "if not, ignore" in normalized_text
        or "please ignore this email" in normalized_text
    )
    if legitimate_reset_context and not financial:
        score = min(score, 24)

    attack_classification = []

    if financial:

        attack_classification.append(
            "Financial Fraud / BEC"
        )

    if credentials:

        attack_classification.append(
            "Credential Phishing"
        )

    if social:

        attack_classification.append(
            "Social Engineering"
        )

    if (
        urgency
        and not attack_classification
    ):

        attack_classification.append(
            "Social Engineering"
        )

    matched_count = sum(
        len(values)
        for values in categories.values()
    )

    engine_risk = raw.get(
        "risk_level"
    )

    if engine_risk:

        risk_level = str(
            engine_risk
        ).upper()

    else:

        if score >= 60:

            risk_level = "HIGH"

        elif score >= 30:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

    return {

        "score":
            score,

        "categories":
            categories,

        "matched_indicator_count":
            matched_count,

        "attack_classification":
            list(
                dict.fromkeys(
                    attack_classification
                )
            ),

        "risk_level":
            risk_level,

        "language":
            multilingual.get("language", "Unknown"),
        "language_code":
            multilingual.get("language_code", "und"),
        "language_confidence":
            multilingual.get("language_confidence", 0.0),
        "script":
            multilingual.get("script", "unknown"),
        "is_multilingual":
            bool(multilingual.get("is_multilingual", False)),
        "detection_method":
            multilingual.get("detection_method", "unknown"),
        "detected_scripts":
            multilingual.get("detected_scripts", []),
        "multilingual_findings":
            multilingual_findings,
        "multilingual_score":
            multilingual_score,

        "raw_findings":
            raw,

    }


# ================================================================
# ML
# ================================================================

def _build_ml_result(
    text: str,
) -> Dict[str, Any]:

    try:

        raw = LocalMLClassifier.predict(
            text or ""
        )

    except Exception as exc:

        return {

            "classification":
                "UNKNOWN",

            "phishing_probability":
                0.0,

            "confidence":
                0.0,

            "model":
                "unavailable",

            "training_source":
                "error",

            "error":
                type(exc).__name__,

        }

    raw = raw or {}

    classification = str(
        raw.get(
            "ml_classification",
            raw.get(
                "classification",
                "UNKNOWN",
            ),
        )
    ).upper()

    confidence = raw.get(
        "confidence_score",
        raw.get(
            "confidence",
            0,
        ),
    )

    try:

        confidence = float(
            confidence
        )

    except Exception:

        confidence = 0.0

    confidence = max(
        0.0,
        min(
            100.0,
            confidence,
        ),
    )

    probability = raw.get(
        "phishing_probability",
        None,
    )

    if probability is not None:

        try:

            probability = float(
                probability
            )

        except Exception:

            probability = None

    if probability is None:

        if classification == "PHISHING":

            probability = (
                confidence / 100.0
            )

        else:

            probability = (
                1.0
                - confidence / 100.0
            )

    probability = max(
        0.0,
        min(
            1.0,
            probability,
        ),
    )

    return {

        "classification":
            classification,

        "phishing_probability":
            round(
                probability,
                4,
            ),

        "confidence":
            round(
                confidence,
                2,
            ),

        "model":
            raw.get(
                "model",
                "Local TF-IDF classifier",
            ),

        "training_source":
            raw.get(
                "training_source",
                "local trained model",
            ),

    }


# ================================================================
# DOMAIN INTELLIGENCE
# ================================================================

def _normalize_internal_domain_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Keep private/loopback IPs out of ordinary domain intelligence.

    URL analysis is the authoritative detector for SSRF-style destinations;
    domain intelligence should classify these hosts consistently instead of
    treating 127.0.0.1 (or another special IP) as a normal resolving domain.
    """
    if not isinstance(result, dict):
        return result

    domains = result.get("domains", [])
    if not isinstance(domains, list):
        return result

    highest = 0
    global_reasons = list(result.get("reasons", []) or [])

    for item in domains:
        if not isinstance(item, dict):
            continue
        host = str(item.get("domain", "")).strip().strip("[]")
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue

        item["is_ip_address"] = True
        item["is_private_ip"] = addr.is_private
        item["is_loopback"] = addr.is_loopback
        item["is_link_local"] = addr.is_link_local
        item["is_reserved_ip"] = addr.is_reserved
        item["is_multicast"] = addr.is_multicast
        item["is_unspecified_ip"] = addr.is_unspecified
        item["registered_domain"] = host

        special = (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
        if special:
            item["risk_score"] = max(_normalize_score(item.get("risk_score", 0)), 80)
            item["risk_level"] = "CRITICAL"
            item["resolves"] = False
            item["resolved_ip"] = None
            reasons = list(item.get("reasons", []) or [])
            reason = "Special-use/private IP destination; not a public domain."
            if reason not in reasons:
                reasons.append(reason)
            item["reasons"] = reasons
            if reason not in global_reasons:
                global_reasons.append(reason)
            highest = max(highest, 80)
        else:
            highest = max(highest, _normalize_score(item.get("risk_score", 0)))

    if highest >= 70:
        result["highest_risk_score"] = highest
        result["overall_risk"] = "CRITICAL"
    elif highest >= 50:
        result["highest_risk_score"] = highest
        result["overall_risk"] = "HIGH"
    elif highest >= 30:
        result["highest_risk_score"] = highest
        result["overall_risk"] = "MEDIUM"
    else:
        result["highest_risk_score"] = highest
        result["overall_risk"] = "LOW"

    result["reasons"] = global_reasons
    return result


def _build_domain_result(
    parsed: Dict[str, Any],
) -> Dict[str, Any]:

    domains = _extract_domains(
        parsed
    )

    # ------------------------------------------------------------
    # Dedicated domain engine
    # ------------------------------------------------------------

    if hasattr(
        DomainForensics,
        "inspect_domains",
    ):

        try:

            result = (
                DomainForensics.inspect_domains(
                    domains
                )
            )

            if isinstance(
                result,
                dict,
            ):

                return _normalize_internal_domain_result(result)

        except Exception:

            pass

    inspected = []

    for item in domains:

        domain = item.get(
            "domain",
            "",
        )

        if not domain:

            continue

        try:

            results = (
                DomainForensics.inspect_urls(
                    [
                        f"https://{domain}"
                    ]
                )
            )

            if results:

                result = results[0]

                analysis = result.get(
                    "analysis",
                    {},
                ) or {}

                risk_score = _normalize_score(
                    analysis.get(
                        "risk_score",
                        0,
                    )
                )

                if risk_score >= 70:

                    risk_level = "CRITICAL"

                elif risk_score >= 50:

                    risk_level = "HIGH"

                elif risk_score >= 30:

                    risk_level = "MEDIUM"

                else:

                    risk_level = "LOW"

                impersonated_brand = (
                    analysis.get(
                        "impersonated_brand"
                    )
                )

                inspected.append(
                    {

                        "domain":
                            domain,

                        "source":
                            item.get(
                                "source",
                                "unknown",
                            ),

                        "valid":
                            True,

                        "registered_domain":
                            domain,

                        "is_punycode":
                            analysis.get(
                                "is_punycode",
                                False,
                            ),

                        "has_suspicious_tld":
                            analysis.get(
                                "has_suspicious_tld",
                                False,
                            ),

                        "impersonated_brand":
                            impersonated_brand,

                        "impersonated_brands":
                            (
                                [impersonated_brand]
                                if impersonated_brand
                                else []
                            ),

                        "typosquatting":
                            analysis.get(
                                "typosquatting",
                                [],
                            ),

                        "resolves":
                            analysis.get(
                                "resolves",
                                False,
                            ),

                        "resolved_ip":
                            analysis.get(
                                "resolved_ip"
                            ),

                        "risk_score":
                            risk_score,

                        "risk_level":
                            risk_level,

                        "reasons":
                            analysis.get(
                                "reasons",
                                [],
                            ),

                    }
                )

        except Exception as exc:

            inspected.append(
                {

                    "domain":
                        domain,

                    "source":
                        item.get(
                            "source",
                            "unknown",
                        ),

                    "valid":
                        True,

                    "risk_score":
                        0,

                    "risk_level":
                        "LOW",

                    "reasons":
                        [
                            (
                                "Domain analysis "
                                f"unavailable: "
                                f"{type(exc).__name__}"
                            )
                        ],

                }
            )

    highest = max(
        (
            item.get(
                "risk_score",
                0,
            )
            for item in inspected
        ),
        default=0,
    )

    brands = []

    typosquatting = []

    reasons = []

    for item in inspected:

        brand = item.get(
            "impersonated_brand"
        )

        if (
            brand
            and brand not in brands
        ):

            brands.append(
                brand
            )

        for brand_item in item.get(
            "impersonated_brands",
            [],
        ) or []:

            if (
                brand_item
                and brand_item not in brands
            ):

                brands.append(
                    brand_item
                )

        for typo in item.get(
            "typosquatting",
            [],
        ) or []:

            if typo not in typosquatting:

                typosquatting.append(
                    typo
                )

        for reason in item.get(
            "reasons",
            [],
        ) or []:

            if reason not in reasons:

                reasons.append(
                    reason
                )

    if highest >= 70:

        overall_risk = "CRITICAL"

    elif highest >= 50:

        overall_risk = "HIGH"

    elif highest >= 30:

        overall_risk = "MEDIUM"

    else:

        overall_risk = "LOW"

    return {

        "total_domains":
            len(domains),

        "highest_risk_score":
            highest,

        "overall_risk":
            overall_risk,

        "impersonated_brands":
            brands,

        "typosquatting_detected":
            typosquatting,

        "reasons":
            reasons,

        "domains":
            inspected,

    }


# ================================================================
# URL INTELLIGENCE
# ================================================================

def _build_url_result(
    parsed: Dict[str, Any],
) -> Dict[str, Any]:

    urls = parsed.get(
        "urls",
        [],
    ) or []

    body = parsed.get(
        "body",
        {},
    ) or {}

    combined_text = (

        str(
            body.get(
                "plain",
                "",
            )
        )

        + "\n"

        + str(
            body.get(
                "html",
                "",
            )
        )

    )

    if URLAnalyzer is not None:

        try:

            result = (
                URLAnalyzer.analyze_text(
                    combined_text
                )
            )

            if isinstance(
                result,
                dict,
            ):

                if (
                    result.get(
                        "total_urls",
                        0,
                    ) > 0
                    or not urls
                ):

                    if os.getenv("NETRA_EXPAND_SHORT_URLS", "0") == "1":
                        from backend.url_expander import URLExpander

                        expansions = []
                        for item in result.get("urls", []):
                            if not item.get("is_shortener"):
                                continue
                            expansion = URLExpander.expand(item.get("url", ""))
                            expansions.append(expansion)
                            final_url = expansion.get("final_url", "")
                            if expansion.get("expanded") and final_url:
                                final_analysis = URLAnalyzer.analyze_url(final_url)
                                item["expanded_url"] = final_url
                                item["redirect_chain"] = expansion.get("redirect_chain", [])
                                item["expanded_analysis"] = final_analysis
                                item["risk_score"] = max(
                                    item.get("risk_score", 0),
                                    final_analysis.get("risk_score", 0),
                                )
                            else:
                                item["expansion_error"] = expansion.get("error", "not_expanded")
                        result["url_expansions"] = expansions
                        if expansions:
                            result["summary"]["reasons"].append(
                                "Shortened URL expansion was attempted with bounded HEAD requests"
                            )

                    return result

        except Exception:

            pass

    try:

        inspected = (
            DomainForensics.inspect_urls(
                urls
            )
        )

    except Exception:

        inspected = []

    highest = max(
        (
            item.get(
                "analysis",
                {},
            ).get(
                "risk_score",
                0,
            )
            for item in inspected
            if isinstance(
                item,
                dict,
            )
        ),
        default=0,
    )

    brands = []

    typosquatting = []

    for item in inspected:

        analysis = item.get(
            "analysis",
            {},
        ) or {}

        brand = analysis.get(
            "impersonated_brand"
        )

        if brand:

            brands.append(
                str(brand)
            )

        typo = analysis.get(
            "typosquatting",
            [],
        )

        if isinstance(
            typo,
            list,
        ):

            typosquatting.extend(
                typo
            )

    if highest >= 70:

        overall_risk = "CRITICAL"

    elif highest >= 50:

        overall_risk = "HIGH"

    elif highest >= 30:

        overall_risk = "MEDIUM"

    else:

        overall_risk = "LOW"

    return {

        "total_urls":
            len(inspected),

        "urls":
            inspected,

        "summary": {

            "suspicious_urls":
                sum(
                    1
                    for item in inspected
                    if item.get(
                        "analysis",
                        {},
                    ).get(
                        "risk_score",
                        0,
                    ) >= 30
                ),

            "highest_url_score":
                highest,

            "impersonated_brands":
                list(
                    dict.fromkeys(
                        brands
                    )
                ),

            "typosquatting_detected":
                list(
                    dict.fromkeys(
                        typosquatting
                    )
                ),

            "overall_risk":
                overall_risk,

        },

    }


# ================================================================
# GEOIP / INFRASTRUCTURE
# ================================================================

def _get_infrastructure(
    parsed: Dict[str, Any],
    authentication: Dict[str, Any],
    enabled: bool = True,
) -> Dict[str, Any]:

    origin_ip = authentication.get(
        "originating_ip"
    )

    if not origin_ip:

        chain = parsed.get(
            "network_chain",
            [],
        ) or []

        if chain:

            origin_ip = chain[0].get(
                "originating_ip"
            )

    base = {

        "ip":
            origin_ip,

        "available":
            False,

        "country":
            "Unknown",

        "city":
            "Unknown",

        "latitude":
            0.0,

        "longitude":
            0.0,

        "isp":
            "Unknown",

        "organization":
            "Unknown",

        "asn":
            "Unknown",

        "timezone":
            "Unknown",

        "is_cloud_vps":
            False,

    }

    if not origin_ip:

        return base

    if (
        not enabled
        or not GEOIP_ENABLED
    ):

        return base

    try:

        intel = GeoIPMapper.get_ip_intel(
            origin_ip
        )

        if intel:

            return intel

    except Exception:

        pass

    return base


# ================================================================
# EVIDENCE
# ================================================================

def _build_evidence(
    header: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    url: Dict[str, Any],
    infrastructure: Dict[str, Any],
    decision: Dict[str, Any],
) -> List[str]:

    evidence = []

    # ------------------------------------------------------------
    # DOMAIN
    # ------------------------------------------------------------

    for brand in domain.get(
        "impersonated_brands",
        [],
    ) or []:

        evidence.append(
            f"Brand impersonation: {brand}"
        )

    for reason in domain.get(
        "reasons",
        [],
    ) or []:

        evidence.append(
            str(reason)
        )

    # ------------------------------------------------------------
    # URL
    # ------------------------------------------------------------

    url_summary = (
        url.get(
            "summary",
            {},
        )
        or {}
    )

    if url_summary.get(
        "suspicious_urls",
        0,
    ):

        evidence.append(
            "Suspicious URLs detected: "
            + str(
                url_summary.get(
                    "suspicious_urls",
                    0,
                )
            )
        )

    for brand in url_summary.get(
        "impersonated_brands",
        [],
    ) or []:

        evidence.append(
            f"URL brand impersonation: {brand}"
        )

    # ------------------------------------------------------------
    # NLP
    # ------------------------------------------------------------

    categories = (
        nlp.get(
            "categories",
            {},
        )
        or {}
    )

    for category_name, values in categories.items():

        if not isinstance(
            values,
            list,
        ):

            continue

        for value in values:

            evidence.append(
                (
                    f"{category_name.replace('_', ' ').title()}: "
                    f"{value}"
                )
            )

    if nlp.get("multilingual_score", 0):
        evidence.append(
            f"Multilingual analysis: {nlp.get('language', 'Unknown')} "
            f"({nlp.get('script', 'unknown')}) score "
            f"{nlp.get('multilingual_score', 0)}/45."
        )

    # ------------------------------------------------------------
    # ML
    # ------------------------------------------------------------

    classification = str(
        ml.get(
            "classification",
            "",
        )
    ).upper()

    probability = ml.get(
        "phishing_probability"
    )

    if classification == "PHISHING":

        evidence.append(
            "ML classifier identified phishing."
        )

        if probability is not None:

            try:

                evidence.append(
                    "ML phishing probability is "
                    f"{float(probability) * 100:.1f}%."
                )

            except Exception:

                pass

    # ------------------------------------------------------------
    # AUTHENTICATION
    # ------------------------------------------------------------

    authentication = (
        header.get(
            "authentication",
            {},
        )
        or {}
    )

    for auth_name in [
        "spf",
        "dkim",
        "dmarc",
    ]:

        status = str(
            authentication.get(
                auth_name,
                "none",
            )
        ).upper()

        if status in {
            "NONE",
            "FAIL",
            "SOFTFAIL",
        }:

            evidence.append(
                f"{auth_name.upper()} "
                f"authentication result: {status}"
            )

    # ------------------------------------------------------------
    # HEADER INDICATORS
    # ------------------------------------------------------------

    for indicator in header.get(
        "indicators",
        [],
    ) or []:

        evidence.append(
            str(indicator)
        )

    # ------------------------------------------------------------
    # INFRASTRUCTURE
    # ------------------------------------------------------------

    if infrastructure.get(
        "ip"
    ):

        evidence.append(
            "Originating IP: "
            + str(
                infrastructure.get(
                    "ip"
                )
            )
        )

    if infrastructure.get(
        "is_cloud_vps",
        False,
    ):

        evidence.append(
            "Origin infrastructure appears "
            "to use cloud/VPS hosting."
        )

    # ------------------------------------------------------------
    # DECISION
    # ------------------------------------------------------------

    for reason in decision.get(
        "reasons",
        [],
    ) or []:

        evidence.append(
            str(reason)
        )

    return list(
        dict.fromkeys(
            evidence
        )
    )


# ================================================================
# EVIDENCE SEAL
# ================================================================

def _create_seal(
    raw: bytes,
    evidence: List[str],
) -> Dict[str, Any]:

    if create_evidence_seal is not None:

        try:

            result = create_evidence_seal(
                raw
            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except Exception:

            pass

    evidence_bytes = (
        "\n".join(
            evidence
        ).encode(
            "utf-8",
            errors="ignore",
        )
    )

    return {

        "sha256_hash":
            hashlib.sha256(
                evidence_bytes
            ).hexdigest(),

        "byte_size":
            len(
                evidence_bytes
            ),

        "sealed_at":
            _now_iso(),

        "encoding":
            "utf-8",

    }


# ================================================================
# THREAT SCORING
# ================================================================

def _is_high_confidence_ssrf_destination(analysis: Dict[str, Any]) -> bool:
    """Identify explicit special-use targets without blocking normal intranets."""
    if not isinstance(analysis, dict) or not analysis.get("ssrf_risk"):
        return False
    hostname = str(analysis.get("hostname", "")).strip().lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    return any(
        bool(analysis.get(flag))
        for flag in (
            "is_private_ip", "is_loopback", "is_link_local", "is_reserved_ip",
            "is_multicast", "is_unspecified_ip",
        )
    )

def _apply_ssrf_scoring_override(
    result: Dict[str, Any],
    url: Dict[str, Any],
) -> Dict[str, Any]:
    """Promote explicit internal-destination URL findings into the verdict.

    A weighted average can otherwise dilute a critical SSRF signal (for
    example ML=48 + URL=79 produced only 20/100). An explicit loopback/private
    destination is therefore treated as a strong independent security signal.
    """
    if not isinstance(result, dict) or not isinstance(url, dict):
        return result

    urls = url.get("urls", []) or []
    ssrf_items = []
    for item in urls:
        analysis = item.get("analysis", item) if isinstance(item, dict) else {}
        if _is_high_confidence_ssrf_destination(analysis):
            ssrf_items.append(analysis)

    if not ssrf_items:
        return result

    highest = max(_normalize_score(x.get("risk_score", 0)) for x in ssrf_items)
    # Explicit special-use destination: do not allow a low weighted average
    # to classify the message as SAFE.
    floor = 75 if highest >= 70 else 60
    current = _normalize_score(result.get("threat_score", result.get("score", 0)))
    final_score = max(current, floor)

    findings = list(result.get("correlation_findings", []) or [])
    finding = "Internal/private URL destination detected; SSRF-style targeting signal."
    if finding not in findings:
        findings.append(finding)

    classifications = list(result.get("attack_classification", []) or [])
    if "SSRF / internal resource targeting" not in classifications:
        classifications.append("SSRF / internal resource targeting")

    result["threat_score"] = final_score
    result["score"] = final_score
    result["severity"] = "CRITICAL" if final_score >= 75 else "HIGH"
    result["risk_level"] = result["severity"]
    result["correlation_bonus"] = max(_normalize_score(result.get("correlation_bonus", 0)), 40)
    result["correlation_findings"] = findings
    result["attack_classification"] = classifications
    result["active_strong_signals"] = max(_normalize_score(result.get("active_strong_signals", 0)), 1)

    # Confidence should reflect that the strong signal is explicit, not just
    # an averaged heuristic. Keep existing confidence if it is already high.
    result["confidence"] = max(_normalize_score(result.get("confidence", 0)), 85)
    return result


def _apply_attachment_scoring_override(
    result: Dict[str, Any],
    attachments: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Ensure high-confidence static attachment findings affect the verdict.

    Keeps the normal weighted engine, but prevents a dangerous executable or
    macro attachment from being diluted into a SAFE result. Attachments are
    analyzed statically only; no file is executed.
    """
    if not isinstance(result, dict) or not isinstance(attachments, dict):
        return result

    highest = _normalize_score(attachments.get("score", 0))
    if highest <= 0:
        return result

    current = _normalize_score(result.get("threat_score", result.get("score", 0)))
    # Critical/high-risk attachment evidence is an independent strong signal.
    if highest >= 90:
        floor = 80
    elif highest >= 75:
        floor = 75
    elif highest >= 50:
        floor = 55
    else:
        floor = 35

    final_score = max(current, floor if attachments.get("suspicious_attachment_count", 0) else current)
    result["threat_score"] = final_score
    result["score"] = final_score
    result["severity"] = (
        "CRITICAL" if final_score >= 75 else
        "HIGH" if final_score >= 50 else
        "MEDIUM" if final_score >= 25 else "SAFE"
    )
    result["risk_level"] = result["severity"]

    findings = list(result.get("correlation_findings", []) or [])
    for finding in attachments.get("findings", []) or []:
        if finding not in findings:
            findings.append(finding)
    result["correlation_findings"] = findings

    classifications = list(result.get("attack_classification", []) or [])
    if highest >= 75 and "Malware Delivery / Dangerous Attachment" not in classifications:
        classifications.append("Malware Delivery / Dangerous Attachment")
    result["attack_classification"] = classifications
    result["active_strong_signals"] = max(
        _normalize_score(result.get("active_strong_signals", 0)),
        1 if highest >= 35 else 0,
    )
    if highest >= 75:
        result["confidence"] = max(_normalize_score(result.get("confidence", 0)), 85)
    return result


def _apply_multilingual_scoring_signal(
    result: Dict[str, Any],
    nlp: Dict[str, Any],
) -> Dict[str, Any]:
    """Preserve meaningful multilingual threat evidence in final scoring."""
    if not isinstance(result, dict) or not isinstance(nlp, dict):
        return result

    multilingual_score = _normalize_score(nlp.get("multilingual_score", 0))
    if multilingual_score < 25:
        return result

    current = _normalize_score(result.get("threat_score", result.get("score", 0)))
    final_score = max(current, multilingual_score)
    result["threat_score"] = final_score
    result["score"] = final_score
    result["severity"] = (
        "CRITICAL" if final_score >= 75 else
        "HIGH" if final_score >= 50 else
        "MEDIUM" if final_score >= 30 else
        "LOW"
    )
    result["risk_level"] = result["severity"]

    findings = list(result.get("correlation_findings", []) or [])
    reason = f"Multilingual threat cues detected in {nlp.get('language', 'Unknown')} content."
    if reason not in findings:
        findings.append(reason)
    result["correlation_findings"] = findings

    classifications = list(result.get("attack_classification", []) or [])
    for label in nlp.get("attack_classification", []) or []:
        if label not in classifications:
            classifications.append(label)
    result["attack_classification"] = classifications
    result["multilingual_signal"] = multilingual_score
    result["active_strong_signals"] = max(_normalize_score(result.get("active_strong_signals", 0)), 1)
    return result


def _run_threat_scoring(
    authentication: Dict[str, Any],
    url: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    infrastructure: Dict[str, Any],
    attachments: Dict[str, Any] = None,
) -> Dict[str, Any]:

    evaluate = getattr(
        ThreatScoringEngine,
        "evaluate",
        None,
    )

    if evaluate is None:

        return {

            "threat_score":
                0,

            "score":
                0,

            "severity":
                "SAFE",

            "confidence":
                0,

        }

    # ------------------------------------------------------------
    # Current engine
    # ------------------------------------------------------------

    try:

        signature = inspect.signature(
            evaluate
        )

        parameters = signature.parameters

        if "header_res" in parameters:

            result = evaluate(

                header_res=
                    authentication,

                url_res=
                    url,

                nlp_res=
                    nlp,

                ml_res=
                    ml,

                domain_res=
                    domain,

                infrastructure=
                    infrastructure,

                attachment_res=
                    attachments or {},

            )

            if isinstance(
                result,
                dict,
            ):

                return _apply_ssrf_scoring_override(result, url)

    except Exception:

        pass

    # ------------------------------------------------------------
    # Legacy positional engine
    # ------------------------------------------------------------

    try:

        nlp_score = (
            _normalize_score(
                nlp.get(
                    "score",
                    0,
                )
            )
            / 100.0
        )

        ml_score = ml.get(
            "phishing_probability",
            0,
        )

        try:

            ml_score = float(
                ml_score
            )

        except Exception:

            ml_score = 0.0

        result = evaluate(

            authentication,

            url.get(
                "urls",
                [],
            ),

            nlp_score,

            ml_score,

        )

        if isinstance(
            result,
            dict,
        ):

            return _apply_ssrf_scoring_override(result, url)

    except Exception:

        pass

    # ------------------------------------------------------------
    # Modern keyword engine
    # ------------------------------------------------------------

    try:

        result = evaluate(

            ml=
                ml,

            nlp=
                nlp,

            url=
                url,

            domain=
                domain,

            authentication=
                authentication,

            infrastructure=
                infrastructure,

        )

        if isinstance(
            result,
            dict,
        ):

            return _apply_ssrf_scoring_override(result, url)

    except Exception as exc:

        return {

            "threat_score":
                0,

            "score":
                0,

            "severity":
                "SAFE",

            "confidence":
                0,

            "error":
                type(exc).__name__,

        }

    return {

        "threat_score":
            0,

        "score":
            0,

        "severity":
            "SAFE",

        "confidence":
            0,

    }


# ================================================================
# DECISION ENGINE
# ================================================================

def _apply_ssrf_decision_override(
    decision: Dict[str, Any],
    scoring: Dict[str, Any],
    url: Dict[str, Any],
) -> Dict[str, Any]:
    """Ensure the final action cannot downgrade an explicit SSRF signal."""
    decision = decision if isinstance(decision, dict) else {}
    urls = url.get("urls", []) if isinstance(url, dict) else []
    has_ssrf = any(
        isinstance(item, dict)
        and _is_high_confidence_ssrf_destination(item.get("analysis", item) or {})
        for item in (urls or [])
    )
    if not has_ssrf:
        return decision

    decision["risk"] = "CRITICAL"
    decision["score"] = max(
        _normalize_score(decision.get("score", 0)),
        _normalize_score(scoring.get("threat_score", scoring.get("score", 0))),
        75,
    )
    decision["action"] = "BLOCK"
    decision["confidence"] = max(_normalize_score(decision.get("confidence", 0)), 85)
    reasons = list(decision.get("reasons", []) or [])
    reason = "Internal/private URL destination detected; possible SSRF-style targeting."
    if reason not in reasons:
        reasons.insert(0, reason)
    decision["reasons"] = reasons
    classifications = list(decision.get("attack_classification", []) or [])
    if "SSRF / internal resource targeting" not in classifications:
        classifications.append("SSRF / internal resource targeting")
    decision["attack_classification"] = classifications
    return decision


def _apply_attachment_decision_override(
    decision: Dict[str, Any],
    scoring: Dict[str, Any],
    attachments: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Promote high-confidence static attachment evidence into the final verdict."""
    if not isinstance(decision, dict) or not isinstance(attachments, dict):
        return decision

    highest = _normalize_score(attachments.get("score", 0))
    suspicious = _normalize_score(attachments.get("suspicious_attachment_count", 0))
    if highest < 75 or suspicious <= 0:
        return decision

    decision["risk"] = "CRITICAL"
    decision["risk_level"] = "CRITICAL"
    decision["score"] = max(
        _normalize_score(decision.get("score", 0)),
        _normalize_score(scoring.get("threat_score", scoring.get("score", 0))),
        75,
    )
    decision["action"] = "BLOCK"
    decision["confidence"] = max(_normalize_score(decision.get("confidence", 0)), 85)

    reasons = list(decision.get("reasons", []) or [])
    reason = "High-risk attachment detected by static analysis; possible malware delivery."
    if reason not in reasons:
        reasons.insert(0, reason)
    decision["reasons"] = reasons

    classifications = list(decision.get("attack_classification", []) or [])
    if "Malware Delivery / Dangerous Attachment" not in classifications:
        classifications.append("Malware Delivery / Dangerous Attachment")
    decision["attack_classification"] = classifications
    return decision


def _run_decision_engine(
    scoring: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    url: Dict[str, Any],
    authentication: Dict[str, Any],
    infrastructure: Dict[str, Any],
) -> Dict[str, Any]:

    decide = getattr(
        DecisionEngine,
        "decide",
        None,
    )

    if decide is not None:

        try:

            result = decide(

                scoring=
                    scoring,

                nlp_analysis=
                    nlp,

                ml_analysis=
                    ml,

                domain_analysis=
                    domain,

                url_analysis=
                    url,

                header_analysis=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except TypeError:

            pass

        except Exception:

            pass

    evaluate = getattr(
        DecisionEngine,
        "evaluate",
        None,
    )

    if evaluate is not None:

        try:

            result = evaluate(

                scoring,

                nlp_analysis=
                    nlp,

                ml_analysis=
                    ml,

                domain_analysis=
                    domain,

                url_analysis=
                    url,

                header_analysis=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except TypeError:

            pass

        except Exception:

            pass

        try:

            result = evaluate(

                score_result=
                    scoring,

                ml=
                    ml,

                nlp=
                    nlp,

                url=
                    url,

                domain=
                    domain,

                auth=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except Exception:

            pass

    # ------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------

    score = _normalize_score(

        scoring.get(
            "threat_score",
            scoring.get(
                "score",
                scoring.get(
                    "total",
                    0,
                ),
            ),
        )

    )

    confidence = _normalize_score(

        scoring.get(
            "confidence",
            ml.get(
                "confidence",
                0,
            ),
        )

    )

    if score >= 75:

        risk = "CRITICAL"

        action = "BLOCK"

    elif score >= 50:

        risk = "HIGH"

        action = "QUARANTINE"

    elif score >= 25:

        risk = "LOW"

        action = "REVIEW"

    else:

        risk = "SAFE"

        action = "ALLOW"

    reasons = []

    if nlp.get(
        "matched_indicator_count",
        0,
    ):

        reasons.append(
            "Suspicious linguistic indicators detected."
        )

    if ml.get(
        "classification",
        "",
    ).upper() == "PHISHING":

        reasons.append(
            "Machine-learning classifier identified phishing."
        )

    if domain.get(
        "impersonated_brands",
        [],
    ):

        reasons.append(
            "Brand impersonation detected."
        )

    if not reasons:

        reasons.append(
            "No significant phishing indicators were identified."
        )

    return {

        "risk":
            risk,

        "score":
            score,

        "action":
            action,

        "confidence":
            confidence,

        "reasons":
            list(
                dict.fromkeys(
                    reasons
                )
            ),

        "attack_classification":
            [],

    }


# ================================================================
# CORE ANALYSIS
# ================================================================

async def _analyze_parsed_email(
    parsed: Dict[str, Any],
    raw: bytes,
    filename: str,
    live_mode: bool = False,
) -> Dict[str, Any]:

    case_id = (
        "NETRA-"
        + uuid.uuid4().hex[:8].upper()
    )

    # ------------------------------------------------------------
    # PRIVACY
    # ------------------------------------------------------------

    try:

        sanitized = (
            IndiaPrivacyPreserver.sanitize_payload(
                parsed
            )
        )

    except Exception:

        sanitized = parsed

    # ------------------------------------------------------------
    # TEXT
    # ------------------------------------------------------------

    text = _safe_text_from_parsed(
        sanitized
    )

    # ------------------------------------------------------------
    # HEADER ANALYSIS
    # ------------------------------------------------------------

    try:

        authentication = (
            HeaderForensicAnalyzer.analyze(
                parsed
            )
        )

    except Exception as exc:

        authentication = {

            "authentication": {

                "spf":
                    "none",

                "dkim":
                    "none",

                "dmarc":
                    "none",

            },

            "alignment": {

                "from_domain":
                    "",

                "reply_to_domain":
                    "",

                "return_path_domain":
                    "",

                "has_mismatch":
                    False,

            },

            "originating_ip":
                None,

            "hop_count":
                0,

            "header_risk_score":
                0,

            "indicators":
                [
                    (
                        "Header analysis unavailable: "
                        f"{type(exc).__name__}"
                    )
                ],

        }

    # ------------------------------------------------------------
    # PARALLEL ANALYSIS
    #
    # Important:
    # These operations are independent, so they execute together.
    # This keeps Gmail response latency low.
    # ------------------------------------------------------------

    nlp_task = asyncio.to_thread(
        _build_nlp_result,
        text,
    )

    ml_task = asyncio.to_thread(
        _build_ml_result,
        text,
    )

    url_task = asyncio.to_thread(
        _build_url_result,
        parsed,
    )

    domain_task = asyncio.to_thread(
        _build_domain_result,
        parsed,
    )

    # For Gmail live analysis, GeoIP can be expensive.
    # We still keep the infrastructure field in the result,
    # but allow it to be skipped when necessary.
    infrastructure_task = asyncio.to_thread(
        _get_infrastructure,
        parsed,
        authentication,
        True,
    )

    attachment_analysis = AttachmentAnalyzer.analyze(
        parsed.get("attachments", []) or []
    )

    (
        nlp,
        ml,
        url,
        domain,
        infrastructure,
    ) = await asyncio.gather(

        nlp_task,

        ml_task,

        url_task,

        domain_task,

        infrastructure_task,

    )

    # ------------------------------------------------------------
    # THREAT SCORING
    # ------------------------------------------------------------

    scoring = _run_threat_scoring(

        authentication=
            authentication,

        url=
            url,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        infrastructure=
            infrastructure,

        attachments=
            attachment_analysis,

    )

    scoring = scoring or {}
    scoring = _apply_multilingual_scoring_signal(
        scoring,
        nlp,
    )

    # ------------------------------------------------------------
    # DECISION
    # ------------------------------------------------------------

    decision = _run_decision_engine(

        scoring=
            scoring,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        url=
            url,

        authentication=
            authentication,

        infrastructure=
            infrastructure,

    )

    decision = decision or {}
    decision = _apply_ssrf_decision_override(
        decision,
        scoring,
        url,
    )
    decision = _apply_attachment_decision_override(
        decision,
        scoring,
        attachment_analysis,
    )

    attachment_reasons = []
    for finding in attachment_analysis.get("attachments", []):
        attachment_reasons.extend(finding.get("reasons", []))
    if attachment_reasons:
        decision["reasons"] = list(dict.fromkeys(
            list(decision.get("reasons", []))
            + attachment_reasons
        ))

    # ------------------------------------------------------------
    # REDACTIONS
    # ------------------------------------------------------------

    try:

        redactions = (
            IndiaPrivacyPreserver.extract_redaction_findings(
                text
            )
        )

    except Exception:

        redactions = []

    # ------------------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------------------

    evidence = _build_evidence(

        header=
            authentication,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        url=
            url,

        infrastructure=
            infrastructure,

        decision=
            decision,

    )

    # ------------------------------------------------------------
    # EVIDENCE SEAL
    # ------------------------------------------------------------

    evidence_seal = _create_seal(

        raw,

        evidence,

    )

    # ------------------------------------------------------------
    # FINAL SCORE
    # ------------------------------------------------------------

    threat_score = _normalize_score(

        scoring.get(
            "threat_score",
            scoring.get(
                "score",
                scoring.get(
                    "total",
                    decision.get(
                        "score",
                        0,
                    ),
                ),
            ),
        )

    )

    # ------------------------------------------------------------
    # FINAL SEVERITY
    # ------------------------------------------------------------

    severity = str(

        decision.get(

            "risk",

            scoring.get(

                "severity",

                "UNKNOWN",

            ),

        )

    ).upper()

    if severity in {
        "SAFE",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:

        pass

    else:

        if threat_score >= 75:

            severity = "CRITICAL"

        elif threat_score >= 50:

            severity = "HIGH"

        elif threat_score >= 25:

            severity = "LOW"

        else:

            severity = "SAFE"

    # ------------------------------------------------------------
    # FINAL VERDICT SYNCHRONIZATION
    # ------------------------------------------------------------
    # Decision overrides (SSRF / dangerous attachments) are authoritative.
    # Propagate the canonical final verdict back into the scoring object so
    # every API surface reports the same score/severity/confidence.
    canonical_score = max(
        threat_score,
        _normalize_score(decision.get("score", 0)),
    )
    canonical_confidence = max(
        _normalize_score(scoring.get("confidence", 0)),
        _normalize_score(decision.get("confidence", 0)),
    )
    canonical_risk = severity

    scoring["threat_score"] = canonical_score
    scoring["score"] = canonical_score
    scoring["severity"] = canonical_risk
    scoring["risk_level"] = canonical_risk
    scoring["confidence"] = canonical_confidence

    # Keep the decision synchronized as well.
    decision["score"] = canonical_score
    decision["risk"] = canonical_risk
    decision["risk_level"] = canonical_risk
    decision["confidence"] = canonical_confidence

    threat_score = canonical_score

    # ------------------------------------------------------------
    # AI EXPLANATION
    #
    # IMPORTANT:
    # For Gmail we use the local rule-based explanation.
    # We do not call an external/slow LLM.
    #
    # ------------------------------------------------------------

    ai_explanation = (

        f"Assessment: {severity} "
        f"({threat_score}/100).\n"

        f"Recommended action: "
        f"{decision.get('action', 'REVIEW')}.\n"

        "Assessment based on multiple "
        "independent threat signals."

    )

    # ------------------------------------------------------------
    # Full forensic explanation
    # ------------------------------------------------------------

    explanation_payload = {

        "case_id":
            case_id,

        "threat_score":
            threat_score,

        "severity":
            severity,

        "decision":
            decision,

        "header_analysis":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "domain_analysis":
            domain,

        "url_analysis":
            url,

        "infrastructure":
            infrastructure,

        "attachments":
            attachment_analysis,

        "evidence":
            evidence,

        "redacted_metadata":
            sanitized.get(
                "metadata",
                {},
            ),

    }

    # Only use the local explainer when available.
    # The current llm_agent.py is local/rule based, so this
    # should be fast, but keep a safe fallback.

    try:

        ai_explanation = (
            ThreatExplainerAgent.explain(
                explanation_payload
            )
        )

    except Exception:

        pass

    # ------------------------------------------------------------
    # FORENSIC PAYLOAD
    # ------------------------------------------------------------

    forensic_payload = {

        "case_id":
            case_id,

        "decision":
            decision,

        "threat_score":
            threat_score,

        "severity":
            severity,

        "confidence":
            decision.get(
                "confidence",
                scoring.get(
                    "confidence",
                    0,
                ),
            ),

        "authentication":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "url_intelligence":
            url,

        "domain_intelligence":
            domain,

        "infrastructure":
            infrastructure,

        "evidence":
            evidence,

        "evidence_seal":
            evidence_seal,

        "ai_explanation":
            ai_explanation,

        "redacted_metadata":
            sanitized.get(
                "metadata",
                {},
            ),

        "live_gmail":
            live_mode,

        "analyzed_at":
            _now_iso(),

    }

    # ------------------------------------------------------------
    # CRITICAL FIX
    #
    # OLD VERSION:
    #
    #     if not live_mode:
    #         db.record_evidence(...)
    #
    # That caused:
    #
    # Gmail -> generated case ID
    # SOC -> requested case ID
    # DB -> case did not exist -> 404
    #
    # NEW VERSION:
    #
    # EVERY analysis gets recorded.
    #
    # This makes Gmail -> SOC case linking work.
    # ------------------------------------------------------------

    block_hash = None

    ledger_error = None

    try:

        block_hash = db.record_evidence(

            case_id=
                case_id,

            raw_sha256=
                parsed.get(
                    "raw_sha256",
                    hashlib.sha256(
                        raw
                    ).hexdigest(),
                ),

            threat_score=
                threat_score,

            verdict=
                decision.get(
                    "risk",
                    severity,
                ),

            forensic_data=
                forensic_payload,

        )

    except Exception as exc:

        ledger_error = (
            f"{type(exc).__name__}: {exc}"
        )

        forensic_payload[
            "ledger_error"
        ] = ledger_error

    # ------------------------------------------------------------
    # METADATA
    # ------------------------------------------------------------

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    clean_metadata = (
        sanitized.get(
            "metadata",
            {},
        )
        or {}
    )

    # ------------------------------------------------------------
    # RESPONSE
    # ------------------------------------------------------------

    return {

        "status":
            "SUCCESS",

        "case_id":
            case_id,

        "decision":
            decision,

        "report": {
            "threat_score":
                {
                    **scoring,
                    "score":
                        scoring.get(
                            "score",
                            scoring.get(
                                "threat_score",
                                0,
                            ),
                        ),
                    "risk_level":
                        scoring.get(
                            "risk_level",
                            scoring.get(
                                "severity",
                                decision.get(
                                    "risk",
                                    "UNKNOWN",
                                ),
                            ),
                        ),
                },
            "decision":
                decision,
            "confidence":
                decision.get(
                    "confidence",
                    scoring.get(
                        "confidence",
                        0,
                    ),
                ),
        },

        "email": {

            "filename":
                filename,

            "subject":
                clean_metadata.get(
                    "subject",
                    metadata.get(
                        "subject",
                        "",
                    ),
                ),

            "sender":
                clean_metadata.get(
                    "from",
                    "",
                ),

            "recipient":
                clean_metadata.get(
                    "to",
                    "",
                ),

            "reply_to":
                clean_metadata.get(
                    "reply_to",
                    "",
                ),

            "attachment_count":
                len(
                    parsed.get(
                        "attachments",
                        [],
                    )
                ),

        },

        "authentication":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "url_intelligence":
            url,

        "domain_intelligence":
            domain,

        "infrastructure":
            infrastructure,

        "threat_score":
            scoring,

        "evidence":
            evidence,

        "ai_explanation":
            ai_explanation,

        "evidence_seal":
            evidence_seal,

        "privacy": {

            "redactions":
                redactions,

            "sanitized":
                True,

        },

        "attachments":
            parsed.get(
                "attachments",
                [],
            ),

        "attachment_analysis":
            attachment_analysis,

        "network_chain":
            parsed.get(
                "network_chain",
                [],
            ),

        "block_hash":
            block_hash,

        "ledger_error":
            ledger_error,

        "analyzed_at":
            _now_iso(),

        # --------------------------------------------------------
        # Extension-friendly result
        # --------------------------------------------------------

        "netra_result": {

            "score":
                threat_score,

            "risk":
                decision.get(
                    "risk",
                    severity,
                ),

            "action":
                decision.get(
                    "action",
                    "REVIEW",
                ),

            "confidence":
                decision.get(
                    "confidence",
                    scoring.get(
                        "confidence",
                        0,
                    ),
                ),

            "case_id":
                case_id,

        },

    }


# ================================================================
# ROOT
# ================================================================

@app.get("/")
async def root():

    return {

        "name":
            "NETRA-Mail",

        "version":
            str(APP_VERSION),

        "status":
            "ONLINE",

        "mode":
            "LOCAL",

        "extension":
            "ENABLED",

        "soc":
            "ENABLED",

        "endpoints": {

            "health":
                "/health",

            "eml_analysis":
                "POST /api/v1/analyze/eml",

            "gmail_analysis":
                "POST /api/v1/analyze/email",

            "gmail_text_analysis":
                "POST /api/v1/analyze/text",

            "forensic_case":
                "GET /api/v1/forensics/case/{case_id}",

            "audit":
                "GET /api/v1/forensics/audit",

        },

    }


# ================================================================
# HEALTH
# ================================================================

@app.get("/health")
async def health():
    """Liveness endpoint: confirms the API process is running."""
    try:
        model_path = getattr(LocalMLClassifier, "MODEL_PATH", None)
        if hasattr(model_path, "exists"):
            model_available = bool(model_path.exists())
        else:
            model_available = bool(model_path and os.path.exists(str(model_path)))
    except Exception:
        model_available = False

    # Keep public liveness probes cheap; full auditing requires authentication.
    ledger = {"status": "NOT_CHECKED", "valid": None}

    return {
        "status": "healthy",
        "version": str(APP_VERSION),
        "mode": "LOCAL",
        "extension_api": True,
        "soc_api": True,
        "model_available": model_available,
        "ledger": {"status": ledger.get("status"), "valid": ledger.get("valid")},
    }


@app.get("/ready")
async def readiness():
    """Readiness endpoint: verifies core dependencies are usable."""
    checks: Dict[str, Any] = {}

    try:
        checks["configuration"] = {
            "ok": bool(APP_VERSION and MAX_EMAIL_SIZE_BYTES > 0 and MAX_EVIDENCE_SIZE_BYTES > 0),
            "version": str(APP_VERSION),
        }
    except Exception as exc:
        checks["configuration"] = {"ok": False, "error": type(exc).__name__}

    try:
        model_path = getattr(LocalMLClassifier, "MODEL_PATH", None)
        model_ok = bool(model_path and os.path.exists(str(model_path)))
        from backend.content_model import predict as content_predict
        content_available = content_predict("").get("available", False)
        checks["ml_model"] = {"ok": bool(content_available or model_ok),
                              "available": bool(content_available or model_ok),
                              "content_model_available": content_available,
                              "legacy_model_available": model_ok}
    except Exception as exc:
        checks["ml_model"] = {"ok": False, "error": type(exc).__name__}

    try:
        with db._connect() as conn:
            conn.execute("SELECT 1").fetchone()
        checks["forensic_ledger"] = {
            "ok": True,
            "status": "reachable",
            "integrity": "Use the authenticated audit endpoint for chain verification.",
        }
    except Exception as exc:
        checks["forensic_ledger"] = {"ok": False, "error": type(exc).__name__}

    storage_paths = {
        "evidence_storage": EVIDENCE_STORAGE_DIR,
        "database_parent": os.path.dirname(str(DATABASE_PATH)) or ".",
    }
    storage_ok = True
    storage_details = {}
    for name, raw_path in storage_paths.items():
        path = os.path.abspath(str(raw_path))
        exists = os.path.isdir(path)
        storage_details[name] = {"ok": exists}
        storage_ok = storage_ok and exists
    checks["storage"] = {"ok": storage_ok, "paths": storage_details}

    components_ok = all(
        component is not None
        for component in (parser, db, campaign_service, case_service, evidence_service, report_service)
    )
    checks["core_components"] = {"ok": components_ok}

    ready = all(bool(item.get("ok")) for item in checks.values())
    payload = {
        "status": "ready" if ready else "not_ready",
        "version": str(APP_VERSION),
        "mode": "LOCAL",
        "checks": checks,
    }

    if not ready:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=payload)

    return payload


# ================================================================
# EML ANALYSIS
# ================================================================

@app.post(
    "/api/v1/analyze/eml"
)
async def analyze_eml_file(
    request: Request,
    file: UploadFile = File(...),
):

    _enforce_rate_limit(request)

    if not file.filename:

        raise HTTPException(

            status_code=400,

            detail=
                "A filename is required.",

        )

    filename = file.filename

    if not filename.lower().endswith(
        ".eml"
    ):

        raise HTTPException(

            status_code=400,

            detail=
                "Only .eml files are supported.",

        )

    raw = await _read_limited_upload(file, MAX_EMAIL_SIZE_BYTES)

    if not raw:

        raise HTTPException(

            status_code=400,

            detail=
                "Uploaded email is empty.",

        )

    if len(raw) > MAX_EMAIL_SIZE_BYTES:

        raise HTTPException(

            status_code=413,

            detail=(
                "Email exceeds configured maximum "
                f"size of {MAX_EMAIL_SIZE_BYTES} bytes."
            ),

        )

    try:

        parsed = await asyncio.to_thread(
            parser.parse_eml_bytes,
            raw,
        )

        return await _analyze_parsed_email(

            parsed=
                parsed,

            raw=
                raw,

            filename=
                filename,

            live_mode=
                False,

        )

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# DIRECT GMAIL ANALYSIS
# ================================================================
#
# This is the endpoint used by content.js.
#
# Gmail sends:
#
# {
#     subject,
#     sender,
#     recipient,
#     reply_to,
#     body,
#     html,
#     headers,
#     received_headers
# }
#
# No .EML upload is required.
#
# ================================================================

@app.post(
    "/api/v1/analyze/email"
)
async def analyze_direct_email(
    http_request: Request,
    request: EmailAnalysisRequest,
):

    _enforce_rate_limit(http_request)

    if not any(

        [
            request.subject,
            request.sender,
            request.body,
            request.html,
        ]

    ):

        raise HTTPException(

            status_code=400,

            detail=
                "Email content is empty.",

        )

    try:

        message = EmailMessage()

        # --------------------------------------------------------
        # Basic headers
        # --------------------------------------------------------

        if request.subject:

            message["Subject"] = (
                request.subject
            )

        if request.sender:

            message["From"] = (
                request.sender
            )

        if request.recipient:

            message["To"] = (
                request.recipient
            )

        if request.reply_to:

            message["Reply-To"] = (
                request.reply_to
            )

        # --------------------------------------------------------
        # Extra headers
        # --------------------------------------------------------

        combined_headers = []

        if request.headers:

            combined_headers.append(
                request.headers
            )

        if request.received_headers:

            combined_headers.append(
                request.received_headers
            )

        for line in "\n".join(
            combined_headers
        ).splitlines():

            if ":" not in line:

                continue

            key, value = line.split(
                ":",
                1,
            )

            key = key.strip()

            value = value.strip()

            if not key:

                continue

            if key.lower() in {

                "subject",
                "from",
                "to",
                "reply-to",

            }:

                continue

            try:

                message[key] = value

            except Exception:

                pass

        # --------------------------------------------------------
        # Body
        # --------------------------------------------------------

        message.set_content(
            request.body or ""
        )

        if request.html:

            try:

                message.add_alternative(

                    request.html,

                    subtype="html",

                )

            except Exception:

                pass

        # --------------------------------------------------------
        # MIME BYTES
        # --------------------------------------------------------

        raw = message.as_bytes()

        parsed = await asyncio.to_thread(

            parser.parse_eml_bytes,

            raw,

        )

        # --------------------------------------------------------
        # COMPLETE LIVE ANALYSIS
        #
        # IMPORTANT:
        # live_mode no longer prevents ledger storage.
        # --------------------------------------------------------

        return await _analyze_parsed_email(

            parsed=
                parsed,

            raw=
                raw,

            filename=
                "gmail-live-analysis.eml",

            live_mode=
                True,

        )

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# TEXT COMPATIBILITY ENDPOINT
# ================================================================

@app.post(
    "/api/v1/analyze/text"
)
async def analyze_text_email(
    http_request: Request,
    request: EmailAnalysisRequest,
):

    return await analyze_direct_email(
        http_request,
        request,
    )


# ================================================================
# FORENSIC CASE REPORT
# ================================================================
#
# THIS IS THE ENDPOINT USED BY THE SOC DASHBOARD.
#
# It uses db.get_case() first because that guarantees we use the
# exact same database object/configuration that recorded the case.
#
# A SQLite fallback is also provided for compatibility with older
# database.py implementations.
#
# ================================================================

@app.get(
    "/api/v1/forensics/case/{case_id}"
)
async def get_forensic_case(
    case_id: str,
):

    case_id = case_id.strip()

    if not case_id:

        raise HTTPException(

            status_code=400,

            detail=
                "Case ID is required.",

        )

    # ------------------------------------------------------------
    # PRIMARY METHOD: DATABASE CLASS
    # ------------------------------------------------------------

    try:

        get_case = getattr(
            db,
            "get_case",
            None,
        )

        if callable(
            get_case
        ):

            record = get_case(
                case_id
            )

            if record:

                payload = (
                    record.get(
                        "forensic_payload",
                        {},
                    )
                    or {}
                )

                return {

                    "status":
                        "SUCCESS",

                    "case_id":
                        case_id,

                    "report":
                        payload,

                    "ledger": {

                        "id":
                            record.get(
                                "id"
                            ),

                        "timestamp":
                            record.get(
                                "timestamp"
                            ),

                        "raw_sha256":
                            record.get(
                                "raw_sha256"
                            ),

                        "threat_score":
                            record.get(
                                "threat_score"
                            ),

                        "verdict":
                            record.get(
                                "verdict"
                            ),

                        "previous_hash":
                            record.get(
                                "previous_hash"
                            ),

                        "block_hash":
                            record.get(
                                "block_hash"
                            ),

                    },

                }

    except Exception:

        pass

    # ------------------------------------------------------------
    # SQLITE FALLBACK
    # ------------------------------------------------------------

    try:

        import sqlite3
        import json

        db_path = getattr(
            db,
            "db_path",
            DATABASE_PATH,
        )

        if not db_path:

            db_path = DATABASE_PATH

        if not os.path.isabs(
            str(db_path)
        ):

            db_path = os.path.abspath(
                str(db_path)
            )

        with sqlite3.connect(
            db_path
        ) as conn:

            conn.row_factory = (
                sqlite3.Row
            )

            cursor = conn.cursor()

            # ----------------------------------------------------
            # Check actual table first.
            # ----------------------------------------------------

            cursor.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                """
            )

            tables = {
                row[0]
                for row in cursor.fetchall()
            }

            if "evidence_ledger" not in tables:

                raise HTTPException(

                    status_code=404,

                    detail={

                        "error":
                            "CASE_NOT_FOUND",

                        "message":
                            (
                                f"Case {case_id} "
                                "was not found."
                            ),

                        "case_id":
                            case_id,

                        "database":
                            str(db_path),

                    },

                )

            cursor.execute(
                """
                SELECT
                    *
                FROM evidence_ledger
                WHERE case_id = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (
                    case_id,
                ),
            )

            row = cursor.fetchone()

        if row is None:

            raise HTTPException(

                status_code=404,

                detail={

                    "error":
                        "CASE_NOT_FOUND",

                    "message":
                        (
                            f"Case {case_id} "
                            "was not found in "
                            "the forensic ledger."
                        ),

                    "case_id":
                        case_id,

                },

            )

        row = dict(row)

        forensic_payload = (
            row.get(
                "forensic_payload"
            )
        )

        if isinstance(
            forensic_payload,
            str,
        ):

            try:

                report = json.loads(
                    forensic_payload
                )

            except Exception:

                report = {

                    "case_id":
                        case_id,

                    "forensic_payload":
                        forensic_payload,

                }

        elif isinstance(
            forensic_payload,
            dict,
        ):

            report = forensic_payload

        else:

            report = {

                "case_id":
                    case_id,

            }

        report["case_id"] = (
            row.get(
                "case_id",
                case_id,
            )
        )

        return {

            "status":
                "SUCCESS",

            "case_id":
                row.get(
                    "case_id",
                    case_id,
                ),

            "report":
                report,

            "ledger": {

                "id":
                    row.get(
                        "id"
                    ),

                "timestamp":
                    row.get(
                        "timestamp"
                    ),

                "raw_sha256":
                    row.get(
                        "raw_sha256"
                    ),

                "threat_score":
                    row.get(
                        "threat_score"
                    ),

                "verdict":
                    row.get(
                        "verdict"
                    ),

                "previous_hash":
                    row.get(
                        "previous_hash"
                    ),

                "block_hash":
                    row.get(
                        "block_hash"
                    ),

            },

        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# FORENSIC AUDIT
# ================================================================

@app.get(
    "/api/v1/forensics/audit"
)
async def audit_chain_integrity():

    try:

        return db.verify_chain_integrity()

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# VERSION 2 STRUCTURED ANALYSIS API
# ================================================================

@app.post("/api/v2/mailbox/analyze")
async def analyze_selected_mailbox_message(request: Request):
    """Fetch the selected original at the backend; clients cannot assert trust."""
    _enforce_rate_limit(request)
    from backend.mailbox_ingestion import fetch_original
    try:
        body = await request.json()
        if not isinstance(body, dict) or set(body) != {"provider", "message_id", "access_token"}:
            raise ValueError()
        provider, identifier, token = (body[key] for key in ("provider", "message_id", "access_token"))
        if (provider not in {"gmail", "microsoft"} or not isinstance(identifier, str)
                or not isinstance(token, str) or not 1 <= len(token) <= 8192
                or not 1 <= len(identifier) <= 2048):
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="A supported provider, message ID and access token are required.")
    try:
        raw = await asyncio.to_thread(fetch_original, provider, identifier, token)
    except Exception:
        raise HTTPException(status_code=502, detail="The mailbox provider could not supply the selected original message.")
    finally:
        body.clear()
        token = None
    try:
        result = await asyncio.to_thread(v2_orchestrator.analyze, raw, "eml",
            trusted_receiver="gmail" if provider == "gmail" else None)
    except Exception:
        raise HTTPException(status_code=422, detail="The selected message could not be safely analyzed.")
    payload = result.model_dump()
    try:
        evidence = evidence_service.register(raw, "original.eml", "message/rfc822", "raw_eml",
            provider + "_connector", result.email_id)
        payload["evidence_reference"] = {key: evidence[key] for key in ("evidence_id", "sha256", "integrity_status")}
    except Exception:
        payload["evidence_reference"] = None
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    payload["correlation"] = _run_correlation(result.email_id)
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    db.set_analysis_owner(result.email_id, request.state.principal.subject)
    if request.state.principal.role == "submitter":
        payload.pop("correlation", None)
    return {"status": "SUCCESS", **payload}


@app.post("/api/v2/emails/upload")
async def upload_email_v2(
    request: Request,
    file: UploadFile = File(...),
):
    _enforce_rate_limit(request)
    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")
    raw = await _read_limited_upload(file, MAX_EMAIL_SIZE_BYTES)
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded email is empty.")
    if len(raw) > MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Email exceeds the configured size limit.")
    try:
        result = await asyncio.to_thread(v2_orchestrator.analyze, raw, "eml")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=422, detail="The email could not be safely analyzed.")
    payload = result.model_dump()
    try:
        registered_evidence = evidence_service.register(raw, filename, "message/rfc822", "raw_eml", "uploaded_file", result.email_id)
        payload["evidence_reference"] = {"evidence_id": registered_evidence["evidence_id"], "sha256": registered_evidence["sha256"], "integrity_status": registered_evidence["integrity_status"]}
    except Exception:
        payload["evidence_reference"] = None
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    payload["correlation"] = _run_correlation(result.email_id)
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    db.set_analysis_owner(result.email_id, request.state.principal.subject)
    if request.state.principal.role == "submitter":
        payload = {key: value for key, value in payload.items() if key != "correlation"}
    return {"status": "SUCCESS", **payload}


@app.post("/api/v2/emails/analyze")
async def analyze_email_v2(
    http_request: Request,
    request: V2TextAnalysisRequest,
):
    _enforce_rate_limit(http_request)
    if not any((request.subject, request.sender, request.body, request.html)):
        raise HTTPException(status_code=400, detail="Email content is empty.")
    try:
        raw = _build_v2_message(request)
        result = await asyncio.to_thread(v2_orchestrator.analyze, raw, "api")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid or oversized email fields.")
    except Exception:
        raise HTTPException(status_code=422, detail="The email could not be safely analyzed.")
    payload = result.model_dump()
    try:
        registered_evidence = evidence_service.register(raw, "reconstructed-message.eml", "message/rfc822", "reconstructed_eml", "api_reconstruction", result.email_id)
        payload["evidence_reference"] = {"evidence_id": registered_evidence["evidence_id"], "sha256": registered_evidence["sha256"], "integrity_status": registered_evidence["integrity_status"]}
    except Exception:
        payload["evidence_reference"] = None
    payload["limitations"].append("This message was reconstructed from supplied fields. Its hash does not authenticate the original delivered email; full headers and attachments may be unavailable.")
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    payload["correlation"] = _run_correlation(result.email_id)
    db.record_v2_analysis(result.email_id, result.evidence.sha256, payload)
    db.set_analysis_owner(result.email_id, http_request.state.principal.subject)
    if http_request.state.principal.role == "submitter":
        payload = {key: value for key, value in payload.items() if key != "correlation"}
    return {"status": "SUCCESS", **payload}


def _get_v2_result(email_id: str) -> Dict[str, Any]:
    try:
        result = db.get_v2_analysis(email_id)
    except Exception:
        raise HTTPException(status_code=503, detail="Investigation storage is unavailable.")
    if not result:
        raise HTTPException(status_code=404, detail="Email analysis was not found.")
    return result


def _run_correlation(email_id: str) -> Dict[str, Any]:
    try:
        return campaign_service.correlate(email_id)
    except Exception:
        return {"relationships_found": 0, "new_relationships": 0, "candidate_campaigns": [], "requires_review": False, "limitations": ["Correlation was unavailable for this analysis and can be retried later."]}


@app.get("/api/v2/emails/{email_id}/relationships")
async def get_email_relationships_v2(email_id: str):
    _get_v2_result(email_id)
    return {"email_id": email_id, "relationships": campaign_service.get_relationships(email_id)}


@app.post("/api/v2/emails/{email_id}/correlate")
async def correlate_email_v2(email_id: str):
    _get_v2_result(email_id)
    return campaign_service.correlate(email_id)


@app.post("/api/v2/campaigns")
async def create_campaign_v2(request: CampaignRequest):
    if not request.name or not request.name.strip():
        raise HTTPException(status_code=400, detail="Campaign name is required")
    status = request.status or "suspected"
    if status not in {"suspected", "under_review", "confirmed", "dismissed", "closed"}:
        raise HTTPException(status_code=400, detail="Invalid campaign status")
    now = datetime.now(timezone.utc).isoformat()
    return db.create_campaign({"campaign_id": "camp_" + uuid.uuid4().hex[:12], "name": request.name.strip(), "description": (request.description or "").strip(), "status": status, "confidence": 0.0, "analyst_confirmed": False, "created_at": now, "updated_at": now, "primary_indicators": []})


@app.get("/api/v2/campaigns")
async def list_campaigns_v2():
    return {"campaigns": campaign_service.list_campaigns()}


@app.get("/api/v2/campaigns/{campaign_id}")
async def get_campaign_v2(campaign_id: str):
    campaign = campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign was not found")
    return campaign


@app.patch("/api/v2/campaigns/{campaign_id}")
async def update_campaign_v2(campaign_id: str, request: CampaignRequest):
    updates = request.model_dump(exclude_unset=True)
    if updates.get("status") is not None and updates["status"] not in {"suspected", "under_review", "confirmed", "dismissed", "closed"}:
        raise HTTPException(status_code=400, detail="Invalid campaign status")
    campaign = db.update_campaign(campaign_id, updates)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign was not found")
    return campaign


@app.get("/api/v2/campaigns/{campaign_id}/emails")
async def get_campaign_emails_v2(campaign_id: str):
    if not db.get_campaign(campaign_id):
        raise HTTPException(status_code=404, detail="Campaign was not found")
    return {"campaign_id": campaign_id, "email_ids": db.get_campaign_emails(campaign_id)}


@app.get("/api/v2/campaigns/{campaign_id}/relationships")
async def get_campaign_relationships_v2(campaign_id: str):
    campaign = campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign was not found")
    return {"campaign_id": campaign_id, "relationships": campaign["relationships"]}


@app.post("/api/v2/cases")
async def create_case_v2(request: CaseRequest):
    try:
        return case_service.create(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v2/cases")
async def list_cases_v2():
    return {"cases": db.list_cases()}


@app.get("/api/v2/cases/{case_id}")
async def get_case_v2(case_id: str):
    try:
        return case_service.require(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.patch("/api/v2/cases/{case_id}")
async def update_case_v2(case_id: str, request: CaseUpdateRequest):
    try:
        return case_service.update(case_id, request.model_dump(exclude_unset=True))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/emails/{email_id}")
async def add_case_email_v2(case_id: str, email_id: str):
    try:
        return case_service.add_email(case_id, email_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/emails")
async def add_case_email_body_v2(case_id: str, request: CaseEmailRequest):
    return await add_case_email_v2(case_id, request.email_id)


@app.delete("/api/v2/cases/{case_id}/emails/{email_id}")
async def remove_case_email_v2(case_id: str, email_id: str):
    try:
        return case_service.remove_email(case_id, email_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/campaigns/{campaign_id}")
async def link_case_campaign_v2(case_id: str, campaign_id: str):
    try:
        return case_service.add_campaign(case_id, campaign_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/notes")
async def add_case_note_v2(case_id: str, request: NoteRequest, http_request: Request):
    try:
        case_service.add_note(case_id, request.note, http_request.state.principal.subject)
        return case_service.require(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/tags")
async def add_case_tag_v2(case_id: str, request: TagRequest):
    try:
        return case_service.add_tag(case_id, request.tag)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v2/cases/{case_id}/timeline")
async def get_case_timeline_v2(case_id: str):
    try:
        case_service.require(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"case_id": case_id, "timeline": db.get_case_timeline(case_id)}


@app.post("/api/v2/evidence/register")
async def register_evidence_v2(
    request: Request,
    file: UploadFile = File(...),
    evidence_type: str = Form("raw_eml"),
    case_id: str | None = Form(None),
    email_id: str | None = Form(None),
):
    _enforce_rate_limit(request)
    raw = await _read_limited_upload(file, MAX_EVIDENCE_SIZE_BYTES)
    if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Evidence exceeds the configured size limit.")
    if case_id and not db.get_case_record(case_id):
        raise HTTPException(status_code=404, detail="Case was not found")
    if email_id and not db.get_v2_analysis(email_id):
        raise HTTPException(status_code=404, detail="Email analysis was not found")
    try:
        return evidence_service.register(raw, file.filename or "evidence.bin", file.content_type or "application/octet-stream", evidence_type, "uploaded_file", email_id, case_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError:
        raise HTTPException(status_code=422, detail="Evidence could not be safely stored")


@app.get("/api/v2/evidence/{evidence_id}")
async def get_evidence_v2(evidence_id: str):
    evidence = evidence_service.get(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence was not found")
    return evidence


@app.get("/api/v2/evidence/{evidence_id}/verify")
async def verify_evidence_v2(evidence_id: str, request: Request):
    _enforce_rate_limit(request)
    try:
        return await asyncio.to_thread(evidence_service.verify, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/v2/evidence/{evidence_id}/versions")
async def evidence_versions_v2(evidence_id: str):
    try:
        return {"evidence_id": evidence_id, "versions": evidence_service.versions(evidence_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/evidence/{evidence_id}/versions")
async def create_evidence_version_v2(
    request: Request,
    evidence_id: str,
    file: UploadFile = File(...),
    reason: str = Form("replacement_preserved_as_new_version"),
):
    _enforce_rate_limit(request)
    raw = await _read_limited_upload(file, MAX_EVIDENCE_SIZE_BYTES)
    if len(raw) > MAX_EVIDENCE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Evidence version exceeds the configured size limit.")
    try:
        return evidence_service.create_version(evidence_id, raw, file.filename, reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v2/evidence/{evidence_id}/custody")
async def evidence_custody_v2(evidence_id: str):
    try:
        return {"evidence_id": evidence_id, "events": evidence_service.custody(evidence_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/v2/cases/{case_id}/evidence")
async def case_evidence_v2(case_id: str):
    try:
        return {"case_id": case_id, "evidence": evidence_service.list_for_case(case_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/evidence/{evidence_id}")
async def link_case_evidence_v2(case_id: str, evidence_id: str):
    try:
        return evidence_service.link_case(evidence_id, case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/v2/cases/{case_id}/custody")
async def case_custody_v2(case_id: str):
    try:
        evidence_items = evidence_service.list_for_case(case_id)
        return {"case_id": case_id, "events": [event for item in evidence_items for event in evidence_service.custody(item["evidence_id"])]}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/v2/cases/{case_id}/reports")
async def create_case_report_v2(case_id: str, request: Request, report_format: str = "json"):
    _enforce_rate_limit(request)
    try:
        return await asyncio.to_thread(report_service.generate, case_id, report_format.lower())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v2/cases/{case_id}/reports")
async def list_case_reports_v2(case_id: str):
    if not db.get_case_record(case_id):
        raise HTTPException(status_code=404, detail="Case was not found")
    return {"case_id": case_id, "reports": report_service.list_for_case(case_id)}


@app.get("/api/v2/reports/{report_id}")
async def get_report_v2(report_id: str):
    report = report_service.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report was not found")
    return report


@app.get("/api/v2/reports/{report_id}/download")
async def download_report_v2(report_id: str):
    report = report_service.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report was not found")
    path = (EVIDENCE_STORAGE_DIR / report["download_reference"]).resolve()
    if EVIDENCE_STORAGE_DIR.resolve() not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Report file is unavailable")
    media_type = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}.get(report["format"], "application/octet-stream")
    try:
        content = report_service.download(report_id)
    except (OSError, ValueError):
        raise HTTPException(status_code=409, detail="Report integrity could not be verified or its encryption key is unavailable.")
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f"attachment; filename={report_id}.{report['format']}"})


@app.get("/api/v2/emails/{email_id}")
async def get_email_v2(email_id: str):
    result = _get_v2_result(email_id)
    response = {key: result[key] for key in ("email_id", "evidence", "classification", "risk_score", "confidence", "limitations")}
    response["parsed"] = {key: result.get("parsed", {}).get(key) for key in ("verified_authentication", "reported_authentication", "ml_analysis", "content_model")}
    response["evidence_reference"] = result.get("evidence_reference")
    from backend.presentation import explain_analysis
    response["explanation"] = explain_analysis(result)
    response["attachment_reviews"] = db.list_attachment_reviews(email_id)
    return response


@app.post("/api/v2/emails/{email_id}/attachments/{attachment_sha256}/unlock")
async def unlock_pdf_attachment(email_id: str, attachment_sha256: str, request: Request):
    """Authenticated analyst operation; original evidence is never overwritten."""
    import re
    from backend.attachment_review import original_attachment, review_pdf
    if not re.fullmatch(r"[0-9a-f]{64}", attachment_sha256):
        raise HTTPException(status_code=400, detail="Invalid attachment reference.")
    result = _get_v2_result(email_id)
    # Do not accept arbitrary uploads or substitute attachments in this route.
    known = result.get("parsed", {}).get("attachment_analysis", {}).get("attachments", [])
    if not any(item.get("sha256") == attachment_sha256 for item in known):
        raise HTTPException(status_code=404, detail="Attachment was not found in this investigation.")
    body = {}
    password = None
    try:
        raw_body = await request.body()
        if len(raw_body) > 4096:
            raise ValueError()
        body = json.loads(raw_body)
        if not isinstance(body, dict) or set(body) != {"password", "consent"}:
            raise ValueError()
        password = body.get("password")
        if body.get("consent") is not True or not isinstance(password, str) or len(password) > 256:
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Explicit consent and a document password of at most 256 characters are required.")
    finally:
        if isinstance(body, dict):
            body.clear()
    try:
        data = await asyncio.to_thread(original_attachment, result, evidence_service, email_id, attachment_sha256)
    except Exception:
        password = None
        raise HTTPException(status_code=409, detail="The preserved original attachment is unavailable or failed integrity checks. Analyze the original email again before unlocking it.")
    try:
        review = await asyncio.to_thread(review_pdf, data, password, email_id, attachment_sha256, request.state.principal.subject)
    except Exception:
        raise HTTPException(status_code=422, detail="The PDF could not be safely inspected. Its contents remain unverified.")
    finally:
        password = None
        data = None
    db.record_attachment_review(review)
    return review


@app.get("/api/v2/me")
async def current_identity(request: Request):
    identity = request.state.principal
    return {"subject": identity.subject, "role": identity.role}


@app.get("/api/v2/dashboard/summary")
async def dashboard_summary_v2():
    return db.dashboard_summary()


@app.get("/api/v2/emails")
async def list_emails_v2(limit: int = 50, offset: int = 0, risk_level: str | None = None):
    return db.list_v2_analyses_page(limit, offset, risk_level)


@app.get("/api/v2/emails/{email_id}/findings")
async def get_email_findings_v2(email_id: str):
    return {"email_id": email_id, "findings": _get_v2_result(email_id)["findings"]}


@app.get("/api/v2/emails/{email_id}/trace")
async def get_email_trace_v2(email_id: str):
    result = _get_v2_result(email_id)
    parsed = result.get("parsed", {})
    trace = parsed.get("origin_trace", {})
    return {"email_id": email_id, **trace, "network_chain": parsed.get("network_chain", trace.get("hops", []))}


@app.get("/api/v2/intelligence/ip/{ip}")
async def get_ip_intelligence_v2(ip: str, request: Request):
    _enforce_rate_limit(request)
    return await asyncio.to_thread(ip_intelligence_provider.lookup, ip)


@app.get("/api/v2/intelligence/domain/{domain}")
async def get_domain_intelligence_v2(domain: str, request: Request):
    _enforce_rate_limit(request)
    return await asyncio.to_thread(domain_intelligence_provider.inspect, domain, source="api")


@app.get("/api/v2/emails/{email_id}/graph")
async def get_email_graph_v2(email_id: str):
    from backend.services.investigation_graph import build_graph
    result = _get_v2_result(email_id)
    return build_graph(result, db.get_relationships(email_id))


# ================================================================
# RUN DIRECTLY
# ================================================================

if __name__ == "__main__":

    uvicorn.run(

        "backend.main:app",

        host="0.0.0.0",

        port=8000,

        reload=True,

    )
