import copy
import re
from typing import Any, Dict


class IndiaPrivacyPreserver:
    """Detect and redact sensitive identifiers while preserving forensic domains."""

    PATTERNS = {
        # Kept for provider-specific UPI detection; the generic email rule below
        # deliberately runs first so ordinary addresses are never truncated.
        "UPI_ID": re.compile(
            r"\b[a-zA-Z0-9._%+\-]{2,256}@[a-zA-Z0-9.-]{2,253}\.[A-Za-z]{2,63}\b"
        ),
        "INDIAN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        "INDIAN_PHONE": re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b"),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "NATIONAL_ID_GENERIC": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        "IFSC_CODE": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "BANK_ACCOUNT": re.compile(r"\b\d{9,18}\b"),
        "EMAIL_ADDRESS": re.compile(
            r"\b[a-zA-Z0-9._%+\-]{1,256}@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b"
        ),
    }

    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text:
            return ""

        redacted = str(text)

        # Order matters: protect complete email addresses before applying
        # generic numeric/identifier rules. Preserve the domain for forensics.
        redacted = cls.PATTERNS["EMAIL_ADDRESS"].sub(r"***@\1", redacted)

        redacted = cls.PATTERNS["CREDIT_CARD"].sub(
            "[REDACTED_PAYMENT_CARD]", redacted
        )
        redacted = cls.PATTERNS["INDIAN_PHONE"].sub(
            "[REDACTED_PHONE]", redacted
        )
        redacted = cls.PATTERNS["NATIONAL_ID_GENERIC"].sub(
            "[REDACTED_NATIONAL_ID]", redacted
        )
        redacted = cls.PATTERNS["INDIAN_PAN"].sub(
            "[REDACTED_PAN]", redacted
        )
        redacted = cls.PATTERNS["IFSC_CODE"].sub(
            "[REDACTED_IFSC]", redacted
        )

        # Generic bank-account redaction is intentionally last because it is
        # broad and can otherwise alter timestamps, IDs, or other numeric data.
        redacted = cls.PATTERNS["BANK_ACCOUNT"].sub(
            "[REDACTED_BANK_ACCOUNT]", redacted
        )
        return redacted

    @classmethod
    def redact_structure(cls, value):
        if isinstance(value, str):
            return cls.redact_text(value)
        if isinstance(value, list):
            return [cls.redact_structure(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.redact_structure(item) for key, item in value.items()}
        return value

    @classmethod
    def sanitize_payload(cls, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        """Deep-copy and sanitize analyst/LLM-facing data without altering evidence."""
        clean = copy.deepcopy(parsed_email)

        body = parsed_email.get("body") or {}
        clean["body"] = {
            "plain": cls.redact_text(body.get("plain", "")),
            "html": cls.redact_text(body.get("html", "")),
        }

        metadata = parsed_email.get("metadata") or {}
        clean["metadata"] = {
            key: value if key == "message_id" else cls.redact_text(str(value))
            for key, value in metadata.items()
        }

        return clean
