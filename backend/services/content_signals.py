"""Bounded static content checks. Never renders HTML or follows URLs."""
import re
import unicodedata
from html import unescape
from urllib.parse import urlsplit

from backend.schemas.findings import Finding


def inspect_content(text: str, html: str) -> list[Finding]:
    text = unescape(text[:524288])
    html = html[:524288]
    findings = []

    def add(category, rule, severity, title, evidence):
        findings.append(Finding(category=category, rule=rule, severity=severity,
            confidence=0.8, title=title, description=title, evidence=evidence,
            limitations=["Static indicator requiring contextual review; not proof of malicious intent."]))

    # Both a payment change and an instruction to use it are required.
    change = re.search(r"\b(?:new|updated|changed|replacement)\s+(?:bank\s+|payment\s+)?(?:account|routing|banking|wire)\b", text, re.I)
    payment = re.search(r"\b(?:send|transfer|wire|pay|remit|deposit)\b", text, re.I)
    if change and payment:
        add("BEC", "payment_destination_change", "high", "Payment requested using changed banking details",
            {"signals": [change.group(0), payment.group(0)]})

    lowered = html.lower()
    if "createobjecturl" in lowered and re.search(r"\b(?:blob|uint8array|atob)\b", lowered):
        add("Text", "html_payload_assembly", "high", "HTML assembles a downloadable payload",
            {"signals": ["createObjectURL", "encoded or binary payload construction"]})

    if any(char in text for char in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068"):
        add("Text", "bidirectional_control", "low", "Text includes direction-changing control characters",
            {"control_present": True})

    domains = set()
    for match in re.finditer(r'https?://[^\s<>"\x27]+', text, re.I):
        if len(domains) >= 100:
            break
        try:
            host = urlsplit(match.group(0)).hostname or ""
            host = host.encode("ascii").decode("idna") if host.isascii() else host
        except (ValueError, UnicodeError):
            continue
        domains.add(host)
    # Mixed scripts within one label are more informative than IDN presence.
    for host in sorted(domains):
        for label in host.split("."):
            scripts = {unicodedata.name(c, "").split(" ")[0] for c in label if c.isalpha()}
            if "LATIN" in scripts and scripts.intersection({"CYRILLIC", "GREEK"}):
                add("URL", "mixed_script_domain", "medium", "Link domain mixes visually confusable scripts",
                    {"domain": host[:253], "scripts": sorted(scripts)})
                break
        else:
            continue
        break
    return findings
