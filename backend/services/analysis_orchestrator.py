from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from uuid import uuid4

from backend.attachment_analyzer import AttachmentAnalyzer
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.nlp_engine import NLPEngine
# Resolve sklearn imports before concurrent first requests can interleave module locks.
from backend.ml_classifier import LocalMLClassifier
from backend.services.phrase_similarity import inspect_phrases
from backend.parser import ForensicEmailParser

from backend.schemas.findings import (
    AnalysisResult,
    EvidenceRecord,
    Finding,
)

from backend.services.risk_engine import RiskEngine
from backend.services.origin_trace import OriginTraceService

from backend.intelligence.domain_provider import (
    DomainIntelligenceProvider,
)

from backend.intelligence.ip_provider import (
    IPIntelligenceProvider,
)

from backend.multilingual_detector import (
    MultilingualLanguageDetector,
)

try:
    from backend.url_analyzer import URLAnalyzer
except Exception:
    URLAnalyzer = None
class AnalysisOrchestrator:
    """
    V2 analysis pipeline with explicitly provisioned local models.

    Multilingual support:
    - Detects supported Indian languages.
    - Preserves the original NLP engine.
    - Adds multilingual contextual evidence.
    - Avoids double-counting multilingual findings.
    - Exposes multilingual_score consistently in the V2 result.
    - Language alone is never considered malicious.
    """

    VERSION = "4.5.1"

    def __init__(
        self,
        parser: ForensicEmailParser | None = None,
        ip_provider: IPIntelligenceProvider | None = None,
        domain_provider: DomainIntelligenceProvider | None = None,
    ):
        self.parser = parser or ForensicEmailParser()
        self.ip_provider = ip_provider or IPIntelligenceProvider()
        self.domain_provider = domain_provider or DomainIntelligenceProvider()

    # ------------------------------------------------------------------
    # FINDING FACTORY
    # ------------------------------------------------------------------

    @staticmethod
    def _finding(
        category: str,
        rule: str,
        severity: str,
        confidence: float,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        limitations: List[str] | None = None,
    ) -> Finding:
        return Finding(
            category=category,
            rule=rule,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence,
            limitations=limitations or [],
        )

    # ------------------------------------------------------------------
    # MULTILINGUAL NLP MERGE
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_multilingual_categories(
        nlp: Dict[str, Any],
        multilingual: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge multilingual Indian-language findings into the existing
        NLP result without replacing the original NLP analysis.
        """

        existing_categories = nlp.get("categories", {}) or {}

        merged_categories = {
            category: list(values or [])
            for category, values in existing_categories.items()
        }

        multilingual_categories = (
            multilingual.get("multilingual_findings", {}) or {}
        )

        for category, indicators in multilingual_categories.items():
            if not indicators:
                continue

            current = merged_categories.setdefault(category, [])

            for indicator in indicators:
                if indicator not in current:
                    current.append(indicator)

        nlp["categories"] = merged_categories

        # Preserve multilingual metadata.
        nlp["language"] = multilingual.get(
            "language",
            "Unknown",
        )

        nlp["language_code"] = multilingual.get(
            "language_code",
            "und",
        )

        nlp["language_confidence"] = multilingual.get(
            "language_confidence",
            0.0,
        )

        nlp["script"] = multilingual.get(
            "script",
            "unknown",
        )

        nlp["is_multilingual"] = multilingual.get(
            "is_multilingual",
            False,
        )

        nlp["detection_method"] = multilingual.get(
            "detection_method",
            "",
        )

        nlp["detected_scripts"] = multilingual.get(
            "detected_scripts",
            [],
        )

        nlp["multilingual_findings"] = multilingual_categories

        # IMPORTANT:
        # Keep the canonical key as multilingual_score.
        nlp["multilingual_score"] = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        return nlp

    # ------------------------------------------------------------------
    # MULTILINGUAL FINDINGS
    # ------------------------------------------------------------------

    def _build_multilingual_findings(
        self,
        multilingual: Dict[str, Any],
    ) -> List[Finding]:
        """
        Convert multilingual detector results into normal V2 Finding
        objects.

        Language itself is never treated as malicious.
        Only contextual threat indicators generate findings.
        """

        findings: List[Finding] = []

        multilingual_score = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        language = multilingual.get(
            "language",
            "Unknown",
        )

        language_code = multilingual.get(
            "language_code",
            "und",
        )

        script = multilingual.get(
            "script",
            "unknown",
        )

        categories = (
            multilingual.get(
                "multilingual_findings",
                {},
            )
            or {}
        )

        urgency = categories.get(
            "urgency",
            [],
        ) or []

        credentials = categories.get(
            "credential_harvesting",
            [],
        ) or []

        financial = categories.get(
            "financial_fraud",
            [],
        ) or []

        social = categories.get(
            "social_engineering",
            [],
        ) or []

        # No threat indicators -> no multilingual finding.
        if not any(
            (
                urgency,
                credentials,
                financial,
                social,
            )
        ):
            return findings

        related_categories = []

        if urgency:
            related_categories.append(
                "urgency"
            )

        if credentials:
            related_categories.append(
                "credential_harvesting"
            )

        if financial:
            related_categories.append(
                "financial_fraud"
            )

        if social:
            related_categories.append(
                "social_engineering"
            )

        # --------------------------------------------------------------
        # STRONG CONTEXTUAL COMBINATION
        # --------------------------------------------------------------

        if urgency and (
            credentials
            or financial
            or social
        ):
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_contextual_social_engineering",
                    "high",
                    0.84,
                    "Multilingual urgency is combined with a high-risk request",
                    (
                        "The message contains supported Indian-language "
                        "or multilingual urgency cues together with "
                        "credential, financial, or social-engineering "
                        "indicators."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "categories": related_categories,
                        "urgency": urgency[:5],
                        "credential_cues": credentials[:5],
                        "financial_cues": financial[:5],
                        "social_cues": social[:5],
                    },
                )
            )

        # --------------------------------------------------------------
        # FINANCIAL FRAUD WITHOUT URGENCY
        # --------------------------------------------------------------

        elif financial:
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_financial_fraud",
                    "medium",
                    0.72,
                    "Financial-risk language detected",
                    (
                        "The message contains financial-risk "
                        "indicators detected in a supported "
                        "Indian language."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "financial_cues": financial[:5],
                    },
                )
            )

        # --------------------------------------------------------------
        # CREDENTIAL HARVESTING WITHOUT URGENCY
        # --------------------------------------------------------------

        if credentials and not urgency:
            findings.append(
                self._finding(
                    "Text",
                    "multilingual_credential_harvesting",
                    "medium",
                    0.76,
                    "Credential-harvesting language detected",
                    (
                        "The message contains credential-related "
                        "language detected in a supported "
                        "Indian language."
                    ),
                    {
                        "language": language,
                        "language_code": language_code,
                        "script": script,
                        "multilingual_score": multilingual_score,
                        "credential_cues": credentials[:5],
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # MAIN ANALYSIS PIPELINE
    # ------------------------------------------------------------------

    def analyze(
        self,
        raw: bytes,
        source_type: str = "eml",
        *,
        trusted_receiver: str | None = None,
    ) -> AnalysisResult:

        if not raw:
            raise ValueError(
                "Email content is empty"
            )

        # ==============================================================
        # 1. FORENSIC PARSING
        # ==============================================================

        parsed = self.parser.parse_eml_bytes(
            raw
        )
        from backend.email_authentication import EmailAuthenticationVerifier
        parsed["verified_authentication"] = EmailAuthenticationVerifier().verify(raw, source_type, trusted_receiver=trusted_receiver)

        metadata = parsed.get(
            "metadata",
            {},
        ) or {}

        body = parsed.get(
            "body",
            {},
        ) or {}

        from backend.services.email_features import email_feature_text
        text = email_feature_text(parsed)

        # ==============================================================
        # 2. EXISTING NLP
        # ==============================================================

        nlp = (
            NLPEngine.analyze_text(
                text
            )
            or {}
        )

        # Keep a copy of the original English NLP categories.
        #
        # This is important because multilingual categories should not
        # cause the original English contextual rules to fire twice.
        original_categories = {
            category: list(values or [])
            for category, values in (
                nlp.get(
                    "categories",
                    {},
                )
                or {}
            ).items()
        }

        # ==============================================================
        # 3. MULTILINGUAL INDIAN-LANGUAGE ANALYSIS
        # ==============================================================

        try:
            multilingual = (
                MultilingualLanguageDetector.analyze(
                    text or ""
                )
                or {}
            )

        except Exception:
            # Multilingual detection must NEVER break V2 analysis.
            multilingual = {
                "language": "Unknown",
                "language_code": "und",
                "language_confidence": 0.0,
                "script": "unknown",
                "is_multilingual": False,
                "detection_method": "error_fallback",
                "detected_scripts": [],
                "multilingual_findings": {},
                "multilingual_score": 0,
            }

        # Merge multilingual information into NLP.
        nlp = self._merge_multilingual_categories(
            nlp,
            multilingual,
        )

        multilingual_score = int(
            multilingual.get(
                "multilingual_score",
                0,
            )
            or 0
        )

        # ==============================================================
        # 4. FINDINGS
        # ==============================================================

        findings: List[Finding] = []
        from backend.services.content_signals import inspect_content
        findings.extend(inspect_content(text, str(body.get("html", ""))))
        findings.extend(inspect_phrases(text))

        # --------------------------------------------------------------
        # MULTILINGUAL FINDINGS
        # --------------------------------------------------------------

        findings.extend(
            self._build_multilingual_findings(
                multilingual
            )
        )

        # ==============================================================
        # 5. EXISTING NLP CATEGORIES
        #
        # IMPORTANT:
        # Use ONLY the ORIGINAL NLP categories here.
        #
        # Otherwise:
        #
        # multilingual finding
        # +
        # contextual_social_engineering
        #
        # would both represent the same evidence.
        # ==============================================================

        urgency = original_categories.get(
            "urgency",
            [],
        ) or []

        credentials = original_categories.get(
            "credential_harvesting",
            [],
        ) or []

        financial = original_categories.get(
            "financial_fraud",
            [],
        ) or []

        social = original_categories.get(
            "social_engineering",
            [],
        ) or []

        # ==============================================================
        # 6. EXISTING ENGLISH CONTEXTUAL RULES
        # ==============================================================

        # Generic request words are not independent authority evidence.
        generic = {"require", "required", "requires", "request", "requested", "please", "action required"}
        social = [cue for cue in social if str(cue).lower() not in generic]
        if "social_engineering" in nlp.get("categories", {}):
            nlp["categories"]["social_engineering"] = [
                cue for cue in nlp["categories"]["social_engineering"]
                if str(cue).lower() not in generic
            ]
        if urgency and (
            credentials
            or financial
            or social
        ):
            findings.append(
                self._finding(
                    "Text",
                    "contextual_social_engineering",
                    "high",
                    0.84,
                    "Urgency is combined with a high-risk request",
                    (
                        "The message combines pressure with "
                        "credential, financial, or authority cues."
                    ),
                    {
                        "urgency": urgency[:5],
                        "related_categories": [
                            key
                            for key, value in (
                                (
                                    "credential_harvesting",
                                    credentials,
                                ),
                                (
                                    "financial_fraud",
                                    financial,
                                ),
                                (
                                    "social_engineering",
                                    social,
                                ),
                            )
                            if value
                        ],
                    },
                )
            )

        elif urgency:
            findings.append(
                self._finding(
                    "Text",
                    "urgency_only",
                    "low",
                    0.62,
                    "Urgency language detected",
                    (
                        "Urgency alone is not proof of phishing "
                        "and should be reviewed with other evidence."
                    ),
                    {
                        "cues": urgency[:5],
                    },
                )
            )

        strong_financial = [cue for cue in financial if str(cue).lower() not in {"money"}]
        strong_authority = [
            cue for cue in social
            if str(cue).lower() not in {
                "click here", "click", "link", "require", "required", "requires",
                "request", "requested", "please", "action required",
            }
        ]
        # A financial noun plus an authority noun is not a payment instruction.
        import re
        payment_instruction = re.search(
            r"\b(?:send|transfer|wire|remit|pay|deposit|purchase|buy|approve)\b[^.!?\n]{0,120}\b(?:money|funds|payment|invoice|account|bank|gift\s+cards?|transaction)\b",
            text, re.I,
        )
        if strong_financial and strong_authority and payment_instruction:
            findings.append(
                self._finding(
                    "BEC",
                    "payment_authority_combination",
                    "high",
                    0.82,
                    "Financial request paired with authority cues",
                    (
                        "The message combines a financial action "
                        "with executive or confidentiality language."
                    ),
                    {
                        "financial": strong_financial[:5],
                        "social": strong_authority[:5],
                    },
                )
            )

        # ==============================================================
        # 7. HEADER FORENSICS
        # ==============================================================

        header = (
            HeaderForensicAnalyzer.analyze(
                parsed
            )
            or {}
        )

        verified = parsed["verified_authentication"]
        for item in header.get("findings", []):
            item = dict(item)
            if item.get("rule") in {"spf_failure", "dkim_failure", "dmarc_failure", "spf_misalignment", "dkim_misalignment", "dmarc_misalignment"}:
                item["severity"] = "info"
                item.setdefault("limitations", []).append("Uploaded authentication claims are not independent verification; trusted failures are recorded separately.")
            if item.get("rule") in {"from_return_path_mismatch", "from_reply_to_mismatch", "received_timestamp_order", "malformed_received"}:
                item["severity"] = "low"
                item.setdefault("limitations", []).append("Infrastructure and forwarding differences are weak context; they do not independently establish an attack.")
            if item.get("rule") == "message_id_domain_mismatch":
                item["severity"] = "info"
            if verified["dmarc"]["status"] == "pass" and item.get("rule") in {"spf_misalignment", "dkim_misalignment", "dmarc_misalignment"}:
                item["severity"] = "info"
                item.setdefault("limitations", []).append("Verified DMARC passed through at least one aligned identifier.")
            if item.get("rule") == "malformed_received" and str(item.get("evidence", {}).get("raw_header", "")).lstrip().lower().startswith("by "):
                item["severity"] = "info"
                item.setdefault("limitations", []).append("A receiver-added by-only hop is valid delivery metadata.")
            findings.append(item)
        parsed["reported_authentication"] = {
            "results": header.get("authentication", {}),
            "independently_verified": False,
            "limitations": ["Supplied authentication headers may be forged. Refer to verified_authentication for local DKIM checks."]
        }
        if verified.get("spf", {}).get("status") == "fail" and verified.get("spf", {}).get("source") in {"trusted_receiver", "trusted_smtp_context"}:
            findings.append(Finding(category="Authentication", rule="trusted_spf_failure", severity="medium", confidence=.9,
                title="Trusted delivery receiver reported SPF failure", description="The SMTP sending IP failed the receiving provider's authorization check.", evidence=verified["spf"], limitations=verified["limitations"]))
        if verified["dkim"]["status"] == "fail":
            findings.append(Finding(
                category="Authentication", rule="local_dkim_failure", severity="medium",
                confidence=0.9, title="Original-message DKIM verification failed",
                description="The checked signatures did not validate against the current public keys.",
                evidence=verified["dkim"], limitations=verified["limitations"]
            ))
        if verified["dmarc"]["status"] == "fail":
            findings.append(Finding(category="Authentication", rule="verified_dmarc_failure", severity="high",
                confidence=0.92, title="Verified identifiers fail DMARC alignment",
                description="Neither verified DKIM nor trusted receiver SPF aligns with the visible From domain.",
                evidence=verified["dmarc"], limitations=verified["limitations"]))

        # ==============================================================
        # 8. URL ANALYSIS
        # ==============================================================

        references = (
            parsed.get(
                "url_references",
                [],
            )
            or [
                {
                    "href": url,
                    "visible_text": "",
                }
                for url in parsed.get(
                    "urls",
                    [],
                )
            ]
        )

        for item in parsed.get("attachments", []):
            for value in item.get("embedded_urls", [])[:20]:
                references.append({"href": value, "visible_text": "QR or attachment URL"})

        from backend.url_expander import URLExpander
        expansions = []
        if URLAnalyzer:
            for reference in list(references)[:100]:
                target = str(reference.get("href", ""))
                if len(expansions) >= 2:
                    break
                if URLAnalyzer.analyze_url(target).get("is_shortener"):
                    expansion = URLExpander.expand(target)
                    expansions.append(expansion)
                    if expansion.get("expanded"):
                        references.append({"href": expansion["final_url"], "visible_text": "Expanded short URL"})
        parsed["url_expansions"] = expansions

        url_result = (
            URLAnalyzer.analyze_references(
                references
            )
            if URLAnalyzer
            else {
                "findings": [],
                "urls": [],
                "highest_risk": 0,
            }
        )
        parsed["url_analysis"] = url_result

        sender_domain = str(verified.get("dmarc", {}).get("from_domain", "")).lower().rstrip(".")
        def aligned_first_party(item):
            registered = str(item.get("registered_domain", "")).lower().rstrip(".")
            return verified.get("dmarc", {}).get("status") == "pass" and bool(registered) and (
                sender_domain == registered or sender_domain.endswith("." + registered)
            )
        for item in url_result.get("findings", []):
            item = dict(item)
            if aligned_first_party(item.get("evidence", {})):
                item["severity"] = "info"
                item.setdefault("limitations", []).append("The URL is first-party aligned with an independently authenticated sender; heuristic structure alone is insufficient for a threat verdict.")
            findings.append(item)
        from backend.intelligence.reputation_provider import URLReputationProvider
        reputation = URLReputationProvider().lookup([str(item.get("href", "")) for item in references])
        parsed["url_reputation"] = reputation
        findings.extend(reputation.get("findings", []))
        suspicious_urls = [item for item in url_result.get("urls", []) if int(item.get("risk_score", 0)) >= 35 and not aligned_first_party(item)]
        weak_credential_context = {
            "authentication", "card details", "credit card", "debit card",
            "log in", "login", "verification", "verify", "account",
        }
        strong_credentials = [
            cue for cue in credentials
            if str(cue).strip().lower() not in weak_credential_context
        ]
        if strong_credentials and suspicious_urls:
            findings.append(self._finding(
                "Text", "credential_request_with_suspicious_link", "high", 0.9,
                "Credential request includes a suspicious link",
                "Credential-related language is paired with a URL that has independent suspicious characteristics.",
                {"suspicious_url_count": len(suspicious_urls), "credential_cues": strong_credentials[:5]},
            ))

        # ==============================================================
        # 9. ATTACHMENT ANALYSIS
        # ==============================================================

        attachment_result = (
            AttachmentAnalyzer.analyze(
                parsed.get(
                    "attachments",
                    [],
                )
            )
        )

        parsed["attachment_analysis"] = attachment_result
        for attachment in attachment_result.get("attachments", []):
            score = int(attachment.get("score", 0))
            if score < 35:
                continue
            severity = "critical" if score >= 75 else "high" if score >= 50 else "medium"
            findings.append(Finding(
                category="Attachment", rule="attachment_hash_blocklist" if attachment.get("reputation", {}).get("matched") else "attachment_static_" + severity,
                severity=severity, confidence=0.95,
                title="Potentially dangerous attachment",
                description="; ".join(attachment.get("reasons", [])),
                evidence={key: attachment.get(key) for key in ("filename", "sha256", "magic_signature", "score", "analysis_skipped")},
                limitations=["Static inspection identifies risky file properties; it does not establish malicious execution."]
            ))

        # ==============================================================
        # 10. ORIGIN TRACE
        # ==============================================================

        origin_trace = (
            OriginTraceService.build(
                parsed,
                self.ip_provider,
            )
        )

        parsed["origin_trace"] = (
            origin_trace
        )

        findings.extend(
            origin_trace.get(
                "findings",
                [],
            )
        )

        # ==============================================================
        # 11. DOMAIN INTELLIGENCE
        # ==============================================================

        origin_domains = []

        for hop in parsed.get(
            "network_chain",
            [],
        ):
            origin_domains.extend(
                {
                    "domain": hostname,
                    "source": "received",
                }
                for hostname in hop.get(
                    "hostnames",
                    [],
                )
                if "." in str(
                    hostname
                )
            )

        metadata_domain = (
            str(
                metadata.get(
                    "from",
                    "",
                )
            )
            .split("@")[-1]
            .strip("> ")
        )

        if metadata_domain:
            origin_domains.insert(0,
                {
                    "domain": metadata_domain,
                    "source": "from",
                }
            )

        domain_results = []

        seen_domains = set()
        for item in origin_domains:
            normalized_domain = item["domain"].lower().rstrip(".")
            if normalized_domain in seen_domains:
                continue
            if len(seen_domains) >= 8:
                break
            seen_domains.add(normalized_domain)
            result = (
                self.domain_provider.inspect(
                    item["domain"],
                    item["source"],
                    [
                        candidate["ip"]
                        for candidate in origin_trace.get(
                            "origin_candidates",
                            [],
                        )
                    ],
                )
            )

            domain_results.append(
                result
            )

            findings.extend(
                result.get(
                    "findings",
                    [],
                )
            )

        parsed["domain_intelligence"] = {
            "domains": domain_results,
            "domain_limit": 8,
            "limited": len({item["domain"].lower().rstrip(".") for item in origin_domains}) > 8,
            "limitations": [
                (
                    "DNS data is time-dependent and does "
                    "not prove ownership or malicious intent."
                )
            ],
        }

        # ==============================================================
        # 12. IP INTELLIGENCE
        # ==============================================================

        parsed["ip_intelligence"] = [
            candidate.get(
                "intelligence"
            )
            for candidate in origin_trace.get(
                "origin_candidates",
                [],
            )
            if candidate.get(
                "intelligence"
            )
        ]

        # ==============================================================
        # 13. EMAIL ML AS CORROBORATED SUPPORTING EVIDENCE
        # ==============================================================

        structural_warning = any(
            str(getattr(item, "severity", item.get("severity", "info") if isinstance(item, dict) else "info")).lower()
            in {"medium", "high", "critical"}
            and str(getattr(item, "category", item.get("category", "") if isinstance(item, dict) else "")).lower()
            in {"authentication", "url", "attachment", "sender identity", "bec"}
            for item in findings
        )
        verified_dmarc = verified.get("dmarc", {})
        trusted_transactional_context = (
            (verified_dmarc.get("status") == "pass" or verified_dmarc.get("receiver_status") in {"pass", "bestguesspass"})
            and not structural_warning
        )
        nlp["trusted_transactional_context"] = trusted_transactional_context

        try:
            ml_analysis = {"available": True, **LocalMLClassifier.predict(text)}
            probability = float(ml_analysis.get("phishing_probability", 0.0))
            corroborating = [
                item for item in findings
                if str(getattr(item, "severity", item.get("severity", "info") if isinstance(item, dict) else "info")).lower()
                in {"medium", "high", "critical"}
            ]
            ml_analysis["used_in_decision"] = False
            hard_structural = any(str(getattr(item, "severity", item.get("severity", "info") if isinstance(item, dict) else "info")).lower() in {"high", "critical"} for item in findings)
            if ml_analysis.get("calibration_status") == "platt_scaling" and probability >= 0.60 and not hard_structural and not trusted_transactional_context:
                findings.append(self._finding(
                    "Machine learning", "calibrated_ml_review", "medium", probability,
                    "Calibrated text model requests review",
                    "Structural evidence is inconclusive; the calibrated text model detects attack-like language. This is an inconclusive review, not confirmed phishing.",
                    {"phishing_probability": round(probability, 4), "threshold": 0.60},
                    ml_analysis.get("limitations", []),
                ))
                ml_analysis["used_in_decision"] = True
            elif ml_analysis.get("calibration_status") == "platt_scaling" and probability >= 0.60 and not hard_structural:
                findings.append(self._finding(
                    "Machine learning", "calibrated_ml_observation", "low", probability,
                    "Text model noticed attack-like wording",
                    "The calibrated text model noticed wording seen in attacks, but its confidence is insufficient to change the verdict without technical evidence.",
                    {"phishing_probability": round(probability, 4), "review_threshold": 0.60,
                     "authenticated_transactional_context": trusted_transactional_context},
                    ml_analysis.get("limitations", []),
                ))
            if probability >= 0.55 and corroborating and not hard_structural and not ml_analysis["used_in_decision"]:
                severity = "medium" if probability >= 0.75 and len(corroborating) >= 2 else "low"
                findings.append(self._finding(
                    "Machine learning", "corroborated_email_ml", severity,
                    min(0.9, max(0.55, probability)),
                    "Email ML supports independently detected threat signals",
                    "The email text model agrees with separate explainable evidence; it is not used as a standalone verdict.",
                    {"phishing_probability": round(probability, 4), "corroborating_findings": len(corroborating)},
                    ml_analysis.get("limitations", []),
                ))
                ml_analysis["used_in_decision"] = True
            parsed["ml_analysis"] = ml_analysis
        except Exception:
            parsed["ml_analysis"] = {
                "available": False,
                "used_in_decision": False,
                "classification": "UNAVAILABLE",
                "limitations": ["An evaluated email model must be provisioned. Explainable analysis remains available."],
            }

        # ==============================================================
        # 14. NORMALIZE FINDINGS
        # ==============================================================

        normalized_findings = [
            (
                finding.model_dump()
                if hasattr(
                    finding,
                    "model_dump",
                )
                else finding
            )
            for finding in findings
        ]

        # ==============================================================
        # 15. FINAL RISK ENGINE
        # ==============================================================

        risk = RiskEngine.evaluate(
            normalized_findings,
            nlp,
        )
        parsed["risk_decision"] = risk

        # ==============================================================
        # 16. MULTILINGUAL RESULT
        #
        # Keep BOTH names for compatibility:
        #
        # multilingual_score
        # score
        #
        # "multilingual_score" is the canonical field.
        # ==============================================================

        parsed["nlp_analysis"] = nlp
        parsed["multilingual_analysis"] = {
            "language": multilingual.get(
                "language",
                "Unknown",
            ),
            "language_code": multilingual.get(
                "language_code",
                "und",
            ),
            "language_confidence": multilingual.get(
                "language_confidence",
                0.0,
            ),
            "script": multilingual.get(
                "script",
                "unknown",
            ),
            "is_multilingual": multilingual.get(
                "is_multilingual",
                False,
            ),
            "detection_method": multilingual.get(
                "detection_method",
                "",
            ),
            "detected_scripts": multilingual.get(
                "detected_scripts",
                [],
            ),
            "findings": multilingual.get(
                "multilingual_findings",
                {},
            ),
            "multilingual_findings": multilingual.get(
                "multilingual_findings",
                {},
            ),
            "multilingual_score": multilingual_score,
            "score": multilingual_score,
        }

        # ==============================================================
        # 16. NLP MULTILINGUAL METADATA
        # ==============================================================

        parsed["nlp_multilingual"] = {
            "language": multilingual.get(
                "language",
                "Unknown",
            ),
            "language_code": multilingual.get(
                "language_code",
                "und",
            ),
            "language_confidence": multilingual.get(
                "language_confidence",
                0.0,
            ),
            "script": multilingual.get(
                "script",
                "unknown",
            ),
            "multilingual_score": multilingual_score,
        }

        # ==============================================================
        # 17. LIMITATIONS
        # ==============================================================

        limitations = [
            (
                "Authentication success does not prove "
                "that a message is safe."
            ),
            *OriginTraceService.LIMITATIONS,
            (
                "IP and DNS intelligence is best-effort "
                "and provider-dependent."
            ),
            (
                "Multilingual language detection provides "
                "contextual evidence and does not by itself "
                "prove malicious intent."
            ),
        ]

        skipped = sum(bool(item.get("analysis_skipped")) for item in parsed.get("attachments", []))
        if skipped:
            limitations.append(f"Content inspection was unavailable for {skipped} attachment(s); the verdict does not establish their safety.")

        # ==============================================================
        # 18. EVIDENCE RECORD
        # ==============================================================

        evidence = EvidenceRecord(
            sha256=hashlib.sha256(
                raw
            ).hexdigest(),
            byte_size=len(raw),
            analysis_version=self.VERSION,
            source_type=source_type,
        )

        # ==============================================================
        # 19. SANITIZE PARSED RESULT
        # ==============================================================

        sanitized = dict(
            parsed
        )
        from backend.compliance import IndiaPrivacyPreserver
        sanitized.pop(
            "raw_bytes",
            None,
        )
        for item in sanitized.get("attachments", []):
            image = item.get("image_analysis") or {}
            ocr_text = image.pop("ocr_text", "")
            if ocr_text:
                image["ocr_text_sha256"] = hashlib.sha256(ocr_text.encode("utf-8")).hexdigest()
                image["ocr_character_count"] = len(ocr_text)
                image["ocr_text_preview"] = IndiaPrivacyPreserver.redact_text(ocr_text[:600])
        # Raw originals remain in evidence storage, not in routine API results.
        sanitized["body"] = IndiaPrivacyPreserver.redact_structure(sanitized.get("body") or {})

        # ==============================================================
        # 20. FINAL V2 RESULT
        # ==============================================================

        return AnalysisResult(
            email_id=str(
                uuid4()
            ),
            evidence=evidence,
            classification=risk[
                "classification"
            ],
            risk_score=risk[
                "risk_score"
            ],
            confidence=risk[
                "confidence"
            ],
            findings=findings,
            parsed=sanitized,
            limitations=limitations,
        )
