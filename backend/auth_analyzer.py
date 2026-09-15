"""Email authentication evidence parser.

This module interprets authentication results added by a receiving mail
provider. It deliberately does *not* claim that a DKIM-Signature header alone
proves a valid signature: cryptographic verification needs the original
canonicalised message and DNS lookup.
"""

import re
from typing import Dict, List, Optional, Tuple
from email.utils import parseaddr


class AuthenticationAnalyzer:
    """Analyze email authentication status"""

    @staticmethod
    def analyze_headers(headers: Dict[str, str], 
                       from_address: str = "",
                       body: str = "") -> Dict[str, any]:
        """
        Analyze email authentication headers
        
        Args:
            headers: Dictionary of email headers
            from_address: From header value
            body: Email body (for verification context)
            
        Returns:
            Dictionary with authentication analysis
        """

        analysis = {
            "spf_status": "UNKNOWN",
            "dkim_status": "UNKNOWN",
            "dmarc_status": "UNKNOWN",
            "authenticated": False,
            "anomalies": [],
            "authentication_source": "unavailable",
            "verification_scope": "Authentication-Results and Received-SPF are upstream-reported results; this parser does not cryptographically re-verify DKIM or independently execute SPF/DMARC DNS checks.",
        }

        # 1. EXTRACT AUTHENTICATION-RESULTS HEADER
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            AuthenticationAnalyzer._parse_authentication_results(
                auth_results, analysis
            )
            analysis["authentication_source"] = "upstream_authentication_results"

        # 2. PARSE SPF HEADER
        received_spf = headers.get("Received-SPF", "")
        if received_spf:
            AuthenticationAnalyzer._parse_spf_header(received_spf, analysis)
            if analysis["authentication_source"] == "unavailable":
                analysis["authentication_source"] = "upstream_received_spf"

        # 3. RECORD DKIM-SIGNATURE WITHOUT MISTAKING IT FOR A PASS.
        # A forged message can contain this header. A PASS is accepted only
        # when an upstream Authentication-Results header explicitly reports it.
        dkim_sig = headers.get("DKIM-Signature", "")
        analysis["dkim_signature_present"] = bool(dkim_sig)
        if dkim_sig and analysis["dkim_status"] == "UNKNOWN":
            analysis["dkim_status"] = "UNVERIFIED"
            analysis["anomalies"].append("DKIM-Signature is present but no trusted authentication result was supplied.")
        elif not dkim_sig and analysis["dkim_status"] == "UNKNOWN":
            analysis["dkim_status"] = "NONE"

        # 4. PARSE FROM HEADER
        from_analysis = AuthenticationAnalyzer._analyze_from_header(
            from_address, headers
        )
        analysis.update(from_analysis)

        # 5. CHECK REPLY-TO MISMATCH
        reply_to = headers.get("Reply-To", "")
        if reply_to and from_address:
            reply_domain = AuthenticationAnalyzer._extract_domain(reply_to)
            from_domain = AuthenticationAnalyzer._extract_domain(from_address)

            if reply_domain != from_domain:
                analysis["anomalies"].append(
                    f"Reply-To domain mismatch: {reply_domain} != {from_domain}"
                )

        # 6. CHECK RETURN-PATH
        return_path = headers.get("Return-Path", "")
        if return_path and from_address:
            return_domain = AuthenticationAnalyzer._extract_domain(return_path)
            from_domain = AuthenticationAnalyzer._extract_domain(from_address)

            if return_domain and return_domain != from_domain:
                analysis["anomalies"].append(
                    f"Return-Path mismatch: {return_domain} != {from_domain}"
                )

        # 7. SET AUTHENTICATED FLAG
        if (analysis["spf_status"] == "PASS" or 
            analysis["dkim_status"] == "PASS" or
            analysis["dmarc_status"] == "PASS"):
            analysis["authenticated"] = True

        return analysis

    @staticmethod
    def _parse_authentication_results(auth_results: str, 
                                     analysis: Dict) -> None:
        """Parse Authentication-Results header"""

        auth_results_lower = auth_results.lower()

        # SPF extraction
        if "spf=" in auth_results_lower:
            if "spf=pass" in auth_results_lower:
                analysis["spf_status"] = "PASS"
            elif "spf=fail" in auth_results_lower:
                analysis["spf_status"] = "FAIL"
            elif "spf=neutral" in auth_results_lower:
                analysis["spf_status"] = "NEUTRAL"
            elif "spf=none" in auth_results_lower:
                analysis["spf_status"] = "NONE"

        # DKIM extraction
        if "dkim=" in auth_results_lower:
            if "dkim=pass" in auth_results_lower:
                analysis["dkim_status"] = "PASS"
            elif "dkim=fail" in auth_results_lower:
                analysis["dkim_status"] = "FAIL"
            elif "dkim=neutral" in auth_results_lower:
                analysis["dkim_status"] = "NEUTRAL"
            elif "dkim=none" in auth_results_lower:
                analysis["dkim_status"] = "NONE"

        # DMARC extraction
        if "dmarc=" in auth_results_lower:
            if "dmarc=pass" in auth_results_lower:
                analysis["dmarc_status"] = "PASS"
            elif "dmarc=fail" in auth_results_lower:
                analysis["dmarc_status"] = "FAIL"
            elif "dmarc=none" in auth_results_lower:
                analysis["dmarc_status"] = "NONE"

    @staticmethod
    def _parse_spf_header(received_spf: str, analysis: Dict) -> None:
        """Parse Received-SPF header"""

        spf_lower = received_spf.lower()

        if "pass" in spf_lower:
            analysis["spf_status"] = "PASS"
        elif "fail" in spf_lower:
            analysis["spf_status"] = "FAIL"
        elif "neutral" in spf_lower:
            analysis["spf_status"] = "NEUTRAL"
        elif "none" in spf_lower:
            analysis["spf_status"] = "NONE"

    @staticmethod
    def _analyze_from_header(from_address: str, 
                            headers: Dict[str, str]) -> Dict:
        """Analyze From header for spoofing indicators"""

        analysis = {}

        if not from_address:
            return analysis

        # Extract domain from From header
        from_domain = AuthenticationAnalyzer._extract_domain(from_address)

        # Check for suspicious From formats
        if "<" not in from_address and "@" in from_address:
            # Simple email format
            pass
        elif "<" in from_address:
            # Display name format: "Name" <email@domain>
            # Extract actual email
            match = re.search(r'<([^>]+)>', from_address)
            if match:
                actual_email = match.group(1)
                actual_domain = AuthenticationAnalyzer._extract_domain(actual_email)
                if actual_domain:
                    from_domain = actual_domain

        return analysis

    @staticmethod
    def _extract_domain(email_or_address: str) -> Optional[str]:
        """Extract domain from email address or header value"""

        if not email_or_address:
            return None

        # Remove angle brackets
        email_or_address = email_or_address.strip("<>")

        # Extract email if there's a display name
        if "<" in email_or_address:
            match = re.search(r'<([^>]+)>', email_or_address)
            if match:
                email_or_address = match.group(1)

        # Split by @
        if "@" in email_or_address:
            parts = email_or_address.split("@")
            domain = parts[-1].strip()
            return domain.lower() if domain else None

        return None

    @staticmethod
    def extract_spf_record(headers: Dict[str, str]) -> Optional[str]:
        """Extract SPF record information from headers"""

        # Check for SPF-related headers
        for key in ["Received-SPF", "Authentication-Results"]:
            value = headers.get(key, "")
            if "spf" in value.lower():
                return value

        return None

    @staticmethod
    def extract_dmarc_info(headers: Dict[str, str]) -> Optional[str]:
        """Extract DMARC information from headers"""

        auth_results = headers.get("Authentication-Results", "")
        if "dmarc" in auth_results.lower():
            return auth_results

        return None

    @staticmethod
    def detect_spoofing_indicators(from_address: str, 
                                  headers: Dict[str, str]) -> List[str]:
        """Detect common email spoofing indicators"""

        indicators = []

        if not from_address:
            return indicators

        from_domain = AuthenticationAnalyzer._extract_domain(from_address)

        # Check Return-Path
        return_path = headers.get("Return-Path", "")
        if return_path:
            return_domain = AuthenticationAnalyzer._extract_domain(return_path)
            if return_domain and return_domain != from_domain:
                indicators.append("Return-Path domain mismatch")

        # Check Reply-To
        reply_to = headers.get("Reply-To", "")
        if reply_to:
            reply_domain = AuthenticationAnalyzer._extract_domain(reply_to)
            if reply_domain and reply_domain != from_domain:
                indicators.append("Reply-To domain mismatch")

        # Check Sender
        sender = headers.get("Sender", "")
        if sender:
            sender_domain = AuthenticationAnalyzer._extract_domain(sender)
            if sender_domain and sender_domain != from_domain:
                indicators.append("Sender domain mismatch")

        return indicators
