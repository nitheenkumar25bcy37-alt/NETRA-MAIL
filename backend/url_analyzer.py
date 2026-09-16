"""
NETRA-Mail URL Intelligence Engine
----------------------------------

Enhanced heuristic URL analyzer.

Design goals:
- Preserve the existing URLAnalyzer API.
- Improve detection of generic phishing URLs.
- Keep explanations/evidence for the SOC dashboard.
- Avoid depending on live external reputation services.
- Produce a 0-100 risk score.
- Avoid treating HTTPS as proof of legitimacy.
"""

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qs, unquote, urlparse


class URLAnalyzer:

    # ============================================================
    # URL EXTRACTION
    # ============================================================

    URL_PATTERN = re.compile(
        r"(?:https?://|www\.)[^\s<>'\"`]+",
        re.I,
    )

    # ============================================================
    # KNOWN SHORTENERS
    # ============================================================

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "rebrand.ly",
        "tiny.cc",
        "lnkd.in",
        "s.id",
        "soo.gd",
        "shorte.st",
        "bc.vc",
    }

    # ============================================================
    # PROTECTED BRANDS
    # ============================================================

    BRANDS = {
        "PayPal": ["paypal.com"],
        "Microsoft": [
            "microsoft.com",
            "live.com",
            "office.com",
            "outlook.com",
        ],
        "Google": [
            "google.com",
            "gmail.com",
            "googleapis.com",
            "gstatic.com",
            "googleusercontent.com",
        ],
        "Apple": [
            "apple.com",
            "icloud.com",
        ],
        "Amazon": [
            "amazon.com",
            "amazon.in",
            "amazon.co.uk",
        ],
        "Facebook": [
            "facebook.com",
            "meta.com",
        ],
        "Instagram": [
            "instagram.com",
        ],
        "Netflix": [
            "netflix.com",
        ],
        "LinkedIn": [
            "linkedin.com",
        ],
        "GitHub": [
            "github.com",
        ],
        "SBI": [
            "sbi.co.in",
            "onlinesbi.sbi",
        ],
        "HDFC": [
            "hdfcbank.com",
        ],
        "ICICI": [
            "icicibank.com",
        ],
        "Axis": [
            "axisbank.com",
        ],
        "DHL": [
            "dhl.com",
        ],
        "FedEx": [
            "fedex.com",
        ],
        "Adobe": [
            "adobe.com",
        ],
        "Dropbox": [
            "dropbox.com",
        ],
        "DocuSign": [
            "docusign.com",
        ],
    }

    # ============================================================
    # SECURITY / PHISHING KEYWORDS
    # ============================================================

    KEYWORDS = {
        "login",
        "log-in",
        "signin",
        "sign-in",
        "sign_in",
        "verify",
        "verification",
        "validate",
        "validation",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "passwd",
        "credential",
        "credentials",
        "authenticate",
        "authentication",
        "billing",
        "payment",
        "wallet",
        "confirm",
        "confirmation",
        "recover",
        "recovery",
        "suspended",
        "suspension",
        "unlock",
        "reset",
        "activate",
        "activation",
        "webmail",
        "portal",
        "invoice",
        "refund",
        "support",
        "customer",
        "banking",
        "bank",
        "signin",
        "mfa",
        "2fa",
        "otp",
        "identity",
        "document",
        "kyc",
    }

    # ============================================================
    # HIGH-RISK PATH TERMS
    # ============================================================

    HIGH_RISK_TERMS = {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "credential",
        "payment",
        "billing",
        "wallet",
        "recover",
        "reset",
        "suspended",
        "unlock",
        "authenticate",
        "authentication",
        "secure-login",
        "account-verification",
        "confirm-account",
        "validate-account",
        "security-check",
    }

    # ============================================================
    # COMMON SUSPICIOUS TLDs
    # ============================================================

    SUSPICIOUS_TLDS = {
        ".zip",
        ".mov",
        ".click",
        ".top",
        ".xyz",
        ".icu",
        ".cam",
        ".buzz",
        ".work",
        ".rest",
        ".fit",
        ".live",
        ".monster",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".pw",
        ".download",
        ".loan",
        ".win",
        ".review",
        ".party",
        ".stream",
        ".link",
        ".site",
        ".online",
        ".shop",
        ".support",
        ".cloud",
    }

    # ============================================================
    # URL QUERY/PARAMETER INDICATORS
    # ============================================================

    SENSITIVE_PARAMETER_NAMES = {
        "password",
        "passwd",
        "pass",
        "pwd",
        "username",
        "user",
        "login",
        "email",
        "token",
        "auth",
        "session",
        "sid",
        "otp",
        "code",
        "verify",
        "verification",
        "redirect",
        "url",
        "return",
        "continue",
    }

    # ============================================================
    # BRAND MODIFIERS
    # ============================================================

    BRAND_MODIFIERS = {
        "login",
        "secure",
        "security",
        "verify",
        "verification",
        "account",
        "accounts",
        "update",
        "support",
        "service",
        "help",
        "auth",
        "authenticate",
        "confirm",
        "confirmation",
        "billing",
        "payment",
        "alert",
        "alerts",
        "notification",
        "notifications",
        "recovery",
        "recover",
        "unlock",
        "sso",
        "portal",
    }

    # ============================================================
    # PUBLIC / COMMON HOSTING PROVIDERS
    # ============================================================

    HOSTING_PROVIDERS = {
        "pages.dev",
        "github.io",
        "gitlab.io",
        "web.app",
        "firebaseapp.com",
        "netlify.app",
        "vercel.app",
        "onrender.com",
        "blogspot.com",
        "blogspot.in",
        "wordpress.com",
        "weebly.com",
        "wixsite.com",
        "000webhostapp.com",
        "000webhost.io",
        "glitch.me",
    }

    # ============================================================
    # URL EXTRACTION
    # ============================================================

    @classmethod
    def extract_urls(cls, text):

        found = []

        for value in cls.URL_PATTERN.findall(text or ""):

            value = value.rstrip(
                ".,;:!?)]}>\"'"
            )

            if value.lower().startswith("www."):
                value = "http://" + value

            if value not in found:
                found.append(value)

        return found

    # ============================================================
    # ENTROPY
    # ============================================================

    @staticmethod
    def _entropy(value):

        if not value:
            return 0.0

        counts = Counter(value)
        length = len(value)

        entropy = 0.0

        for count in counts.values():

            probability = count / length

            entropy -= probability * math.log2(
                probability
            )

        return entropy

    # ============================================================
    # EDIT DISTANCE
    # ============================================================

    @staticmethod
    def levenshtein_distance(a, b):

        if a == b:
            return 0

        if not a:
            return len(b)

        if not b:
            return len(a)

        prev = list(
            range(len(b) + 1)
        )

        for i, ca in enumerate(a, 1):

            cur = [i]

            for j, cb in enumerate(b, 1):

                cur.append(
                    min(
                        cur[-1] + 1,
                        prev[j] + 1,
                        prev[j - 1] + (ca != cb),
                    )
                )

            prev = cur

        return prev[-1]

    # ============================================================
    # REGISTERED-DOMAIN APPROXIMATION
    # ============================================================

    @classmethod
    def _base_domain(cls, hostname):

        labels = [
            x
            for x in hostname.split(".")
            if x
        ]

        if len(labels) < 2:
            return hostname

        # Common multi-part public suffixes.
        if (
            len(labels) >= 3
            and labels[-2] in {
                "co",
                "com",
                "net",
                "org",
                "gov",
                "ac",
                "edu",
            }
            and len(labels[-1]) in {2, 3}
        ):

            return ".".join(
                labels[-3:]
            )

        return ".".join(
            labels[-2:]
        )

    # ============================================================
    # STATIC SSRF / INTERNAL DESTINATION CLASSIFICATION
    # ============================================================

    @staticmethod
    def _classify_ip_address(hostname):
        """Classify an IP without making any network connection."""
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            return {
                "is_private_ip": False,
                "is_loopback": False,
                "is_link_local": False,
                "is_reserved_ip": False,
                "is_multicast": False,
                "is_unspecified_ip": False,
                "ssrf_risk": False,
            }

        is_private = ip.is_private
        is_loopback = ip.is_loopback
        is_link_local = ip.is_link_local
        is_reserved = ip.is_reserved
        is_multicast = ip.is_multicast
        is_unspecified = ip.is_unspecified

        # Treat non-public/special-use destinations as SSRF-sensitive.
        ssrf_risk = (
            is_private
            or is_loopback
            or is_link_local
            or is_reserved
            or is_multicast
            or is_unspecified
        )

        return {
            "is_private_ip": is_private,
            "is_loopback": is_loopback,
            "is_link_local": is_link_local,
            "is_reserved_ip": is_reserved,
            "is_multicast": is_multicast,
            "is_unspecified_ip": is_unspecified,
            "ssrf_risk": ssrf_risk,
        }

    @staticmethod
    def _is_local_hostname(hostname):
        """Detect obvious local/internal hostnames without DNS resolution."""
        host = (hostname or "").lower().rstrip(".")

        if not host:
            return False

        local_exact = {
            "localhost",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
            "broadcasthost",
        }

        if host in local_exact:
            return True

        # Internal single-label names and common local suffixes.
        if "." not in host:
            return True

        internal_suffixes = (
            ".localhost",
            ".local",
            ".localdomain",
            ".internal",
            ".intranet",
            ".home",
            ".lan",
        )

        return host.endswith(internal_suffixes)

    # ============================================================
    # MAIN URL ANALYSIS
    # ============================================================

    @classmethod
    def analyze_url(cls, url):

        result = {

            "url": url,

            "hostname": None,

            "scheme": None,

            "is_https": False,

            "is_ip_address": False,

            "is_shortener": False,

            "suspicious_keywords": [],

            "brand_impersonation": [],

            "typosquatting": [],

            "risk_score": 0,

            "risk_reasons": [],

            # New explainability fields
            "url_length": 0,

            "hostname_length": 0,

            "path_length": 0,

            "query_length": 0,

            "subdomain_count": 0,

            "hyphen_count": 0,

            "digit_count": 0,

            "special_character_count": 0,

            "encoded_character_count": 0,

            "suspicious_parameters": [],

            "suspicious_tld": False,

            "punycode": False,

            "high_entropy_hostname": False,

            "hosting_provider": False,

            "userinfo_present": False,

            "port_present": False,

            # Static SSRF / internal-destination indicators.
            # No DNS lookup or remote network request is performed.
            "is_private_ip": False,

            "is_loopback": False,

            "is_link_local": False,

            "is_reserved_ip": False,

            "is_multicast": False,

            "is_unspecified_ip": False,

            "is_local_hostname": False,

            "ssrf_risk": False,

            "redirect_wrapper": None,

            "redirect_target": None,

            "ml_analysis": {
                "available": False,
                "used_in_score": False,
            },

        }

        # --------------------------------------------------------
        # Parse safely
        # --------------------------------------------------------

        try:

            decoded_url = unquote(
                str(url)
            )

            parsed = urlparse(
                decoded_url
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower().strip(".")

        except Exception:

            result["risk_score"] = 70

            result["risk_reasons"].append(
                "URL could not be parsed safely"
            )

            result["risk_level"] = "HIGH"

            return result

        result["hostname"] = hostname

        result["scheme"] = (
            parsed.scheme.lower()
        )

        result["is_https"] = (
            parsed.scheme.lower()
            == "https"
        )

        # Gmail commonly rewrites legitimate links through Google's /url
        # redirect endpoint. Analyze the embedded destination instead of
        # treating wrapper length and encoded parameters as attacker signals.
        if (
            hostname in {"google.com", "www.google.com"}
            and parsed.path.rstrip("/") == "/url"
        ):
            query_values = parse_qs(parsed.query, keep_blank_values=False)
            target_values = query_values.get("q") or query_values.get("url") or []
            target = str(target_values[0]).strip() if target_values else ""
            target_parsed = urlparse(target)
            if target and target != str(url) and target_parsed.scheme in {"http", "https"} and target_parsed.hostname:
                nested = cls.analyze_url(target)
                nested["url"] = str(url)
                nested["redirect_wrapper"] = hostname
                nested["redirect_target"] = target
                nested["risk_reasons"] = list(dict.fromkeys([
                    "Known Google redirect wrapper; embedded destination analyzed directly",
                    *nested.get("risk_reasons", []),
                ]))
                return nested

        # --------------------------------------------------------
        # Basic measurements
        # --------------------------------------------------------

        url_text = str(url)

        path = unquote(
            parsed.path or ""
        )

        query = unquote(
            parsed.query or ""
        )

        result["url_length"] = len(
            url_text
        )

        result["hostname_length"] = len(
            hostname
        )

        result["path_length"] = len(
            path
        )

        result["query_length"] = len(
            query
        )

        labels = [
            x
            for x in hostname.split(".")
            if x
        ]

        explicit_phishing_terms = {
            "phishing",
            "phish",
            "fake",
            "credential-steal",
        }
        if any(term in hostname for term in explicit_phishing_terms):
            result["risk_score"] += 40
            result["risk_reasons"].append(
                "Hostname contains an explicit phishing or fake-site indicator"
            )

        registered_domain = cls._base_domain(hostname)
        registered_labels = set(registered_domain.split("."))
        subdomain_labels = set()
        for label in labels[:-2]:
            subdomain_labels.update(
                token for token in re.split(r"[._-]+", label) if token
            )
        misleading_terms = {
            "bank", "banking", "login", "secure", "verify", "account", "paypal",
            "microsoft", "google", "apple", "amazon",
        }
        misleading_subdomain_terms = sorted(
            subdomain_labels & misleading_terms
        )
        if misleading_subdomain_terms and not (subdomain_labels & registered_labels):
            result["suspicious_keywords"].append("misleading_subdomain")
            result["risk_score"] += 25
            result["risk_reasons"].append(
                "Brand or account language appears in a subdomain, not the registered domain"
            )

        result["subdomain_count"] = max(
            0,
            len(labels) - 2
        )

        result["hyphen_count"] = hostname.count(
            "-"
        )

        result["digit_count"] = sum(
            1
            for x in hostname
            if x.isdigit()
        )

        result["special_character_count"] = sum(
            1
            for x in url_text
            if x in "@?=&%_~"
        )

        result["encoded_character_count"] = len(
            re.findall(
                r"%[0-9a-fA-F]{2}",
                str(url),
            )
        )

        # --------------------------------------------------------
        # IP address / static SSRF classification
        # --------------------------------------------------------

        ip_classification = cls._classify_ip_address(hostname)

        if any(
            ip_classification.get(key)
            for key in (
                "is_private_ip",
                "is_loopback",
                "is_link_local",
                "is_reserved_ip",
                "is_multicast",
                "is_unspecified_ip",
            )
        ):
            result["is_ip_address"] = True
            result.update(ip_classification)

            result["risk_score"] += 25

            result["risk_reasons"].append(
                "URL uses a raw IP address as the hostname"
            )

            result["risk_score"] += 25
            result["risk_reasons"].append(
                "IP address belongs to a private, loopback, link-local, reserved, multicast, or unspecified range"
            )

        else:
            try:
                ipaddress.ip_address(hostname)
                result["is_ip_address"] = True
                result.update(ip_classification)

                result["risk_score"] += 25

                result["risk_reasons"].append(
                    "URL uses a raw IP address as the hostname"
                )

            except ValueError:
                # Hostname: classify obvious local/internal names only.
                result["is_local_hostname"] = cls._is_local_hostname(hostname)

                if result["is_local_hostname"]:
                    result["ssrf_risk"] = True
                    result["risk_score"] += 35
                    result["risk_reasons"].append(
                        "Hostname appears to reference a local or internal destination"
                    )

        # --------------------------------------------------------
        # URL shortener
        # --------------------------------------------------------

        if hostname in cls.SHORTENERS:

            result["is_shortener"] = True

            result["risk_score"] += 18

            result["risk_reasons"].append(
                "URL uses a known URL shortening service"
            )

        # --------------------------------------------------------
        # Punycode / IDN
        # --------------------------------------------------------

        if (
            "xn--" in hostname
            or any(
                ord(c) > 127
                for c in hostname
            )
        ):

            result["punycode"] = True

            result["risk_score"] += 25

            result["risk_reasons"].append(
                "Hostname contains IDN/punycode or non-ASCII characters"
            )

        # --------------------------------------------------------
        # Suspicious TLD
        # --------------------------------------------------------

        suspicious_tld = any(
            hostname.endswith(tld)
            for tld in cls.SUSPICIOUS_TLDS
        )

        if suspicious_tld:

            result["suspicious_tld"] = True

            result["risk_score"] += 15

            result["risk_reasons"].append(
                "Domain uses a TLD frequently observed in suspicious infrastructure"
            )

        # --------------------------------------------------------
        # Suspicious URL keywords
        # --------------------------------------------------------

        target = (
            path
            + " "
            + query
            + " "
            + hostname
        ).lower()

        keywords = sorted(
            keyword
            for keyword in cls.KEYWORDS
            if keyword in target
        )

        if misleading_subdomain_terms:
            keywords.append("misleading_subdomain")

        if keywords:

            result["suspicious_keywords"] = keywords

            result["risk_score"] += min(
                24,
                len(keywords) * 4,
            )

            result["risk_reasons"].append(
                "URL contains account, credential, security or payment keywords"
            )

        # --------------------------------------------------------
        # High-risk path terms
        # --------------------------------------------------------

        high_risk_matches = sorted(
            term
            for term in cls.HIGH_RISK_TERMS
            if term in (
                path + " " + query
            ).lower()
        )

        if high_risk_matches:

            bonus = min(
                15,
                len(high_risk_matches) * 5,
            )

            result["risk_score"] += bonus

            result["risk_reasons"].append(
                "URL path/query contains high-risk authentication or account-action terms"
            )

        # --------------------------------------------------------
        # Brand impersonation
        # --------------------------------------------------------

        for brand, legitimate_domains in cls.BRANDS.items():

            brand_lower = brand.lower()

            legitimate_host = any(
                hostname == domain
                or hostname.endswith(
                    "." + domain
                )
                for domain in legitimate_domains
            )

            if legitimate_host:
                continue

            # Brand appearing anywhere in hostname.
            if brand_lower in hostname:

                result["brand_impersonation"].append(
                    brand
                )

                result["risk_score"] += 30

                result["risk_reasons"].append(
                    f"Domain appears to contain the protected brand name {brand}"
                )

        # --------------------------------------------------------
        # Brand + modifier combination
        # --------------------------------------------------------

        host_tokens = re.split(
            r"[.\-_]+",
            hostname,
        )

        for brand, legitimate_domains in cls.BRANDS.items():

            brand_lower = brand.lower()

            if not any(
                hostname == domain
                or hostname.endswith("." + domain)
                for domain in legitimate_domains
            ):

                if brand_lower in host_tokens:

                    modifiers = set(
                        host_tokens
                    ) & cls.BRAND_MODIFIERS

                    if modifiers:

                        if brand not in result[
                            "brand_impersonation"
                        ]:

                            result[
                                "brand_impersonation"
                            ].append(
                                brand
                            )

                        result["risk_score"] += 15

                        result["risk_reasons"].append(
                            f"Brand name is combined with a suspicious service/account modifier"
                        )

        # --------------------------------------------------------
        # Typosquatting
        # --------------------------------------------------------

        base_label = (
            labels[-2]
            if len(labels) >= 2
            else (
                labels[0]
                if labels
                else ""
            )
        )

        # Strip obvious separators.
        normalized_base = re.sub(
            r"[^a-z0-9]",
            "",
            base_label,
        )

        for brand in cls.BRANDS:

            brand_normalized = re.sub(
                r"[^a-z0-9]",
                "",
                brand.lower(),
            )

            if (
                normalized_base
                and normalized_base != brand_normalized
                and len(normalized_base) >= 4
            ):

                distance = cls.levenshtein_distance(
                    normalized_base,
                    brand_normalized,
                )

                allowed_distance = (
                    1
                    if len(brand_normalized) <= 5
                    else 2
                )

                if distance <= allowed_distance:

                    result["typosquatting"].append(
                        brand
                    )

                    result["risk_score"] += 28

                    result["risk_reasons"].append(
                        f"Domain closely resembles legitimate {brand} infrastructure"
                    )

        # --------------------------------------------------------
        # @ userinfo trick
        # --------------------------------------------------------

        if parsed.username:

            result["userinfo_present"] = True

            result["risk_score"] += 20

            result["risk_reasons"].append(
                "URL contains embedded user information or an @-style redirection trick"
            )

        # --------------------------------------------------------
        # Explicit port
        # --------------------------------------------------------

        try:

            if parsed.port is not None:

                result["port_present"] = True

                if parsed.port not in {
                    80,
                    443,
                }:

                    result["risk_score"] += 12

                    result["risk_reasons"].append(
                        "URL uses a non-standard network port"
                    )

        except ValueError:

            result["risk_score"] += 10

            result["risk_reasons"].append(
                "URL contains an invalid or unusual port specification"
            )

        # --------------------------------------------------------
        # Excessive subdomains
        # --------------------------------------------------------

        if len(labels) >= 5:

            result["risk_score"] += 10

            result["risk_reasons"].append(
                "Unusually deep subdomain structure"
            )

        elif len(labels) >= 4:

            result["risk_score"] += 4

        # --------------------------------------------------------
        # Long hostname
        # --------------------------------------------------------

        if len(hostname) > 75:

            result["risk_score"] += 10

            result["risk_reasons"].append(
                "Unusually long hostname"
            )

        elif len(hostname) > 50:

            result["risk_score"] += 6

            result["risk_reasons"].append(
                "Long hostname"
            )

        # --------------------------------------------------------
        # Long complete URL
        # --------------------------------------------------------

        if len(url_text) > 250:

            result["risk_score"] += 10

            result["risk_reasons"].append(
                "Unusually long URL"
            )

        elif len(url_text) > 150:

            result["risk_score"] += 5

        # --------------------------------------------------------
        # Hyphen-heavy hostname
        # --------------------------------------------------------

        if hostname.count("-") >= 3:

            result["risk_score"] += 8

            result["risk_reasons"].append(
                "Hostname contains an unusually high number of hyphens"
            )

        # --------------------------------------------------------
        # Digit-heavy hostname
        # --------------------------------------------------------

        if len(hostname) >= 8:

            digit_ratio = sum(
                1
                for char in hostname
                if char.isdigit()
            ) / max(
                1,
                len(hostname),
            )

            if digit_ratio >= 0.30:

                result["risk_score"] += 8

                result["risk_reasons"].append(
                    "Hostname contains an unusually high proportion of digits"
                )

        # --------------------------------------------------------
        # Hostname entropy
        # --------------------------------------------------------

        hostname_entropy = cls._entropy(
            hostname
        )

        if (
            len(hostname) >= 15
            and hostname_entropy >= 4.0
        ):

            result[
                "high_entropy_hostname"
            ] = True

            result["risk_score"] += 8

            result["risk_reasons"].append(
                "Hostname has unusually high character entropy"
            )

        # --------------------------------------------------------
        # Suspicious parameters
        # --------------------------------------------------------

        parameter_names = []

        for part in query.split("&"):

            if "=" in part:

                name = part.split(
                    "=",
                    1,
                )[0].strip().lower()

                parameter_names.append(
                    name
                )

        sensitive = sorted(
            name
            for name in parameter_names
            if name in cls.SENSITIVE_PARAMETER_NAMES
        )

        if sensitive:

            result[
                "suspicious_parameters"
            ] = sensitive

            result["risk_score"] += min(
                15,
                len(sensitive) * 5,
            )

            result["risk_reasons"].append(
                "URL query contains credential, authentication or redirect parameters"
            )

        # --------------------------------------------------------
        # Excessive encoded characters
        # --------------------------------------------------------

        if result[
            "encoded_character_count"
        ] >= 5:

            result["risk_score"] += 8

            result["risk_reasons"].append(
                "URL contains multiple encoded characters"
            )

        # --------------------------------------------------------
        # Double encoding
        # --------------------------------------------------------

        if re.search(
            r"%25[0-9a-fA-F]{2}",
            str(url),
        ):

            result["risk_score"] += 15

            result["risk_reasons"].append(
                "URL appears to contain double-encoded content"
            )

        # --------------------------------------------------------
        # Excessive path separators
        # --------------------------------------------------------

        if path.count("/") >= 8:

            result["risk_score"] += 7

            result["risk_reasons"].append(
                "URL contains unusually deep path nesting"
            )

        # --------------------------------------------------------
        # Repeated separators / obfuscation
        # --------------------------------------------------------

        if (
            "//" in path
            or "///" in path
        ):

            result["risk_score"] += 6

            result["risk_reasons"].append(
                "URL path contains repeated slash separators"
            )

        # --------------------------------------------------------
        # Suspicious file extensions
        # --------------------------------------------------------

        lower_path = path.lower()

        suspicious_extensions = (
            ".exe",
            ".scr",
            ".zip",
            ".rar",
            ".7z",
            ".iso",
            ".img",
            ".js",
            ".hta",
            ".jar",
            ".lnk",
            ".msi",
        )

        if any(
            lower_path.endswith(ext)
            for ext in suspicious_extensions
        ):

            result["risk_score"] += 12

            result["risk_reasons"].append(
                "URL points to a potentially executable or archive file"
            )

        # --------------------------------------------------------
        # Hosting provider
        # --------------------------------------------------------

        base_domain = cls._base_domain(
            hostname
        )

        if any(
            hostname == provider
            or hostname.endswith(
                "." + provider
            )
            for provider in cls.HOSTING_PROVIDERS
        ):

            result[
                "hosting_provider"
            ] = True

            # Hosting is NOT inherently malicious.
            # Only give a small signal when combined with
            # phishing-style URL structure.
            if (
                keywords
                or result[
                    "brand_impersonation"
                ]
                or result[
                    "suspicious_parameters"
                ]
            ):

                result["risk_score"] += 8

                result["risk_reasons"].append(
                    "Suspicious URL is hosted on a commonly abused shared hosting platform"
                )

        # --------------------------------------------------------
        # HTTP is a weak signal only
        # --------------------------------------------------------

        if (
            parsed.scheme.lower()
            == "http"
        ):

            result["risk_score"] += 5

            result["risk_reasons"].append(
                "URL does not use HTTPS"
            )

        # IMPORTANT:
        # HTTPS does NOT reduce risk.
        # Phishing sites frequently use HTTPS.

        # --------------------------------------------------------
        # Suspicious hostname composition
        # --------------------------------------------------------

        if (
            len(labels) >= 3
            and any(
                len(label) >= 20
                for label in labels
            )
        ):

            result["risk_score"] += 8

            result["risk_reasons"].append(
                "Hostname contains an unusually long label"
            )

        # --------------------------------------------------------
        # Generic suspicious combination
        # --------------------------------------------------------

        signals = 0

        if keywords:
            signals += 1

        if suspicious_tld:
            signals += 1

        if result["subdomain_count"] >= 3:
            signals += 1

        if result["hyphen_count"] >= 2:
            signals += 1

        if result["encoded_character_count"] >= 3:
            signals += 1

        if result["suspicious_parameters"]:
            signals += 1

        if result["high_entropy_hostname"]:
            signals += 1

        if len(url_text) >= 120:
            signals += 1

        if signals >= 3:

            result["risk_score"] += 12

            result["risk_reasons"].append(
                "Multiple independent URL anomalies correlate with phishing-like structure"
            )

        elif signals >= 2:

            result["risk_score"] += 6

        # --------------------------------------------------------
        # Strong combinations
        # --------------------------------------------------------

        if (
            result["brand_impersonation"]
            and (
                keywords
                or result[
                    "suspicious_parameters"
                ]
            )
        ):

            result["risk_score"] += 18

            result["risk_reasons"].append(
                "Brand impersonation combined with credential/account activity"
            )

        if (
            result["typosquatting"]
            and keywords
        ):

            result["risk_score"] += 15

            result["risk_reasons"].append(
                "Typosquatting combined with phishing-related URL language"
            )

        if (
            result["is_ip_address"]
            and keywords
        ):

            result["risk_score"] += 12

            result["risk_reasons"].append(
                "Raw IP address combined with credential/account keywords"
            )

        # --------------------------------------------------------
        # Evaluated URL ML (bounded supporting evidence)
        # --------------------------------------------------------

        heuristic_score = int(result["risk_score"])
        try:
            from backend.url_ml_classifier import URLMLClassifier
            ml_analysis = URLMLClassifier.predict(url_text)
            ml_analysis["used_in_score"] = False
            probability = float(ml_analysis.get("phishing_probability", 0.0))

            # The model never creates a verdict by itself. It can strengthen a
            # URL only when the explainable analyzer independently found risk.
            # This protects ordinary unseen sites from model-only false alarms.
            if probability >= 0.98 and heuristic_score >= 25:
                result["risk_score"] += 15
                ml_analysis["used_in_score"] = True
                result["risk_reasons"].append(
                    "URL ML and independent structural indicators both identify phishing-like behavior"
                )
            elif probability >= 0.90 and heuristic_score >= 15:
                result["risk_score"] += 8
                ml_analysis["used_in_score"] = True
                result["risk_reasons"].append(
                    "URL ML supports the independently detected suspicious URL structure"
                )
            result["ml_analysis"] = ml_analysis
        except Exception as exc:
            result["ml_analysis"] = {
                "available": False,
                "used_in_score": False,
                "classification": "UNAVAILABLE",
                "limitations": ["URL ML was unavailable; explainable URL analysis remained active."],
                "error_type": type(exc).__name__,
            }

        # --------------------------------------------------------
        # Final normalization
        # --------------------------------------------------------

        result["risk_score"] = min(
            100,
            max(
                0,
                int(
                    round(
                        result["risk_score"]
                    )
                ),
            ),
        )

        # --------------------------------------------------------
        # Risk level
        # --------------------------------------------------------

        if result["risk_score"] >= 75:

            result["risk_level"] = "CRITICAL"

        elif result["risk_score"] >= 50:

            result["risk_level"] = "HIGH"

        elif result["risk_score"] >= 30:

            result["risk_level"] = "MEDIUM"

        else:

            result["risk_level"] = "LOW"

        # --------------------------------------------------------
        # Remove duplicate reasons
        # --------------------------------------------------------

        result["risk_reasons"] = list(
            dict.fromkeys(
                result["risk_reasons"]
            )
        )

        result["brand_impersonation"] = list(
            dict.fromkeys(
                result["brand_impersonation"]
            )
        )

        result["typosquatting"] = list(
            dict.fromkeys(
                result["typosquatting"]
            )
        )

        return result

    # ============================================================
    # TEXT ANALYSIS
    # ============================================================

    @classmethod
    def analyze_text(cls, text):

        urls = cls.extract_urls(
            text
        )

        results = [
            cls.analyze_url(url)
            for url in urls
        ]

        highest = max(
            (
                x["risk_score"]
                for x in results
            ),
            default=0,
        )

        suspicious_count = sum(
            1
            for x in results
            if x["risk_score"] >= 30
        )

        brands = sorted(
            {
                brand
                for x in results
                for brand in x.get(
                    "brand_impersonation",
                    [],
                )
            }
        )

        typosquatting = sorted(
            {
                brand
                for x in results
                for brand in x.get(
                    "typosquatting",
                    [],
                )
            }
        )

        reasons = []

        for item in results:

            for reason in item.get(
                "risk_reasons",
                [],
            ):

                if reason not in reasons:

                    reasons.append(
                        reason
                    )

        if highest >= 75:

            overall_risk = "CRITICAL"

        elif highest >= 50:

            overall_risk = "HIGH"

        elif highest >= 30:

            overall_risk = "MEDIUM"

        else:

            overall_risk = "LOW"

        return {

            "total_urls":
                len(results),

            "urls":
                results,

            "summary": {

                "suspicious_urls":
                    suspicious_count,

                "highest_url_score":
                    highest,

                "impersonated_brands":
                    brands,

                "typosquatting_detected":
                    typosquatting,

                "overall_risk":
                    overall_risk,

                "reasons":
                    reasons,

            },

        }

    # ============================================================
    # STRUCTURED V2 FINDINGS
    # ============================================================

    @classmethod
    def analyze_references(cls, references):
        """Analyze parsed visible/href references without fetching remote URLs."""
        from uuid import uuid4
        from urllib.parse import urlparse

        findings = []
        results = []
        for reference in references or []:
            href = str(reference.get("href", "") or reference.get("normalized", ""))
            if not href or href.lower().startswith(("javascript:", "data:", "mailto:")):
                continue
            result = cls.analyze_url(href)
            parsed = urlparse(href)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                continue
            hostname = (parsed.hostname or "").lower()
            visible = str(reference.get("visible_text", ""))
            visible_urls = cls.extract_urls(visible)
            visible_host = (
                (urlparse(visible_urls[0]).hostname or "").lower()
                if visible_urls
                else ""
            )
            result["registered_domain"] = cls._base_domain(hostname)
            result["port"] = parsed.port
            result["path"] = parsed.path
            result["query_parameters"] = sorted({item.split("=", 1)[0] for item in parsed.query.split("&") if item})
            result["encoded_characters"] = result.get("encoded_character_count", 0)
            result["redirect_indicators"] = [item for item in result.get("suspicious_parameters", []) if item in {"redirect", "url", "return", "continue"}]
            result["visible_text"] = visible
            result["href"] = href
            result["visible_host"] = visible_host
            result["visible_href_mismatch"] = bool(visible_host and visible_host != hostname)
            result["mixed_script"] = any(ord(char) > 127 for char in hostname) and "xn--" not in hostname
            results.append(result)
            if result.get("visible_href_mismatch"):
                findings.append({"finding_id": str(uuid4()), "category": "URL", "rule": "visible_href_mismatch", "severity": "high", "confidence": 0.94, "title": "Visible link destination differs from href", "description": "The visible link text points to a different host than the actual href.", "evidence": {"visible_host": visible_host, "actual_host": hostname, "href": href}, "limitations": ["A mismatch can also be caused by intentionally shortened or redirected links."]})
            rules = []
            if result.get("is_shortener"):
                rules.append(("url_shortener", "medium", 0.88, "URL shortener detected", "The destination is obscured behind a known URL shortening service."))
            if result.get("punycode") or result.get("mixed_script"):
                rules.append(("idn_or_mixed_script", "high", 0.91, "Internationalized or mixed-script hostname detected", "The hostname uses IDN, punycode, or non-ASCII characters that can resemble another domain."))
            if result.get("is_ip_address"):
                rules.append(("ip_based_url", "medium", 0.86, "URL uses an IP address", "The link uses a raw IP address instead of a registered domain."))
            if result.get("ssrf_risk"):
                rules.append(("ssrf_internal_destination", "high", 0.97, "Potential internal/SSRF destination", "The URL points to a local, private, link-local, reserved, multicast, unspecified, or obvious internal hostname. No network request was made."))
            if result.get("port_present") or parsed.port not in (None, 80, 443):
                rules.append(("suspicious_port", "medium", 0.8, "URL uses a non-standard port", "The URL specifies a port outside the normal HTTP or HTTPS ports."))
            if result.get("risk_score", 0) >= 50:
                rules.append(("suspicious_url_features", "high", 0.82, "Suspicious URL characteristics detected", "The URL contains multiple credential, brand, redirect, or infrastructure signals."))
            for rule, severity, confidence, title, description in rules:
                findings.append({"finding_id": str(uuid4()), "category": "URL", "rule": rule, "severity": severity, "confidence": confidence, "title": title, "description": description, "evidence": {"url": href, "hostname": hostname, "registered_domain": result.get("registered_domain"), "risk_score": result.get("risk_score", 0), "risk_reasons": result.get("risk_reasons", [])[:10]}, "limitations": ["No DNS resolution or remote URL fetch was performed; redirect chains and live reputation are not inferred."]})
        return {"urls": results, "findings": findings, "highest_risk": max((item.get("risk_score", 0) for item in results), default=0), "redirect_chain": [], "network_fetch_performed": False}
