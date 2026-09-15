from __future__ import annotations

import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Tuple


# ============================================================
# LANGUAGE DEFINITIONS
# ============================================================

LANGUAGE_LABELS = {
    "eng": "English",
    "hin": "Hindi",
    "tam": "Tamil",
    "mal": "Malayalam",
    "tel": "Telugu",
    "kan": "Kannada",
}


# Unicode ranges for native Indian scripts.
SCRIPT_RANGES = {
    "hin": ((0x0900, 0x097F),),  # Devanagari
    "tam": ((0x0B80, 0x0BFF),),  # Tamil
    "tel": ((0x0C00, 0x0C7F),),  # Telugu
    "kan": ((0x0C80, 0x0CFF),),  # Kannada
    "mal": ((0x0D00, 0x0D7F),),  # Malayalam
}


# ============================================================
# NATIVE-SCRIPT SECURITY CUES
# ============================================================

CUES = {
    "tam": {
        "urgency": (
            "அவசரம்",
            "உடனடியாக",
            "இப்போதே",
            "விரைவாக",
            "உடனே",
        ),
        "financial_fraud": (
            "வங்கி",
            "கணக்கு",
            "பணம்",
            "பரிவர்த்தனை",
            "கட்டணம்",
            "கேஒய்சி",
        ),
        "credential_harvesting": (
            "கடவுச்சொல்",
            "உள்நுழைவு",
            "சரிபார்க்கவும்",
            "otp",
            "ஓடிபி",
        ),
        "social_engineering": (
            "கிளிக் செய்யவும்",
            "இங்கே கிளிக்",
            "முடக்கப்படும்",
            "தகவலை வழங்கவும்",
        ),
    },

    "hin": {
        "urgency": (
            "तुरंत",
            "तत्काल",
            "अभी",
            "जल्दी",
            "शीघ्र",
        ),
        "financial_fraud": (
            "बैंक",
            "खाता",
            "पैसे",
            "भुगतान",
            "लेनदेन",
            "क्रेडिट",
            "डेबिट",
            "केवाईसी",
        ),
        "credential_harvesting": (
            "पासवर्ड",
            "लॉगिन",
            "सत्यापित",
            "सत्यापन",
            "ओटीपी",
        ),
        "social_engineering": (
            "क्लिक करें",
            "यहाँ क्लिक",
            "निलंबित",
            "जानकारी दें",
            "तुरंत कार्रवाई",
        ),
    },

    "mal": {
        "urgency": (
            "അടിയന്തിരം",
            "ഉടൻ",
            "ഉടനടി",
            "ഇപ്പോൾ തന്നെ",
            "വേഗത്തിൽ",
        ),
        "financial_fraud": (
            "ബാങ്ക്",
            "അക്കൗണ്ട്",
            "പണം",
            "പണമിടപാട്",
            "പേയ്മെന്റ്",
            "കെവൈസി",
        ),
        "credential_harvesting": (
            "പാസ്‌വേഡ്",
            "പാസ്വേഡ്",
            "ലോഗിൻ",
            "സ്ഥിരീകരിക്കുക",
            "ഒടിപി",
        ),
        "social_engineering": (
            "ക്ലിക്ക് ചെയ്യുക",
            "ഇവിടെ ക്ലിക്ക്",
            "സസ്പെൻഡ്",
            "വിവരങ്ങൾ നൽകുക",
        ),
    },

    "tel": {
        "urgency": (
            "అత్యవసరం",
            "వెంటనే",
            "తక్షణమే",
            "ఇప్పుడే",
            "త్వరగా",
        ),
        "financial_fraud": (
            "బ్యాంక్",
            "ఖాతా",
            "డబ్బు",
            "చెల్లింపు",
            "లావాదేవీ",
            "కెవైసి",
        ),
        "credential_harvesting": (
            "పాస్‌వర్డ్",
            "పాస్వర్డ్",
            "లాగిన్",
            "ధృవీకరించండి",
            "ఓటీపీ",
        ),
        "social_engineering": (
            "క్లిక్ చేయండి",
            "ఇక్కడ క్లిక్",
            "ఖాతా నిలిపివేయబడుతుంది",
            "సమాచారం ఇవ్వండి",
        ),
    },

    "kan": {
        "urgency": (
            "ತುರ್ತು",
            "ತಕ್ಷಣ",
            "ಈಗಲೇ",
            "ಶೀಘ್ರವಾಗಿ",
        ),
        "financial_fraud": (
            "ಬ್ಯಾಂಕ್",
            "ಖಾತೆ",
            "ಹಣ",
            "ಪಾವತಿ",
            "ವಹಿವಾಟು",
            "ಕೆವೈಸಿ",
        ),
        "credential_harvesting": (
            "ಪಾಸ್‌ವರ್ಡ್",
            "ಪಾಸ್ವರ್ಡ್",
            "ಲಾಗಿನ್",
            "ಪರಿಶೀಲಿಸಿ",
            "ಒಟಿಪಿ",
        ),
        "social_engineering": (
            "ಕ್ಲಿಕ್ ಮಾಡಿ",
            "ಇಲ್ಲಿ ಕ್ಲಿಕ್",
            "ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ",
            "ಮಾಹಿತಿ ನೀಡಿ",
        ),
    },
}

# Canonical Unicode aliases. Earlier copies of the source passed some native
# strings through a legacy Windows encoding, which preserved script detection
# but prevented the phishing cue dictionaries from matching real messages.
_NATIVE_CUE_ALIASES = {
    "hin": {
        "urgency": ("तुरंत", "तत्काल", "अभी", "जल्दी", "शीघ्र"),
        "financial_fraud": ("बैंक", "खाता", "पैसे", "भुगतान", "लेनदेन", "क्रेडिट", "डेबिट", "केवाईसी"),
        "credential_harvesting": ("पासवर्ड", "लॉगिन", "सत्यापित", "सत्यापन", "ओटीपी"),
        "social_engineering": ("क्लिक करें", "यहाँ क्लिक", "निलंबित", "जानकारी दें", "तुरंत कार्रवाई"),
    },
    "tam": {
        "urgency": ("அவசரம்", "உடனடியாக", "இப்போதே", "விரைவாக", "உடனே"),
        "financial_fraud": ("வங்கி", "கணக்கு", "பணம்", "பரிவர்த்தனை", "கட்டணம்", "கேஒய்சி"),
        "credential_harvesting": ("கடவுச்சொல்", "உள்நுழைவு", "சரிபார்க்கவும்", "ஓடிபி"),
        "social_engineering": ("கிளிக் செய்யவும்", "இங்கே கிளிக்", "முடக்கப்படும்", "தகவலை வழங்கவும்"),
    },
    "tel": {
        "urgency": ("అత్యవసరం", "వెంటనే", "తక్షణమే", "ఇప్పుడే", "త్వరగా"),
        "financial_fraud": ("బ్యాంక్", "ఖాతా", "డబ్బు", "చెల్లింపు", "లావాదేవీ", "కేవైసి"),
        "credential_harvesting": ("పాస్‌వర్డ్", "లాగిన్", "ధృవీకరించండి", "ఓటీపీ"),
        "social_engineering": ("క్లిక్ చేయండి", "ఇక్కడ క్లిక్", "ఖాతా నిలిపివేయబడుతుంది", "సమాచారం ఇవ్వండి"),
    },
    "kan": {
        "urgency": ("ತುರ್ತು", "ತಕ್ಷಣ", "ಈಗಲೇ", "ಶೀಘ್ರವಾಗಿ"),
        "financial_fraud": ("ಬ್ಯಾಂಕ್", "ಖಾತೆ", "ಹಣ", "ಪಾವತಿ", "ವಹಿವಾಟು", "ಕೆವೈಸಿ"),
        "credential_harvesting": ("ಪಾಸ್‌ವರ್ಡ್", "ಲಾಗಿನ್", "ಪರಿಶೀಲಿಸಿ", "ಒಟಿಪಿ"),
        "social_engineering": ("ಕ್ಲಿಕ್ ಮಾಡಿ", "ಇಲ್ಲಿ ಕ್ಲಿಕ್", "ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ", "ಮಾಹಿತಿ ನೀಡಿ"),
    },
    "mal": {
        "urgency": ("അടിയന്തിരം", "ഉടൻ", "ഉടനടി", "ഇപ്പോൾ തന്നെ", "വേഗത്തിൽ"),
        "financial_fraud": ("ബാങ്ക്", "അക്കൗണ്ട്", "പണം", "പണമിടപാട്", "പേയ്മെന്റ്", "കെവൈസി"),
        "credential_harvesting": ("പാസ്‌വേഡ്", "പാസ്‌വേഡ്", "ലോഗിൻ", "സ്ഥിരീകരിക്കുക", "ഒടിപി"),
        "social_engineering": ("ക്ലിക്ക് ചെയ്യുക", "ഇവിടെ ക്ലിക്ക്", "സസ്പെൻഡ്", "വിവരങ്ങൾ നൽകുക"),
    },
}

for _language_code, _categories in _NATIVE_CUE_ALIASES.items():
    for _category, _aliases in _categories.items():
        CUES[_language_code][_category] = tuple(
            dict.fromkeys((*CUES[_language_code][_category], *_aliases))
        )


# ============================================================
# ROMANIZED / TRANSLITERATED LANGUAGE CUES
# ============================================================

ROMAN = {
    "tam": {
        "urgency": (
            "avasaram",
            "avaram",
            "udane",
            "udanadi",
            "ippove",
            "seekiram",
        ),
        "financial_fraud": (
            "vangi",
            "kanakku",
            "panam",
            "parivarthanai",
            "katnam",
            "kyc",
        ),
        "credential_harvesting": (
            "kadavuchol",
            "ulnuzhaivu",
            "password",
            "login",
            "sariparkka",
            "otp",
        ),
        "social_engineering": (
            "click pannunga",
            "inga click",
            "mudakkappadum",
            "thagaval kudunga",
        ),
    },

    "hin": {
        "urgency": (
            "turant",
            "tatkal",
            "abhi",
            "jaldi",
            "sheeghra",
        ),
        "financial_fraud": (
            "bank",
            "khata",
            "paise",
            "bhugtan",
            "len-den",
            "credit",
            "debit",
            "kyc",
        ),
        "credential_harvesting": (
            "password",
            "login",
            "satyapit",
            "satyapan",
            "otp",
        ),
        "social_engineering": (
            "click karein",
            "yahan click",
            "band ho jayega",
            "jaankari dein",
        ),
    },

    "mal": {
        "urgency": (
            "athyandiram",
            "adiyanthiram",
            "udan",
            "udane",
            "ippol thanne",
            "vegam",
        ),
        "financial_fraud": (
            "bank",
            "account",
            "panam",
            "panamidapadu",
            "payment",
            "idapadu",
            "kyc",
        ),
        "credential_harvesting": (
            "password",
            "login",
            "sthirikarikkuka",
            "otp",
        ),
        "social_engineering": (
            "click cheyyuka",
            "ivide click",
            "account thadayum",
            "vivaram nalkuka",
        ),
    },

    "tel": {
        "urgency": (
            "atyavasaram",
            "ventane",
            "taksaname",
            "ippude",
            "twaraga",
        ),
        "financial_fraud": (
            "bank",
            "khata",
            "dabbu",
            "chellimpu",
            "lavadevi",
            "kyc",
        ),
        "credential_harvesting": (
            "password",
            "login",
            "druvikarinchandi",
            "otp",
        ),
        "social_engineering": (
            "click cheyandi",
            "ikkada click",
            "khata nilipiveyabadutundi",
            "samacharam ivvandi",
        ),
    },

    "kan": {
        "urgency": (
            "turtu",
            "takshana",
            "igale",
            "shighravagi",
        ),
        "financial_fraud": (
            "bank",
            "khate",
            "hana",
            "payment",
            "vahivatu",
            "kyc",
        ),
        "credential_harvesting": (
            "password",
            "login",
            "parishilisi",
            "otp",
        ),
        "social_engineering": (
            "click madi",
            "illi click",
            "khate sthagitavaguttade",
            "mahiti nidi",
        ),
    },
}


# ============================================================
# GENERIC WORDS
# ============================================================
#
# These are deliberately excluded from language classification.
#
# Example:
#
#   "Your bank account is suspended"
#
# contains "bank" + "account".
#
# Those words exist in several transliteration dictionaries,
# but they are clearly valid English words and therefore must
# NOT make English become Malayalam/Hindi/etc.
# ============================================================

GENERIC_ROMAN_TERMS = {
    "bank",
    "account",
    "password",
    "login",
    "verify",
    "verified",
    "verification",
    "payment",
    "transaction",
    "credit",
    "debit",
    "kyc",
    "otp",
    "click",
    "information",
    "security",
    "suspend",
    "suspended",
    "blocked",
    "block",
}


# ============================================================
# COMMON ENGLISH VOCABULARY
# ============================================================

COMMON_ENGLISH = {
    "the",
    "your",
    "you",
    "will",
    "be",
    "is",
    "are",
    "was",
    "were",
    "this",
    "that",
    "these",
    "those",
    "for",
    "from",
    "with",
    "and",
    "or",
    "to",
    "of",
    "in",
    "on",
    "at",
    "by",
    "please",
    "verify",
    "immediately",
    "account",
    "bank",
    "suspended",
    "suspend",
    "click",
    "here",
    "now",
    "password",
    "login",
    "payment",
    "transaction",
    "information",
    "security",
    "message",
    "email",
    "dear",
    "customer",
    "confirm",
    "confirmation",
    "action",
    "required",
    "yourself",
    "important",
    "notice",
    "service",
    "update",
    "access",
    "online",
    "please",
    "need",
    "must",
}


# ============================================================
# SCRIPT COUNTING
# ============================================================

def _counts(text: str) -> Counter:
    """
    Count characters belonging to each supported native script.

    Latin characters are counted separately as English/Latin
    evidence, but Latin alone does not automatically mean English.
    """

    counts = Counter()

    for char in text:
        codepoint = ord(char)

        for language, ranges in SCRIPT_RANGES.items():

            if any(
                start <= codepoint <= end
                for start, end in ranges
            ):
                counts[language] += 1
                break

        # Count Latin characters.
        if "LATIN" in unicodedata.name(char, ""):
            counts["eng"] += 1

    return counts


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def _roman(text: str) -> str:
    """
    Normalize Latin/Romanized text.

    Example:

        "Udanadiyaga! Sariparkkavum."

    becomes:

        "udanadiyaga sariparkkavum"
    """

    return re.sub(
        r"[^a-z0-9]+",
        " ",
        text.lower(),
    ).strip()


def _tokens(text: str) -> List[str]:
    """
    Extract English/Latin tokens.
    """

    return re.findall(
        r"[a-z]+(?:'[a-z]+)?",
        text.lower(),
    )


# ============================================================
# CUE MATCHING
# ============================================================

def _matches(
    text: str,
    groups: Dict[str, tuple],
    roman: bool = False,
) -> Dict[str, List[str]]:
    """
    Match security cues in text.

    Native scripts use substring matching.

    Romanized text uses word-boundary matching so that:
        bank

    does not accidentally match:
        banking
    """

    if roman:
        haystack = _roman(text)
    else:
        haystack = text.lower()

    results: Dict[str, List[str]] = {}

    for category, terms in groups.items():

        found: List[str] = []

        for term in terms:

            normalized_term = term.lower()

            if roman:

                pattern = (
                    r"(?<!\w)"
                    + re.escape(normalized_term)
                    + r"(?!\w)"
                )

                matched = (
                    re.search(
                        pattern,
                        haystack,
                    )
                    is not None
                )

            else:

                matched = (
                    normalized_term
                    in haystack
                )

            if matched:
                found.append(term)

        if found:
            results[category] = sorted(
                set(found)
            )

    return results


# ============================================================
# ENGLISH LIKELIHOOD
# ============================================================

def _english_likelihood(text: str) -> float:
    """
    Estimate how English-like a Latin message is.

    This is deliberately lightweight and deterministic.

    It is NOT intended to replace a statistical language model.
    It exists mainly to prevent ordinary English from being
    incorrectly classified as a Romanized Indian language.
    """

    tokens = _tokens(text)

    if not tokens:
        return 0.0

    english_words = sum(
        token in COMMON_ENGLISH
        for token in tokens
    )

    return (
        english_words
        / max(len(tokens), 1)
    )


# ============================================================
# ROMANIZED LANGUAGE EVIDENCE
# ============================================================

def _roman_language_evidence(
    text: str,
    language: str,
) -> Tuple[
    Dict[str, List[str]],
    int,
    int,
]:
    """
    Determine language-specific Romanized evidence.

    Returns:

        findings
        unique_language_specific_term_count
        category_count

    Generic English words are excluded from language evidence.

    This is the key protection against:

        English -> Malayalam (Romanized)
    """

    findings = _matches(
        text,
        ROMAN.get(language, {}),
        roman=True,
    )

    language_specific_terms: List[str] = []

    for values in findings.values():

        for value in values:

            normalized = value.lower()

            if (
                normalized
                not in GENERIC_ROMAN_TERMS
            ):
                language_specific_terms.append(
                    normalized
                )

    language_specific_terms = sorted(
        set(language_specific_terms)
    )

    unique_count = len(
        language_specific_terms
    )

    category_count = len(findings)

    return (
        findings,
        unique_count,
        category_count,
    )


# ============================================================
# MAIN DETECTOR
# ============================================================

def analyze(
    text: str,
) -> Dict[str, Any]:
    """
    Analyze an email/text message for:

    - language
    - language code
    - script
    - multilingual status
    - detection method
    - Indian-language phishing cues
    - multilingual security score

    Supported:

    Native:
        Tamil
        Hindi
        Telugu
        Kannada
        Malayalam

    Latin:
        English
        Romanized/transliterated Indian-language cues
    """

    text = str(text or "")

    counts = _counts(text)

    # ========================================================
    # STEP 1: NATIVE SCRIPT DETECTION
    # ========================================================

    native_languages = [
        language
        for language in SCRIPT_RANGES
        if counts[language] >= 2
    ]

    # --------------------------------------------------------
    # Exactly one native Indian script
    # --------------------------------------------------------

    if len(native_languages) == 1:

        primary = native_languages[0]

        language = LANGUAGE_LABELS[
            primary
        ]

        confidence = round(
            min(
                0.99,
                0.65
                + (
                    0.30
                    * counts[primary]
                    / max(
                        sum(
                            counts[x]
                            for x in native_languages
                        ),
                        1,
                    )
                ),
            ),
            2,
        )

        mixed = False
        detection_method = "unicode_script"
        script = primary

    # --------------------------------------------------------
    # Multiple native Indian scripts
    # --------------------------------------------------------

    elif len(native_languages) > 1:

        primary = max(
            native_languages,
            key=lambda language: counts[language],
        )

        language = "Mixed Indian languages"

        confidence = 0.86

        mixed = True

        detection_method = "unicode_script"

        script = "mixed"

    # ========================================================
    # STEP 2: LATIN / ROMANIZED DETECTION
    # ========================================================

    else:

        ranked = []

        for language in ROMAN:

            (
                roman_findings,
                unique_count,
                category_count,
            ) = _roman_language_evidence(
                text,
                language,
            )

            # Language-specific transliteration gets the
            # strongest weight.
            evidence_score = (
                unique_count
                + (
                    2
                    if category_count >= 2
                    else 0
                )
            )

            ranked.append(
                (
                    language,
                    evidence_score,
                    unique_count,
                    category_count,
                    roman_findings,
                )
            )

        ranked.sort(
            key=lambda item: (
                item[1],
                item[2],
                item[3],
            ),
            reverse=True,
        )

        english_like = _english_likelihood(
            text
        )

        best = (
            ranked[0]
            if ranked
            else None
        )

        # ----------------------------------------------------
        # Potential Romanized Indian language
        # ----------------------------------------------------

        if (
            best is not None
            and best[2] >= 2
        ):

            (
                candidate,
                evidence_score,
                unique_count,
                category_count,
                candidate_findings,
            ) = best

            # ------------------------------------------------
            # English protection
            # ------------------------------------------------
            #
            # If the message contains a significant amount
            # of common English vocabulary and the apparent
            # Romanized evidence is weak, English wins.
            # ------------------------------------------------

            if (
                english_like >= 0.30
                and unique_count < 3
            ):

                primary = "eng"

                language = "English"

                confidence = round(
                    min(
                        0.96,
                        0.70
                        + (
                            english_like
                            * 0.20
                        ),
                    ),
                    2,
                )

                mixed = False

                detection_method = (
                    "english_likelihood"
                )

                script = "latin"

            else:

                primary = candidate

                language = (
                    LANGUAGE_LABELS[
                        primary
                    ]
                    + " (Romanized)"
                )

                confidence = round(
                    min(
                        0.91,
                        0.62
                        + (
                            0.06
                            * unique_count
                        )
                        + (
                            0.04
                            * category_count
                        ),
                    ),
                    2,
                )

                mixed = False

                detection_method = (
                    "romanized_cues"
                )

                script = "latin_romanized"

        # ----------------------------------------------------
        # Normal English / unknown Latin text
        # ----------------------------------------------------

        else:

            primary = "eng"

            language = "English"

            if counts["eng"]:

                confidence = round(
                    min(
                        0.96,
                        0.65
                        + (
                            english_like
                            * 0.25
                        ),
                    ),
                    2,
                )

            else:

                confidence = 0.35

            mixed = False

            detection_method = (
                "latin_default"
            )

            script = "latin"

    # ========================================================
    # STEP 3: SECURITY CUE EXTRACTION
    # ========================================================

    findings: Dict[
        str,
        List[str],
    ] = {}

    # Native-script messages:
    # use native language dictionaries.
    if native_languages:

        languages_to_check = (
            native_languages
        )

    # Romanized Indian-language messages:
    # use only the detected language.
    elif primary in ROMAN:

        languages_to_check = [
            primary
        ]

    # English:
    # NEVER apply Indian Romanized dictionaries.
    else:

        languages_to_check = []

    for language_code in languages_to_check:

        # ----------------------------------------------------
        # Native cues
        # ----------------------------------------------------

        native_findings = _matches(
            text,
            CUES.get(
                language_code,
                {},
            ),
        )

        for category, values in (
            native_findings.items()
        ):

            findings.setdefault(
                category,
                [],
            ).extend(values)

        # ----------------------------------------------------
        # Romanized cues
        # ----------------------------------------------------

        if primary in ROMAN:

            roman_findings = _matches(
                text,
                ROMAN.get(
                    language_code,
                    {},
                ),
                roman=True,
            )

            for category, values in (
                roman_findings.items()
            ):

                findings.setdefault(
                    category,
                    [],
                ).extend(values)

    # Remove duplicates.
    findings = {
        category: sorted(
            set(values)
        )
        for category, values
        in findings.items()
    }

    # ========================================================
    # STEP 4: MULTILINGUAL SECURITY SCORE
    # ========================================================

    weights = {
        "urgency": 8,
        "financial_fraud": 9,
        "credential_harvesting": 10,
        "social_engineering": 6,
    }

    score = sum(
        min(
            24,
            len(values)
            * weights.get(
                category,
                5,
            ),
        )
        for category, values
        in findings.items()
    )

    active_categories = sum(
        bool(values)
        for values
        in findings.values()
    )

    # Multiple security categories together are stronger
    # evidence than a single isolated keyword.
    if active_categories >= 2:
        score += 10

    if active_categories >= 3:
        score += 8

    # Keep the multilingual detector bounded.
    score = min(
        45,
        score,
    )

    # ========================================================
    # STEP 5: FINAL RESULT
    # ========================================================

    return {
        "language": language,

        "language_code": primary,

        "language_confidence": confidence,

        "script": script,

        "is_multilingual": mixed,

        "detection_method": detection_method,

        "detected_scripts": [
            LANGUAGE_LABELS[x]
            for x in native_languages
        ],

        "multilingual_findings": findings,

        "multilingual_score": score,
    }


# ============================================================
# PUBLIC CLASS API
# ============================================================

class MultilingualLanguageDetector:

    @staticmethod
    def analyze(
        text: str,
    ) -> Dict[str, Any]:

        return analyze(text)
