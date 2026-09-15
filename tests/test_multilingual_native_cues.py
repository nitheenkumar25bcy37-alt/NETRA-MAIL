import pytest

from backend.multilingual_detector import MultilingualLanguageDetector


@pytest.mark.parametrize(
    ("language_code", "message"),
    [
        ("hin", "तुरंत अपना पासवर्ड सत्यापित करें, नहीं तो खाता निलंबित होगा।"),
        ("tam", "உடனடியாக உங்கள் கடவுச்சொல் சரிபார்க்கவும்; கணக்கு முடக்கப்படும்."),
        ("tel", "వెంటనే మీ పాస్‌వర్డ్ ధృవీకరించండి; ఖాతా నిలిపివేయబడుతుంది."),
        ("kan", "ತಕ್ಷಣ ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲಿಸಿ; ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ."),
        ("mal", "ഉടൻ നിങ്ങളുടെ പാസ്‌വേഡ് സ്ഥിരീകരിക്കുക; അക്കൗണ്ട് സസ്പെൻഡ് ചെയ്യും."),
    ],
)
def test_native_language_security_cues_are_detected(language_code, message):
    result = MultilingualLanguageDetector.analyze(message)
    assert result["language_code"] == language_code
    assert result["multilingual_score"] >= 18
    assert len(result["multilingual_findings"]) >= 2


@pytest.mark.parametrize(
    ("language_code", "message"),
    [
        ("hin", "कल हमारी परियोजना बैठक दस बजे होगी।"),
        ("tam", "நாளை திட்டக் கூட்டம் காலை பத்து மணிக்கு நடைபெறும்."),
        ("tel", "రేపు ప్రాజెక్ట్ సమావేశం ఉదయం పది గంటలకు జరుగుతుంది."),
        ("kan", "ನಾಳೆ ಯೋಜನೆಯ ಸಭೆ ಬೆಳಿಗ್ಗೆ ಹತ್ತು ಗಂಟೆಗೆ ನಡೆಯುತ್ತದೆ."),
        ("mal", "നാളെ പദ്ധതി യോഗം രാവിലെ പത്ത് മണിക്ക് നടക്കും."),
    ],
)
def test_native_language_business_text_does_not_trigger_phishing_cues(language_code, message):
    result = MultilingualLanguageDetector.analyze(message)
    assert result["language_code"] == language_code
    assert result["multilingual_score"] == 0
    assert result["multilingual_findings"] == {}
