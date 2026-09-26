"""Synthetic reproductions of report findings, not the user's private email."""
import json
from email.message import EmailMessage
from unittest.mock import patch
import pytest
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.financial_context import request_evidence
from backend.inspection_client import _portable_result, inspect_attachment
from backend.url_analyzer import URLAnalyzer
from backend.tracking_links import opaque_tracking_provider
from tests.test_pdf_unlock import pdf_fixture

CIRCULAR = "https://www.sebi.gov.in/legal/circulars/jun-2025/adoption-of-standardised-validated-and-exclusive-upi-ids-for-payment-collection-by-sebi-registered-intermediaries-from-investors_94535.html"
TRACKER = "https://email.jiocx.com/interface/ctr/v2/" + "aB_123" * 20


def analyze(body, href=TRACKER, authenticated=True):
    msg = EmailMessage()
    msg['From'] = 'reports@example.org'
    msg['Subject'] = 'Funds/Securities Balance'
    if authenticated:
        msg['Authentication-Results'] = 'mx.google.com; spf=pass smtp.mailfrom=example.org; dmarc=pass header.from=example.org'
    msg.set_content(body)
    msg.add_alternative('<p>' + body + '</p><a href="' + href + '">https://www.example.org/circular</a><a href="' + CIRCULAR + '">Circular</a>', subtype='html')
    engine = AnalysisOrchestrator()
    engine.domain_provider.inspect = lambda *a, **kw: {'findings': []}
    with patch('backend.email_authentication.DKIMVerifier.verify', return_value={'status': 'unsigned', 'signatures': [], 'limitations': []}), patch('backend.email_authentication.EmailAuthenticationVerifier._arc', return_value={'status': 'none'}):
        return engine.analyze(msg.as_bytes(), trusted_receiver='gmail' if authenticated else None)


def test_authenticated_statement_tracking_is_uncertainty_not_deception():
    result = analyze('Your funds balance is attached. Please open the attachment. You will be prompted to enter a password. The password is your PAN in upper case. Do not share your password. Never transfer funds to a personal bank account. Report discrepancies immediately.')
    assert result.risk_score < 25, [(f.rule, f.severity) for f in result.findings]
    assert result.classification == 'Legitimate or low risk'
    assert any(f.rule == 'opaque_tracking_destination' for f in result.findings)
    assert not any(f.rule == 'payment_authority_combination' for f in result.findings)


@pytest.mark.parametrize('body,href,authenticated', [
    ('Send your password immediately or your account will be suspended.', TRACKER, True),
    ('Transfer funds to the CEO bank account in strict confidence.', 'https://evil.test/login', True),
    ('Your statement is attached.', 'https://email.jiocx.com.evil.test/interface/ctr/v2/' + 'a'*60, True),
    ('Your statement is attached.', TRACKER, False),
])
def test_attacks_and_unverified_sender_not_blanket_trusted(body, href, authenticated):
    result = analyze(body, href, authenticated)
    assert result.risk_score >= 35


def test_circular_lexical_words_not_independent_ml_evidence():
    with patch('backend.url_ml_classifier.URLMLClassifier.predict', return_value={'phishing_probability': .999}):
        result = URLAnalyzer.analyze_url(CIRCULAR)
    assert not result['ml_analysis']['used_in_score']
    assert result['risk_score'] < 35


def test_provider_route_requires_exact_host_and_https():
    assert opaque_tracking_provider(TRACKER)
    assert not opaque_tracking_provider(TRACKER.replace('https:', 'http:'))
    assert not opaque_tracking_provider(TRACKER.replace('email.jiocx.com', 'email.jiocx.com.evil.test'))


def test_hindi_discrepancy_advice_is_not_a_secret_request():
    text = 'उसके ब्यौरे को सत्यापित कर लें और यदि कोई फर्क नज़र आता है, तो तत्काल अपने ब्रोकर को लिखित में उसकी सूचना दें'
    categories = {'credential_harvesting': ['सत्यापित', 'पासवर्ड'], 'financial_fraud': ['बैंक'], 'urgency': ['तत्काल']}
    assert request_evidence(text, categories) == []
    assert request_evidence('तत्काल अपना पासवर्ड सत्यापित करें', categories)


def test_completed_extraction_survives_timeout_and_visual_failure():
    checkpoint = {'available': True, 'pages': [{'text': 'native text'}], 'limitations': []}
    raw = json.dumps(checkpoint).encode() + b'\n'
    result = _portable_result(raw, -9)
    assert result['available'] and result['limitations']
    result = _portable_result(raw + b'{"available":false,"error":"portable_inspection_failed"}', 0)
    assert result['available'] and result['limitations']
    assert not _portable_result(b'', -9)['available']


def test_real_portable_correct_password_retains_pdf_checks(monkeypatch):
    monkeypatch.setenv('NETRA_INSPECTION_MODE', 'portable')
    result = inspect_attachment(pdf_fixture(), 'statement.pdf', 'application/pdf', password='sample-secret-987')
    assert result['available'], result
    assert 'monthly statement' in result['pages'][0]['text']
    assert result['encrypted']
    assert 'sample-secret-987' not in json.dumps(result)

