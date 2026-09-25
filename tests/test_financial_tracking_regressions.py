from email.message import EmailMessage
from unittest.mock import patch
from urllib.parse import quote

import pytest

from backend.email_authentication import EmailAuthenticationVerifier
from backend.parser import _SafeHTMLExtractor
from backend.presentation import explain_analysis
from backend.services.financial_context import request_text
from backend.services.risk_engine import RiskEngine
from backend.tracking_links import embedded_destination
from backend.url_analyzer import URLAnalyzer
from evaluation.financial_mail_regression import wrap, run


def test_anchor_text_ends_at_close_and_handles_nested_formatting():
    parser = _SafeHTMLExtractor()
    parser.feed('<a href="https://groww.app.link/help">Help <b>centre</b><span hidden>www.evil.test</span></a><p>www.nseindia.com</p>')
    assert parser.links == [{'href': 'https://groww.app.link/help', 'visible_text': 'Help centre'}]


def test_new_nonlink_anchor_does_not_inherit_previous_href():
    parser = _SafeHTMLExtractor()
    parser.feed('<a href="https://example.org">First<a name="section">www.evil.test</a>')
    assert parser.links[0]['visible_text'] == 'First'


def test_nested_tracking_targets_keep_destination_and_provenance():
    target = 'https://digest.groww.in/p/news'
    inner = 'https://client-pixel.groww.in/email/click-tracking?redirect_uri=' + quote(target, safe='')
    result = URLAnalyzer.analyze_references([{'href': wrap(inner), 'visible_text': target}])
    item = result['urls'][0]
    assert item['redirect_target'] == target
    assert len(item['tracking_chain']) == 2
    assert item['registered_domain'] == 'groww.in'
    assert not item['visible_href_mismatch']
    assert item['risk_score'] < 35
    assert 'not verified' in item['destination_status']


@pytest.mark.parametrize('target,rule', [
    ('http://127.0.0.1/admin', 'ssrf_internal_destination'),
    ('https://sbi-login.attacker.example/verify', 'visible_href_mismatch'),
    ('https://xn--pple-43d.com/login', 'idn_or_mixed_script'),
])
def test_tracking_does_not_hide_dangerous_destination(target, rule):
    result = URLAnalyzer.analyze_references([{'href': wrap(target), 'visible_text': 'https://sbi.co.in/login'}])
    assert any(f['rule'] == rule for f in result['findings'])


@pytest.mark.parametrize('url', [
    'https://r.ap-south-1.awstrack.me.evil.test/L0/https:%2F%2Fsbi.co.in/1/a/b',
    'https://user:password@k97t77cm.r.ap-south-1.awstrack.me/L0/https:%2F%2Fsbi.co.in/1/a/b',
    'https://k97t77cm.r.ap-south-1.awstrack.me/L0/not-a-url/1/a/b',
    'https://www.google.com/url?q=https://one.test&q=https://two.test',
])
def test_ambiguous_or_spoofed_wrappers_are_not_trusted(url):
    assert embedded_destination(url) is None


def test_generic_redirect_does_not_hide_private_wrapper():
    result = URLAnalyzer.analyze_references([{'href': 'http://127.0.0.1/email/click-tracking?redirect_uri=https%3A%2F%2Fsbi.co.in'}])
    assert result['urls'][0]['wrapper_structural_warning']
    assert any(f['rule'] == 'ssrf_internal_destination' for f in result['findings'])


def test_tracking_depth_is_bounded():
    target = 'https://example.org'
    for _ in range(8):
        target = 'https://www.google.com/url?q=' + quote(target, safe='')
    result = URLAnalyzer.analyze_url(target)
    assert len(result.get('tracking_chain', [])) <= 4


def test_unresolved_shortener_is_uncertainty_not_phishing_proof():
    analysis = URLAnalyzer.analyze_references([{'href': wrap('https://bit.ly/4iBf3z8')}])
    decision = RiskEngine.evaluate(analysis['findings'])
    assert decision['classification'] == 'Legitimate or low risk'
    assert decision['risk_score'] > 0
    assert any(f['rule'] == 'url_shortener' for f in analysis['findings'])


def test_mail_web_ip_difference_does_not_add_risk():
    from backend.intelligence.domain_provider import DomainIntelligenceProvider
    class Resolver:
        def resolve(self, domain, kind):
            return ['104.18.36.24'] if kind == 'A' else []
    result = DomainIntelligenceProvider(resolver=Resolver()).inspect('example.com', related_ips=['76.223.181.139'])
    assert any(f['rule'] == 'ip_domain_inconsistency' for f in result['findings'])
    assert RiskEngine.evaluate(result['findings'])['risk_score'] == 0


@pytest.mark.parametrize('trusted,claimed_domain,expected', [
    ('gmail', 'sbi.co.in', 'pass'),
    (None, 'sbi.co.in', 'unavailable'),
    ('gmail', 'unrelated.test', 'fail'),
])
def test_receiver_dmarc_respects_provider_and_sender_boundary(trusted, claimed_domain, expected):
    msg = EmailMessage()
    msg['From'] = 'sender@sbi.co.in'
    msg['Authentication-Results'] = f'mx.google.com; spf=pass smtp.mailfrom=amazonses.com; dmarc=pass header.from={claimed_domain}'
    msg.set_content('Statement ready')
    with patch('backend.email_authentication.DKIMVerifier.verify', return_value={'status': 'unavailable', 'signatures': []}), patch.object(EmailAuthenticationVerifier, '_arc', return_value={'status': 'none'}):
        result = EmailAuthenticationVerifier().verify(msg.as_bytes(), trusted_receiver=trusted)
    assert result['dmarc']['status'] == expected


def test_safety_advice_does_not_hide_a_following_request():
    text, observations = request_text('Never share your OTP. But send your password now to verify your account.')
    assert 'Safety advice' in observations
    assert 'send your password now' in text


def test_strongest_duplicate_rule_survives_safe_first_link():
    result = RiskEngine.evaluate([
        {'rule': 'suspicious_url_features', 'severity': 'info', 'confidence': .82, 'category': 'URL'},
        {'rule': 'suspicious_url_features', 'severity': 'high', 'confidence': .82, 'category': 'URL'},
    ])
    assert result['risk_score'] == 26
    assert len(result['contributions']) == 1


def test_explanation_separates_sender_identity_from_content():
    view = explain_analysis({'parsed': {'verified_authentication': {'dmarc': {'status': 'pass'}}}})
    assert 'Sender authentication passed' in view['sender_summary']
    assert 'not an unconditional safety guarantee' in view['sender_summary']


def test_financial_pipeline_matrix_preserves_attack_detection():
    result = run()
    assert result['fp'] == 0
    assert result['tp'] == 8
