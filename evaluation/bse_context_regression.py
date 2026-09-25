"""Synthetic bilingual/context regressions; not independent production accuracy."""
import argparse
import json
import os
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch
from backend.services.analysis_orchestrator import AnalysisOrchestrator

CASES = [
    ('bse-style', False, 'Please follow the procedure below to open the attachment. Click on the attachment provided with this email. You will be prompted to enter a password. The password is your PAN in upper case. Report discrepancies immediately. Trading in suspended securities is restricted. निवेशकों के लिए KYC सूचना।'),
    ('hindi-advice', False, 'अपना पासवर्ड कभी साझा न करें। KYC जानकारी सुरक्षित रखें। Your monthly statement is attached.'),
    ('separate-news', False, 'Your account statement is attached. Enter your PAN to open the PDF. Market news: trading was suspended immediately. KYC सूचना।'),
    ('english-advice', False, 'Never share your password. Report fraud immediately. Your password-protected statement is attached.'),
    ('english-attack', True, 'Enter your password immediately or your account will be suspended.'),
    ('hindi-attack', True, 'तुरंत अपना पासवर्ड सत्यापित करें, नहीं तो खाता निलंबित होगा।'),
    ('bilingual-attack', True, 'निवेशकों के लिए सूचना। Send your password immediately to verify your account.'),
    ('advice-plus-attack', True, 'Never share your OTP. But send your password immediately or your account will be suspended.'),
]

def run():
    rows = []
    with patch.dict(os.environ, {'NETRA_URL_REPUTATION_ENABLED': 'false', 'NETRA_EXPAND_SHORT_URLS': '0'}), patch('backend.email_authentication.DKIMVerifier.verify', return_value={'status': 'unsigned', 'signatures': [], 'limitations': []}), patch('backend.email_authentication.EmailAuthenticationVerifier._arc', return_value={'status': 'none'}):
        for name, malicious, text in CASES:
            msg = EmailMessage()
            msg['From'] = 'reports@example.com'
            msg['Subject'] = 'Account notification'
            msg['Authentication-Results'] = 'mx.google.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com'
            msg.set_content(text)
            engine = AnalysisOrchestrator()
            engine.domain_provider.inspect = lambda *a, **kw: {'findings': []}
            result = engine.analyze(msg.as_bytes(), trusted_receiver='gmail')
            detected = result.risk_score >= 25 or result.classification != 'Legitimate or low risk'
            rows.append({'name': name, 'malicious': malicious, 'detected': detected, 'score': result.risk_score, 'rules': [f.rule for f in result.findings if f.severity != 'info']})
    return {'scope': __doc__, 'version': AnalysisOrchestrator.VERSION, 'criterion': 'score >=25 or non-low-risk classification', 'network': 'disabled; trusted receiver simulated', 'tp': sum(r['malicious'] and r['detected'] for r in rows), 'fp': sum(not r['malicious'] and r['detected'] for r in rows), 'positive_count': 4, 'negative_count': 4, 'rows': rows}

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
