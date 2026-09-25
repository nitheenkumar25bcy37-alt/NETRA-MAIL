"""Synthetic regression matrix, not a production accuracy estimate.

Receiver authentication and DNS are deterministic test doubles. ML, parsing,
URL analysis and composite scoring use the real pipeline. No links are opened.
Run as: python -m evaluation.financial_mail_regression --output PATH
"""
import argparse
import json
import os
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from backend.services.analysis_orchestrator import AnalysisOrchestrator


def wrap(target):
    return 'https://k97t77cm.r.ap-south-1.awstrack.me/L0/' + quote(target, safe=':') + '/1/message-token/signature'


def cases():
    banks = ['sbi.co.in', 'hdfcbank.bank.in', 'icicibank.com', 'axisbank.com', 'example-bank.test']
    for bank in banks:
        for action in ['credited', 'debited']:
            yield (bank + '-' + action, False, bank,
                   f'Your account was {action} INR 500. Never share your OTP or password. No action is required.',
                   wrap('https://' + bank + '/statement'), 'View statement')
    yield ('newsletter', False, 'digest.groww.in',
           'Financial news: acquisition deal, funds, money and purchase. A trusted manager explains the market.',
           wrap('https://digest.groww.in/p/news'), 'Read news')
    yield ('protected-statement', False, 'groww.in',
           'Your contract note is password protected. Use your PAN in capital letters to open the attached PDF.',
           wrap('https://groww.in/help'), 'Help')
    for index, target in enumerate(['https://paypal.verify-account.evil.xyz/login',
                                    'http://127.0.0.1/admin',
                                    'https://sbi-login.attacker.example/verify',
                                    'https://xn--pple-43d.com/login']):
        for wrapped in [False, True]:
            yield (f'attack-{index}-{wrapped}', True, 'sbi.co.in',
                   'Send your password now. Your account will be suspended. Verify immediately.',
                   wrap(target) if wrapped else target, 'https://sbi.co.in/login')


def run():
    rows = []
    for name, malicious, domain, body, href, label in cases():
        message = EmailMessage()
        message['Subject'] = name
        message['From'] = 'notifications@' + domain
        message['Return-Path'] = '<bounce@ap-south-1.amazonses.com>'
        message['Authentication-Results'] = f'mx.google.com; spf=pass smtp.mailfrom=ap-south-1.amazonses.com; dkim=pass header.d={domain}; dmarc=pass header.from={domain}'
        message.set_content(body)
        message.add_alternative(f'<p>{body}</p><a href="{href}">{label}</a><p>Exchange information: www.nseindia.com</p>', subtype='html')
        engine = AnalysisOrchestrator()
        engine.domain_provider.inspect = lambda *a, **kw: {'findings': []}
        with patch.dict(os.environ, {'NETRA_URL_REPUTATION_ENABLED': 'false', 'NETRA_EXPAND_SHORT_URLS': '0'}), patch('backend.email_authentication.DKIMVerifier.verify', return_value={'status': 'unsigned', 'signatures': [], 'limitations': []}), patch('backend.email_authentication.EmailAuthenticationVerifier._arc', return_value={'status': 'none', 'source': 'fixture', 'chain': []}):
            result = engine.analyze(message.as_bytes(), 'eml', trusted_receiver='gmail')
        detected = result.risk_score >= 35 or result.classification not in {'Legitimate or low risk'}
        rows.append({'name': name, 'malicious': malicious, 'detected': detected, 'score': result.risk_score, 'classification': result.classification, 'rules': [{'rule': f.rule, 'severity': f.severity} for f in result.findings]})
    tp = sum(r['malicious'] and r['detected'] for r in rows)
    fp = sum(not r['malicious'] and r['detected'] for r in rows)
    positives = sum(r['malicious'] for r in rows)
    return {'scope': __doc__, 'version': AnalysisOrchestrator.VERSION, 'count': len(rows), 'tp': tp, 'fp': fp, 'recall': tp / positives, 'false_positive_rate': fp / (len(rows) - positives), 'rows': rows}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print({k: v for k, v in result.items() if k not in {'scope', 'rows'}})
