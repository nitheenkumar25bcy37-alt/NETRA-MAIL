from unittest.mock import patch
import pytest

from backend.services.financial_context import request_text, request_evidence
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.presentation import explain_analysis
from backend.inspection_client import inspect_attachment
from backend.attachment_analyzer import AttachmentAnalyzer
from evaluation.bse_context_regression import run


@pytest.mark.parametrize('numbered', [False, True])
def test_local_document_instructions_use_bounded_context(numbered):
    text = 'Please follow the procedure to open the attachment. '
    text += ('1. Click on the attachment. 2. You will be prompted to enter a password. 3. The password is your PAN in upper case.' if numbered else 'Click on the attachment. You will be prompted to enter a password. The password is your PAN in upper case.')
    remaining, observations = request_text(text)
    assert 'enter a password' not in remaining
    assert 'Local document instruction' in observations
    remaining, _ = request_text('You will be prompted to enter a password. Send your password immediately.')
    assert 'Send your password immediately' in remaining
    assert 'enter a password' in remaining


def test_local_instructions_do_not_hide_online_password_request():
    text, _ = request_text('Open the attachment. You will be prompted to enter a password at https://evil.test. Send your PAN to us immediately.')
    assert 'enter a password at https' in text
    assert 'Send your PAN' in text


def test_urgency_from_unrelated_passage_does_not_join_request():
    result = request_evidence('Enter your password to unlock the account. Market trading was suspended immediately.', {'urgency': ['immediately', 'suspended'], 'credential_harvesting': ['password']})
    assert result
    assert not any(r['categories']['urgency'] for r in result)


def test_multilingual_nouns_are_informational_without_request():
    data = {'language': 'Hindi', 'multilingual_findings': {'financial_fraud': ['kyc'], 'credential_harvesting': ['password']}}
    findings = AnalysisOrchestrator()._build_multilingual_findings(data, 'KYC information. The PDF password is your PAN.')
    assert findings and all(f.severity == 'info' for f in findings)


@pytest.mark.parametrize('text', [
    'तुरंत अपना पासवर्ड सत्यापित करें, नहीं तो खाता निलंबित होगा।',
    'உடனடியாக உங்கள் கடவுச்சொல் சரிபார்க்கவும்; கணக்கு முடக்கப்படும்.',
    'వెంటనే మీ పాస్‌వర్డ్ ధృవీకరించండి; ఖాతా నిలిపివేయబడుతుంది.',
    'ತಕ್ಷಣ ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲಿಸಿ; ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ.',
    'ഉടൻ നിങ്ങളുടെ പാസ്‌വേഡ് സ്ഥിരീകരിക്കുക; അക്കൗണ്ട് സസ്പെൻഡ് ചെയ്യും.',
])
def test_native_requests_remain_actionable(text):
    from backend.multilingual_detector import MultilingualLanguageDetector
    data = MultilingualLanguageDetector.analyze(text)
    findings = AnalysisOrchestrator()._build_multilingual_findings(data, text)
    assert any(f.severity in {'medium', 'high'} for f in findings)
    assert any(f.evidence.get('matched_passages') for f in findings)


def test_hosted_mode_selects_portable_worker_without_docker(monkeypatch):
    monkeypatch.setenv('NETRA_DEPLOYMENT_MODE', 'hosted')
    monkeypatch.delenv('NETRA_INSPECTION_MODE', raising=False)
    with patch('backend.inspection_client._portable_attachment', return_value={'available': True}) as worker, patch('backend.inspection_client.inspect_task') as docker:
        assert inspect_attachment(b'%PDF', 'statement.pdf', 'application/pdf')['available']
        worker.assert_called_once()
        docker.assert_not_called()


def test_explicit_docker_mode_never_falls_back(monkeypatch):
    monkeypatch.setenv('NETRA_DEPLOYMENT_MODE', 'hosted')
    monkeypatch.setenv('NETRA_INSPECTION_MODE', 'docker')
    with patch('backend.inspection_client.inspect_task', return_value={'available': False}), patch('backend.inspection_client._portable_attachment') as portable:
        assert not inspect_attachment(b'%PDF', 'statement.pdf', 'application/pdf')['available']
        portable.assert_not_called()


def test_unavailable_attachment_does_not_display_clean_score():
    view = explain_analysis({'parsed': {'attachment_analysis': {'attachments': [{'filename': 'statement.pdf', 'score': 0, 'risk_level': 'LOW', 'analysis_skipped': True}]}}})
    item = view['attachment_analysis']['attachments'][0]
    assert item['assessment_label'] == 'Not inspected'
    assert item['coverage'] == 'unavailable'


def test_encrypted_pdf_content_remains_unverified():
    result = AttachmentAnalyzer._analyze_one({'filename': 'statement.pdf', 'content_type': 'application/pdf', 'content': b'%PDF-1.4\n/Encrypt 3 0 R\n%%EOF'})
    assert result['content_coverage'] == 'limited'
    assert result['encrypted_pdf_marker']
    assert any('not been decrypted' in reason for reason in result['reasons'])


def test_bilingual_matrix_preserves_attack_detection():
    result = run()
    assert result['fp'] == 0
    assert result['tp'] == 4
