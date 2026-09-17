import hashlib,json
from backend.services.risk_engine import RiskEngine
from backend.domain_confusables import inspect_hostname
from backend.header_analyzer import HeaderForensicAnalyzer
from backend.attachment_reputation import apply_reputation

def finding(rule,category="Authentication",severity="medium"):
    return {"rule":rule,"category":category,"severity":severity,"confidence":.9}
def test_verified_failure_needs_independent_spoof():
    assert RiskEngine.evaluate([finding("local_dkim_failure")])["risk_score"]<75
    assert RiskEngine.evaluate([finding("local_dkim_failure"),finding("display_name_impersonation","Sender identity")])["risk_score"]>=75
    assert not RiskEngine.evaluate([finding("dkim_failure"),finding("display_name_impersonation","Sender identity")])["escalations"]
def test_executable_escalation_explained():
    result=RiskEngine.evaluate([finding("attachment_static_critical","Attachment","critical")])
    assert result["risk_score"]>=75 and result["escalations"]
def test_idn_is_not_automatically_a_brand_homograph():
    assert inspect_hostname("p\u0430ypal.com",{"paypal"})["lookalike"]
    assert not inspect_hostname("\u092d\u093e\u0930\u0924.in",{"paypal"})["lookalike"]
    assert inspect_hostname("p\u0430ypal.com".encode("idna").decode(),{"paypal"})["lookalike"]
def test_mixed_timezone_headers_do_not_crash():
    result=HeaderForensicAnalyzer._relay_findings([{"timestamp":"2025-01-01T12:00:00"},{"timestamp":"2025-01-01T10:00:00+00:00"}])
    assert isinstance(result,list)
def test_blocklist_known_hash_and_unknown(tmp_path,monkeypatch):
    digest=hashlib.sha256(b"test").hexdigest();p=tmp_path/"hashes.json";p.write_text(json.dumps([digest]));monkeypatch.setenv("NETRA_ATTACHMENT_BLOCKLIST",str(p))
    result=apply_reputation({"sha256":digest,"score":0,"reasons":[]})
    assert result["score"]==100 and result["reputation"]["matched"]
    assert apply_reputation({"sha256":"0"*64,"score":0})["score"]==0

def test_mutations_require_key_and_origin_is_not_identity(monkeypatch):
    from backend.access_control import AccessPolicy
    from fastapi.testclient import TestClient
    import backend.main as main
    monkeypatch.setattr(main,"access_policy",AccessPolicy(json.dumps([{"subject":"admin","role":"admin","key_sha256":hashlib.sha256(b"secret").hexdigest()}])))
    monkeypatch.setattr(main,"ALLOW_EXTENSION_SUBMISSIONS",True)
    client=TestClient(main.app)
    for path in ["/api/v2/cases","/api/v2/emails/analyze","/api/v2/emails/upload"]:
        assert client.post(path).status_code==401
    if main.NETRA_EXTENSION_ORIGIN:
        assert client.post("/api/v2/emails/analyze",headers={"Origin":main.NETRA_EXTENSION_ORIGIN}).status_code==401

def test_mutation_rate_limit_returns_429(monkeypatch):
    from backend.access_control import AccessPolicy
    from fastapi.testclient import TestClient
    import backend.main as main
    monkeypatch.setattr(main,"access_policy",AccessPolicy(json.dumps([{"subject":"admin","role":"admin","key_sha256":hashlib.sha256(b"secret").hexdigest()}])))
    monkeypatch.setattr(main.rate_limiter,"allow",lambda key:False)
    assert TestClient(main.app).post("/api/v2/cases",headers={"X-NETRA-API-Key":"secret"}).status_code==429


def test_phrase_similarity_detects_request_but_not_safety_advice():
    from backend.services.phrase_similarity import inspect_phrases
    assert inspect_phrases("Confirm your pass word and verification code to prevent your account from being suspended.")
    assert not inspect_phrases("Never provide your login details or password to anyone.")
    assert not inspect_phrases("You requested a password reset. Use the reset link if you made this request; otherwise ignore this email.")

def test_brand_in_unrelated_sender_does_not_bypass_spoof_check():
    result=HeaderForensicAnalyzer.analyze({"metadata":{"from":"PayPal <sender@google.com>"}})
    assert any(f["rule"]=="display_name_impersonation" for f in result["findings"])

def test_external_anchor_refuses_invalid_chain():
    import pytest
    from scripts.anchor_ledger import checkpoint
    class Invalid:
        def verify_chain_integrity(self): return {"valid":False}
    with pytest.raises(ValueError): checkpoint(Invalid())

def test_external_anchor_requires_receipt(monkeypatch):
    import pytest
    from scripts.anchor_ledger import publish
    class Reply:
        status_code=200
        def json(self):return {"receipt_id":"external-001"}
    captured={}
    def post(url,**kwargs):captured.update(kwargs);return Reply()
    monkeypatch.setattr("scripts.anchor_ledger.requests.post",post)
    result=publish({"chain_hash":"a"*64,"record_count":1},"https://anchor.example/checkpoints","secret")
    assert result["receipt"]["receipt_id"]=="external-001"
    assert captured["allow_redirects"] is False
    assert len(captured["headers"]["X-NETRA-Checkpoint-Signature"])==64
    with pytest.raises(ValueError):publish({},"http://anchor.example","secret")


def test_shortener_final_destination_is_analyzed_before_scoring(monkeypatch):
    from email.message import EmailMessage
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from evaluation.evaluate_v2 import OfflineIPs,OfflineDomains
    from backend.url_expander import URLExpander
    final="https://paypal.verify-account.xyz.com/login"
    monkeypatch.setattr(URLExpander,"expand",lambda url:{"original_url":url,"final_url":final,"expanded":True,"redirect_chain":[url,final]})
    message=EmailMessage();message["From"]="sender@example.test";message["Subject"]="Link";message.set_content("See https://bit.ly/test")
    result=AnalysisOrchestrator(ip_provider=OfflineIPs(),domain_provider=OfflineDomains()).analyze(message.as_bytes())
    assert result.parsed["url_expansions"][0]["final_url"]==final
    assert any(u["href"]==final for u in result.parsed["url_analysis"]["urls"])

def test_stale_calibration_cannot_change_raw_probability(tmp_path,monkeypatch):
    from backend.ml_classifier import LocalMLClassifier
    path=tmp_path/"calibration.json";path.write_text(json.dumps({"model_sha256":"0"*64,"slope":10,"intercept":10,"activated":True}))
    monkeypatch.setenv("NETRA_ML_CALIBRATION",str(path))
    result=LocalMLClassifier.predict("Meeting tomorrow at noon")
    assert result["calibration_status"]=="invalid_or_stale"
    assert result["phishing_probability"]==result["raw_phishing_probability"]


def test_calibration_text_matches_production_readable_features():
    from email.message import EmailMessage
    from evaluation.calibrate_email_model import text
    from backend.parser import ForensicEmailParser
    from backend.services.email_features import email_feature_text
    msg=EmailMessage();msg["From"]="sender@example.test";msg["Subject"]="Identity review";msg.set_content("Plain request");msg.add_alternative("<p>Visible request</p><script>hidden code</script>",subtype="html")
    raw=msg.as_bytes()
    assert text(raw)==email_feature_text(ForensicEmailParser().parse_eml_bytes(raw))
    assert "hidden code" not in text(raw)


def test_concurrent_model_cold_start_in_fresh_process():
    import subprocess,sys
    code=r"""
from concurrent.futures import ThreadPoolExecutor
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from evaluation.evaluate_v2 import OfflineIPs,OfflineDomains
analyzer=AnalysisOrchestrator(ip_provider=OfflineIPs(),domain_provider=OfflineDomains())
raw=b'From: sender@example.test\nSubject: Project meeting\n\nMeeting tomorrow. https://example.com/info'
with ThreadPoolExecutor(max_workers=10) as pool:
    results=list(pool.map(lambda _:analyzer.analyze(raw),range(20)))
assert len(results)==20
assert all(r.parsed['ml_analysis']['available'] for r in results)
"""
    subprocess.run([sys.executable,"-c",code],check=True,timeout=60)
