import pytest
from backend.url_analyzer import URLAnalyzer

def analyze(visible, actual):
    return URLAnalyzer.analyze_references([{"visible_text":visible,"href":actual}])

@pytest.mark.parametrize("visible,actual",[
    ("https://equery.irctc.co.in","https://www.irctc.co.in/nget/train-search"),
    ("https://support.example.com","https://www.example.com/help"),
    ("https://help.example.co.uk","https://accounts.example.co.uk/reset"),
    ("https://SHOP.EXAMPLE.COM./info","https://www.example.com/info"),
])
def test_sibling_subdomains_are_not_deceptive_mismatch(visible,actual):
    result=analyze(visible,actual)
    assert not result["urls"][0]["visible_href_mismatch"]
    assert not any(f["rule"]=="visible_href_mismatch" for f in result["findings"])
    assert any(f["rule"]=="same_domain_link_host_difference" and f["severity"]=="info" for f in result["findings"])

@pytest.mark.parametrize("visible,actual",[
    ("https://www.irctc.co.in","https://irctc.co.in.attacker.com/login"),
    ("https://www.example.com","https://example-login.com/login"),
    ("https://alice.github.io","https://bob.github.io/login"),
    ("https://alice.blogspot.com","https://bob.blogspot.com/login"),
    ("https://8.8.8.8","https://1.1.1.1"),
])
def test_unrelated_domains_and_separate_hosted_tenants_still_warn(visible,actual):
    assert any(f["rule"]=="visible_href_mismatch" and f["severity"]=="high" for f in analyze(visible,actual)["findings"])

def test_same_domain_does_not_skip_destination_risk_checks():
    result=analyze("https://help.example.com","https://paypal.verify-account.example.com/login")
    assert not result["urls"][0]["visible_href_mismatch"]
    assert result["urls"][0]["risk_score"]>0
    assert any(f["rule"]=="suspicious_url_features" for f in result["findings"])

def test_unicode_and_punycode_equivalent_names_match():
    result=analyze("https://b\u00fccher.de","https://xn--bcher-kva.de/info")
    assert not result["urls"][0]["visible_href_mismatch"]


def test_controlled_indian_banking_zone_preserves_bank_identity():
    from backend.domain_identity import registered_identity
    assert registered_identity("onlinesbi.sbi.bank.in") == "sbi.bank.in"
    analyzed = URLAnalyzer.analyze_url("https://onlinesbi.sbi.bank.in/")
    assert URLAnalyzer._base_domain(analyzed["hostname"]) == "sbi.bank.in"
    assert "SBI" not in analyzed["brand_impersonation"]


def test_same_domain_explanation_reaches_exported_report():
    from backend.presentation import explain_analysis,explanation_lines
    result=analyze("https://support.example.com","https://www.example.com/help")
    text="\n".join(explanation_lines(explain_analysis({"risk_score":0,"parsed":{"url_analysis":result}})))
    assert "different subdomains of example.com" in text
    assert "not counted as phishing" in text

def test_full_email_pipeline_does_not_flag_sibling_domain_label():
    from email.message import EmailMessage
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from evaluation.evaluate_v2 import OfflineIPs,OfflineDomains
    msg=EmailMessage();msg["From"]="sender@example.com";msg["Subject"]="Support information";msg.set_content("Support information");msg.add_alternative('<a href="https://www.example.com/help">https://support.example.com</a>',subtype="html")
    result=AnalysisOrchestrator(ip_provider=OfflineIPs(),domain_provider=OfflineDomains()).analyze(msg.as_bytes())
    rules=[f.rule for f in result.findings]
    assert "visible_href_mismatch" not in rules
    assert "same_domain_link_host_difference" in rules
