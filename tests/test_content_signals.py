from backend.services.content_signals import inspect_content


def rules(text="", html=""):
    return {finding.rule for finding in inspect_content(text, html)}


def test_payment_change_requires_payment_instruction():
    assert "payment_destination_change" in rules("Please remit to our new bank account.")
    assert "payment_destination_change" not in rules("Your new account is ready.")
    assert "payment_destination_change" not in rules("Please pay the normal invoice.")


def test_script_confusable_domain_and_legitimate_idn():
    assert "mixed_script_domain" in rules("https://p\u0430ypal.example/login")
    assert "mixed_script_domain" in rules("https://xn--pypal-4ve.example/login")
    assert "mixed_script_domain" not in rules("https://\u092d\u093e\u0930\u0924.example/")


def test_payload_assembly_requires_multiple_signals():
    assert "html_payload_assembly" in rules(html="<script>URL.createObjectURL(new Blob([atob(x)]))</script>")
    assert "html_payload_assembly" not in rules(html="<p>Blob storage documentation</p>")


def test_direction_controls_are_reviewable_not_language_classification():
    assert "bidirectional_control" in rules("invoice\u202eexe.pdf")
    assert not rules("Normal meeting agenda")


def test_generic_money_and_click_language_does_not_form_bec(tmp_path, monkeypatch):
    from email.message import EmailMessage
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from evaluation.evaluate_v2 import OfflineDomains, OfflineIPs
    monkeypatch.setattr("backend.dkim_verifier.DKIMVerifier.verify", lambda *a: {"status": "unsigned", "signatures": [], "limitations": []})
    message = EmailMessage(); message["From"] = "jobs@example.com"; message["To"] = "user@example.com"
    message["Subject"] = "Earn money with new roles"; message.set_content("Click here to view roles: https://example.com/jobs")
    result = AnalysisOrchestrator(ip_provider=OfflineIPs(), domain_provider=OfflineDomains()).analyze(message.as_bytes())
    assert all(finding.rule != "payment_authority_combination" for finding in result.findings)


def test_html_metadata_and_hidden_text_do_not_enter_visible_nlp():
    from backend.parser import ForensicEmailParser
    html = "<head><title><!--terminated manager payment password--></title><style>.payment{}</style></head><body><p>Competition prize pool. Register now.</p><div style='display: none'><span>wire money urgently</span></div><p>Welcome students</p><script>password</script></body>"
    details = ForensicEmailParser._extract_html_details(html)
    assert "Welcome students" in details["visible_text"]
    assert all(word not in details["visible_text"] for word in ["terminated", "password", "wire", "manager"])


def test_promotion_metadata_does_not_trigger_bec_and_attack_still_does(monkeypatch):
    from email.message import EmailMessage
    from backend.services.analysis_orchestrator import AnalysisOrchestrator
    from evaluation.evaluate_v2 import OfflineDomains, OfflineIPs
    monkeypatch.setattr("backend.dkim_verifier.DKIMVerifier.verify", lambda *a: {"status": "unsigned", "signatures": [], "limitations": []})
    engine = AnalysisOrchestrator(ip_provider=OfflineIPs(), domain_provider=OfflineDomains())
    message = EmailMessage(); message["From"] = "events@example.com"; message["Subject"] = "Competition invitation"
    message.set_content("<html><body><p>Register for a competition with a prize pool and career opportunities.</p><title><!--terminated manager bank account payment login password--></title></body></html>", subtype="html")
    result = engine.analyze(message.as_bytes())
    assert result.classification == "Legitimate or low risk"
    assert all(f.rule not in {"contextual_social_engineering", "payment_authority_combination"} for f in result.findings)
    message.set_content("The manager requests that you wire money to our new bank account urgently.")
    attack = engine.analyze(message.as_bytes())
    assert attack.classification == "Business Email Compromise"
    assert any(f.rule == "payment_destination_change" for f in attack.findings)
