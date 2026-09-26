from unittest.mock import Mock, patch
from email.message import EmailMessage
import json
import pytest
from backend.intelligence.ip_provider import IPIntelligenceProvider
from backend.email_authentication import EmailAuthenticationVerifier
from backend.services.origin_trace import OriginTraceService
from backend.presentation import explain_origin


def test_ipstack_location_cache_and_no_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("NETRA_IPSTACK_API_KEY", "test-secret")
    response = Mock(status_code=200)
    response.json.return_value = {"ip": "195.201.243.180", "country_name": "Germany", "region_name": "Bavaria", "city": "Gunzenhausen", "latitude": 49.1, "longitude": 10.7}
    response.iter_content.return_value = [json.dumps(response.json.return_value).encode()]
    with patch("backend.intelligence.ip_provider.requests.get", return_value=response) as request:
        provider = IPIntelligenceProvider(cache_dir=str(tmp_path))
        result = provider.lookup("195.201.243.180")
        assert result["country"] == "Germany" and result["source"] == "ipstack"
        assert result["vpn"] is None and not result["security_details_available"]
        assert provider.lookup("195.201.243.180") == result
        assert request.call_count == 1
        assert request.call_args.kwargs["allow_redirects"] is False
        assert "test-secret" not in json.dumps(result)
        assert all("test-secret" not in p.read_text() for p in tmp_path.rglob("*.json"))
        provider.lookup("127.0.0.1")
        assert request.call_count == 1


@pytest.mark.parametrize("code,source", [(101,"provider_configuration_error"),(104,"provider_rate_limited"),(105,"provider_configuration_error")])
def test_ipstack_errors_are_explained(tmp_path,monkeypatch,code,source):
    monkeypatch.setenv("NETRA_IPSTACK_API_KEY", "test-secret")
    response=Mock(status_code=200)
    response.json.return_value={"success":False,"error":{"code":code,"info":"untrusted secret"}}
    response.iter_content.return_value = [json.dumps(response.json.return_value).encode()]
    with patch("backend.intelligence.ip_provider.requests.get",return_value=response):
        result=IPIntelligenceProvider(cache_dir=str(tmp_path)).lookup("8.8.8.8")
    assert result["source"]==source and not result["available"]
    assert "untrusted secret" not in json.dumps(result)


@pytest.mark.parametrize("ip", ["195.201.243.180", "2001:4860:4860::8888"])
def test_gmail_spf_ip_reaches_dashboard(ip):
    msg=EmailMessage()
    msg["From"]="sender@example.com"
    msg["Authentication-Results"]=f"mx.google.com; spf=pass (google.com: domain designates {ip} as permitted sender) smtp.mailfrom=sender@example.com; dmarc=pass header.from=example.com"
    msg.set_content("Test")
    with patch("backend.email_authentication.DKIMVerifier.verify",return_value={"status":"unsigned"}), patch.object(EmailAuthenticationVerifier,"_arc",return_value={}):
        trusted=EmailAuthenticationVerifier().verify(msg.as_bytes(),trusted_receiver="gmail")
        upload=EmailAuthenticationVerifier().verify(msg.as_bytes())
    assert trusted["spf"]["client_ip"]==ip
    assert "client_ip" not in upload["spf"]
    provider=Mock()
    provider.lookup.return_value={"available":True,"country":"Germany","latitude":49.1,"longitude":10.7,"source":"ipstack"}
    trace=OriginTraceService.build({"verified_authentication":trusted},provider)
    server=explain_origin(trace)["servers"][0]
    assert server["ip"]==ip and server["coordinates"]
    assert "Gmail" in server["role"] and server["provider"]=="ipstack"
    provider.lookup.assert_called_once_with(ip)
