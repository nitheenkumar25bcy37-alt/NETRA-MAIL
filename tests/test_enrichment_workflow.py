"""Synthetic provider fixtures: these are not live acceptance evidence."""
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
import pytest
from backend.intelligence.registration import RegistrationProvider
from backend.intelligence.network_enrichment import enrich_network
from backend.intelligence.infrastructure_reputation import InfrastructureReputation
from backend.intelligence.transport import Transport, LookupError
from backend.services.investigation_graph import build_graph


@pytest.fixture(autouse=True)
def enable(monkeypatch):
    for key in ("NETRA_REGISTRATION_ENABLED", "NETRA_NETWORK_ENRICHMENT_ENABLED", "NETRA_TOR_ENABLED", "NETRA_THREATFOX_ENABLED"):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("NETRA_THREATFOX_AUTH_KEY", "fixture-key")
    monkeypatch.delenv("NETRA_WHOISXML_API_KEY", raising=False)


def rdap():
    return {"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}], "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Fixture Registrar"]]]}], "status": ["active"], "nameservers": [{"ldhName": "ns.example.com"}]}


def reg_client(record):
    client = Mock()
    client.get.side_effect = [{"services": [[["com"], ["https://registry.example/"]]]}, record]
    return client


def test_registration_success_redaction_and_age():
    record = rdap(); record["redacted"] = [{"name": "Registrant"}]
    r = RegistrationProvider(reg_client(record)).lookup("mail.example.com")
    assert r["status"] == "redacted" and r["domain"] == "example.com"
    assert r["domain_age_days"] > 9000 and r["registrar"] == "Fixture Registrar"
    assert r["nameservers"] == ["ns.example.com"] and r["expires_at"]


@pytest.mark.parametrize("date", [None, "not-a-date", "2999-01-01T00:00:00Z"])
def test_registration_never_invents_age(date):
    record = rdap(); record["events"] = [{"eventAction": "registration", "eventDate": date}]
    result = RegistrationProvider(reg_client(record)).lookup("example.com")
    assert result["domain_age_days"] is None


@pytest.mark.parametrize("failure", ["rate_limited", "provider_unavailable", "unsupported_domain", "credential_or_permission_required"])
def test_registration_outages(failure):
    c = Mock(); c.get.side_effect = LookupError(failure)
    result = RegistrationProvider(c).lookup("example.com")
    assert result["status"] == failure and result["domain_age_days"] is None


@pytest.mark.parametrize("record", [{}, {"ldhName": "different.com"}, {"ldhName": "example.com", "entities": "wrong"}])
def test_malformed_registration(record):
    assert RegistrationProvider(reg_client(record)).lookup("example.com")["status"] == "malformed_response"


def test_licensed_whois_fallback(monkeypatch):
    monkeypatch.setenv("NETRA_WHOISXML_API_KEY", "secret")
    c = Mock(); c.get.side_effect = [{"services": []}, {"WhoisRecord": {"domainName": "example.com", "registrarName": "Fallback registrar", "createdDateNormalized": "2001-01-01 00:00:00 UTC"}}]
    # Provider UTC-normalized dates are supported.
    result = RegistrationProvider(c).lookup("example.com")
    assert result["registrar"] == "Fallback registrar" and result["domain_age_days"] > 9000
    assert "secret" not in json.dumps(result) and len(result["attempts"]) == 2


def test_network_missing_fields_and_conflicts():
    c = Mock(); c.get.return_value = {"status": "ok", "data": {"asns": [{"asn": 64500, "holder": "Network holder"}]}}
    r = enrich_network({"ip": "8.8.8.8", "asn": "AS15169", "country": "Example", "source": "fixture", "looked_up_at": "2026-01-01T00:00:00Z"}, c)
    assert r["asn"] == "AS15169" and r["organization"] == "Network holder"
    assert r.get("hosting_provider") is None and r.get("isp") is None
    assert "asn" in r["network_enrichment"]["conflicting_fields"]
    assert len(r["field_provenance"]["asn"]) == 2


@pytest.mark.parametrize("data", [{}, {"status": "ok", "data": {"asns": "bad"}}, {"status": "ok", "data": {"asns": [{"asn": "bad"}]}}])
def test_network_malformed(data):
    c = Mock(); c.get.return_value = data
    assert enrich_network({"ip": "8.8.8.8", "country": "Keep me"}, c)["network_enrichment"]["status"] == "malformed_response"


def test_tor_and_threatfox_freshness_and_email_time():
    now = datetime.now(timezone.utc); old = now - timedelta(days=60)
    c = Mock()
    c.get.side_effect = ["ExitAddress 8.8.8.8 " + now.strftime("%Y-%m-%d %H:%M:%S"), {"query_status": "ok", "data": [{"ioc_type": "ip:port", "ioc": "8.8.8.8:443", "threat_type": "botnet_cc", "malware": "fixture", "last_seen": old.isoformat()}]}]
    parsed = {"metadata": {"date": now.isoformat()}, "ip_intelligence": [{"ip": "8.8.8.8", "vpn": True, "source": "fixture", "looked_up_at": now.isoformat()}]}
    result = InfrastructureReputation(c).lookup(parsed)
    kinds = {o["kind"]: o for o in result["observations"]}
    assert kinds["tor_exit_observation"]["freshness"] == "fresh"
    assert kinds["malware_infrastructure_reputation"]["freshness"] == "expired_or_unknown"
    assert not kinds["malware_infrastructure_reputation"]["email_time_within_observation_window"]
    assert all(o["review_status"] == "needs_review" for o in kinds.values())
    assert "fixture-key" not in json.dumps(result)


def test_reputation_does_not_upload_content_or_url_tokens():
    c = Mock(); c.get.side_effect = ["bad tor response", {"query_status": "no_result"}]
    parsed = {"body": {"plain": "PRIVATE BODY"}, "urls": ["https://example.com/?secret=TOKEN"], "domain_intelligence": {"domains": [{"domain": "example.com"}]}}
    result = InfrastructureReputation(c).lookup(parsed)
    assert not result["observations"] and result["lookups"][0]["status"] == "malformed_response"
    assert "PRIVATE" not in str(c.mock_calls) and "TOKEN" not in str(c.mock_calls)


@pytest.mark.parametrize("status", [429, 401, 500, 302])
def test_transport_status_and_negative_cache(status):
    t = Transport(); response = Mock(status_code=status); t.session = Mock(); t.session.request.return_value = response
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]):
        for _ in range(2):
            with pytest.raises(LookupError): t.get("https://provider.example/data")
    assert t.session.request.call_count == 1
    assert t.session.request.call_args.kwargs["allow_redirects"] is False
    response.close.assert_called_once()


def test_transport_size_https_private_and_cache():
    t = Transport(); t.session = Mock()
    with pytest.raises(LookupError): t.get("http://provider.example")
    with patch("socket.getaddrinfo", return_value=[(None,None,None,None,("127.0.0.1",443))]):
        with pytest.raises(LookupError): t.get("https://private.example")
    response = Mock(status_code=200); response.iter_content.return_value = [b"x" * (2*1024*1024+1)]
    t.session.request.return_value = response
    with patch("socket.getaddrinfo", return_value=[(None,None,None,None,("8.8.8.8",443))]):
        with pytest.raises(LookupError): t.get("https://provider.example/large")
        response.iter_content.return_value = [b'{"value": 1}']
        assert t.get("https://provider.example/ok") == t.get("https://provider.example/ok")


def record(identifier):
    return {"email_id": identifier, "risk_score": 60, "parsed": {"metadata": {"from": "x@example.com"}, "urls": ["https://example.com/verify"], "attachments": [{"sha256": "a"*64}], "ip_intelligence": [{"ip": "8.8.8.8", "asn": "AS15169"}], "domain_intelligence": {"domains": [{"domain": "example.com", "registration": {"registrar": "Common registrar", "nameservers": ["common.ns"], "status": "ok"}}]}}}


def relation(fields):
    return {"source_email_id": "a", "target_email_id": "b", "relationship_type": fields[0], "confidence": 0.8, "created_at": "2026-09-26T00:00:00Z", "evidence": [{"field": field, "source_value": "exact fixture", "target_value": "exact fixture"} for field in fields]}


@pytest.mark.parametrize("fields", [["shared_asn"], ["shared_registered_domain", "shared_origin_ip"], ["shared_registrar", "shared_nameserver"], ["shared_sender", "body_structure_similarity"], ["vpn", "geography"]])
def test_graph_common_infrastructure_never_clusters(fields):
    a, b = record("a"), record("b")
    graph = build_graph(a, [relation(fields)], [b])
    assert not graph["candidate_clusters"]
    assert {"sender", "url", "attachment_hash", "asn", "registrar", "nameserver"} <= {n["type"] for n in graph["nodes"]}


def test_qualified_graph_cluster_has_precise_evidence():
    a, b = record("a"), record("b")
    edge = relation(["shared_url", "shared_sender"])
    graph = build_graph(a, [edge], [b])
    assert graph["candidate_clusters"][0]["email_ids"] == ["a", "b"]
    assert graph["candidate_clusters"][0]["supporting_edges"][0]["evidence"] == edge["evidence"]
    b["risk_score"] = 0
    assert not build_graph(a, [edge], [b])["candidate_clusters"]

def test_gmail_contract_to_persistence_dashboard_graph_and_pdf(monkeypatch):
    import io
    from email.message import EmailMessage
    from fastapi.testclient import TestClient
    from streamlit.testing.v1 import AppTest
    from pypdf import PdfReader
    import backend.main as api
    from backend.intelligence.domain_provider import DomainIntelligenceProvider
    from dashboard.api_client import APIClient
    from backend.intelligence.transport import transport
    from backend.intelligence.registration import RegistrationProvider
    msg = EmailMessage()
    msg['From'] = 'Sender <sender@example.com>'
    msg['To'] = 'recipient@example.org'
    msg['Subject'] = 'Synthetic workflow validation'
    msg['Received'] = 'from fixture.example.com (fixture.example.com [8.8.8.8]) by mx.example.org; Sat, 26 Sep 2026 10:00:00 +0000'
    msg.set_content('This synthetic message verifies the full investigation workflow with no private email data. Please review the project meeting notes tomorrow.')
    raw = msg.as_bytes()
    monkeypatch.setattr('backend.mailbox_ingestion.fetch_original', lambda *args: raw)
    monkeypatch.setattr('backend.dkim_verifier.DKIMVerifier.verify', lambda *args: {'status':'unavailable'})
    monkeypatch.setattr('backend.email_authentication.EmailAuthenticationVerifier._arc', lambda *args: {'status':'unavailable'})
    monkeypatch.setenv('NETRA_URL_REPUTATION_ENABLED','false')
    resolver = Mock(); resolver.resolve.return_value = []
    domain_provider = DomainIntelligenceProvider(resolver=resolver)
    monkeypatch.setattr(api.v2_orchestrator, 'domain_provider', domain_provider)
    def provider_data(url, **kwargs):
        if 'iana.org' in url: return {'services':[[['com'],['https://registry.example/']]]}
        if 'registry.example' in url: return rdap()
        if 'ripe.net' in url: return {'status':'ok','data':{'asns':[{'asn':15169,'holder':'Fixture network'}]}}
        if 'torproject.org' in url: return 'ExitAddress 1.1.1.1 2026-01-01 00:00:00'
        if 'threatfox' in url: return {'query_status':'no_result'}
        raise AssertionError('Unexpected external destination')
    monkeypatch.setattr(transport,'get',provider_data)
    monkeypatch.setattr(api.v2_orchestrator.ip_provider,'lookup',lambda ip: enrich_network({'ip':ip,'country':'Fixture country','city':'Fixture city','source':'synthetic provider','looked_up_at':'2026-09-26T00:00:00Z'}))
    client = TestClient(api.app)
    response = client.post('/api/v2/mailbox/analyze',json={'provider':'gmail','message_id':'0123456789ab','access_token':'synthetic-token'})
    assert response.status_code == 200, response.text
    payload = response.json(); email_id = payload['email_id']
    stored = api.db.get_v2_analysis(email_id)
    assert stored['parsed']['domain_intelligence']['domains'][0]['registration']['registrar'] == 'Fixture Registrar'
    assert 'synthetic-token' not in json.dumps(stored)
    def request(self, method, path, **kwargs):
        r = client.request(method,path,**kwargs); r.raise_for_status(); return r.json()
    monkeypatch.setattr(APIClient,'request',request)
    monkeypatch.setattr(APIClient,'download_report',lambda self,rid: client.get('/api/v2/reports/'+rid+'/download').content)
    dashboard = APIClient()
    assert dashboard.email(email_id)['explanation']['infrastructure']['registrations'][0]['domain_age_days'] > 9000
    assert any(n['type']=='registrar' for n in dashboard.graph(email_id)['nodes'])
    app = AppTest.from_file('../dashboard/app.py',default_timeout=30)
    app.query_params['email_id'] = email_id
    app.run()
    assert not app.exception
    assert any('Fixture Registrar' in str(m.value) for m in app.markdown)
    app.button(key='export_'+email_id).click().run()
    assert not app.exception and not app.error
    pdf = app.session_state['export_pdf_'+email_id]
    text = '\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
    assert 'Fixture Registrar' in text and 'Evidence graph analysis' in text
    assert 'Fixture country' in text and 'RIPEstat' in text
    assert client.get('/api/v2/evidence/'+payload['evidence_reference']['evidence_id']+'/verify').json()['match']

@pytest.mark.parametrize('failure',['rate_limited','provider_unavailable','credential_or_permission_required'])
def test_reputation_outage_is_not_a_safe_verdict(failure):
    c=Mock(); c.get.side_effect=LookupError(failure)
    result=InfrastructureReputation(c).lookup({'ip_intelligence':[{'ip':'8.8.8.8'}]})
    assert not result['observations']
    assert all(item['status']==failure for item in result['lookups'])
    assert 'not safe' in result['limitations'][0]


def test_provider_geo_vpn_and_shared_network_cannot_raise_verdict():
    from backend.services.origin_trace import OriginTraceService
    from backend.services.risk_engine import RiskEngine
    provider=Mock();provider.lookup.return_value={'vpn':True,'hosting_provider':'Fixture cloud','country':'Far away'}
    trace=OriginTraceService.build({'network_chain':[{'extracted_ips':['8.8.8.8'],'ip_classifications':['public']}]},provider)
    assert all(item['severity']=='info' for item in trace['findings'])
    assert RiskEngine.evaluate(trace['findings'])['risk_score']==0


def test_campaign_service_does_not_promote_common_cloud(tmp_path):
    from backend.database import ForensicLedgerDB
    from backend.services.campaign_service import CampaignService
    db=ForensicLedgerDB(str(tmp_path/'ledger.db'))
    a,b=record('a'),record('b')
    for item in (a,b):
        item['parsed']['urls']=[];item['parsed']['attachments']=[]
        db.record_v2_analysis(item['email_id'],item['email_id']*64,item)
    with patch('backend.services.campaign_service.CampaignCorrelator.correlate',return_value=[relation(['shared_origin_ip','shared_asn','shared_registrar'])]):
        result=CampaignService(db).correlate('a')
    assert result['relationships_found']==1 and not result['candidate_campaigns']


def test_graph_neighbourhood_stops_at_two_hops():
    records=[record(name) for name in ('a','b','c','d')]
    edges=[]
    for a,b in (('a','b'),('b','c'),('c','d')):
        r=relation(['shared_url','shared_sender']);r.update(source_email_id=a,target_email_id=b);edges.append(r)
    graph=build_graph(records[0],edges,records)
    assert graph['neighbourhood']=={'a':0,'b':1,'c':2}
    assert graph['candidate_clusters'][0]['email_ids']==['a','b','c']

def test_registration_uses_offline_registry_suffix_boundary():
    from backend.intelligence.registration import registration_domain
    assert registration_domain('mail.company.co.uk')=='company.co.uk'
    assert registration_domain('tenant.github.io')=='github.io'
    assert registration_domain('private.internal')==''
    c=Mock()
    assert RegistrationProvider(c).lookup('private.internal')['status']=='unsupported_domain'
    c.get.assert_not_called()
