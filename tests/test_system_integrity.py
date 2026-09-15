from fastapi.testclient import TestClient

from backend.main import app


def test_health_endpoint_is_available_without_deployment_authentication():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_v2_analysis_rejects_empty_content():
    response = TestClient(app).post("/api/v2/emails/analyze", json={})
    assert response.status_code == 400
    assert response.json()["detail"] == "Email content is empty."
