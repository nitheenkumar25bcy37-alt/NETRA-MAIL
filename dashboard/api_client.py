from __future__ import annotations

import os
from typing import Any, Dict

import requests


class APIClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or os.getenv("NETRA_API_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.api_key = os.getenv("NETRA_API_ACCESS_KEY", "").strip()

    def request(self, method: str, path: str, **kwargs) -> Any:
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.api_key:
            headers["X-NETRA-API-Key"] = self.api_key
        timeout = kwargs.pop("timeout", 45)
        response = requests.request(method, f"{self.base_url}{path}", timeout=timeout, headers=headers, allow_redirects=False, **kwargs)
        if 300 <= response.status_code < 400:
            raise RuntimeError("Backend redirects are not permitted.")
        if response.status_code == 404 and path.startswith("/api/v2/emails/"):
            raise RuntimeError(
                "This investigation was not found on the configured NETRA backend "
                f"({self.base_url}). Confirm that the dashboard and Gmail extension "
                "use the same API address, then analyze the email again if the "
                "backend data was reset."
            )
        response.raise_for_status()
        return response.json()

    def get(self, path: str, **kwargs) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Any:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs) -> Any:
        return self.request("PATCH", path, **kwargs)

    def summary(self) -> Dict[str, Any]:
        return self.get("/api/v2/dashboard/summary")

    def emails(self, limit: int = 50, offset: int = 0, risk_level: str | None = None) -> Dict[str, Any]:
        params = {"limit": limit, "offset": offset}
        if risk_level:
            params["risk_level"] = risk_level
        return self.get("/api/v2/emails", params=params)

    def email(self, email_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/emails/{email_id}")

    def upload_original(self, filename: str, raw: bytes) -> Dict[str, Any]:
        return self.post("/api/v2/emails/upload", files={"file": (filename, raw, "message/rfc822")})

    def unlock_pdf(self, email_id: str, digest: str, password: str):
        from urllib.parse import urlsplit
        target = urlsplit(self.base_url)
        local = target.hostname in {"localhost", "127.0.0.1", "::1"}
        if target.username or target.password or not (target.scheme == "https" or (local and target.scheme == "http")):
            raise ValueError("PDF passwords require HTTPS, except on localhost.")
        return self.post(f"/api/v2/emails/{email_id}/attachments/{digest}/unlock",
                         json={"password": password, "consent": True}, timeout=90)

    def findings(self, email_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/emails/{email_id}/findings")

    def trace(self, email_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/emails/{email_id}/trace")

    def graph(self, email_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/emails/{email_id}/graph")

    def relationships(self, email_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/emails/{email_id}/relationships")

    def ip_intelligence(self, ip: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/intelligence/ip/{ip}")

    def campaigns(self) -> Dict[str, Any]:
        return self.get("/api/v2/campaigns")

    def cases(self) -> Dict[str, Any]:
        return self.get("/api/v2/cases")

    def case(self, case_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/cases/{case_id}")

    def case_evidence(self, case_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/cases/{case_id}/evidence")

    def case_timeline(self, case_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/cases/{case_id}/timeline")

    def evidence(self, evidence_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/evidence/{evidence_id}")

    def evidence_verify(self, evidence_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/evidence/{evidence_id}/verify")

    def reports(self, case_id: str) -> Dict[str, Any]:
        return self.get(f"/api/v2/cases/{case_id}/reports")

    def create_report(self, case_id: str, report_format: str) -> Dict[str, Any]:
        return self.post(f"/api/v2/cases/{case_id}/reports", params={"report_format": report_format})

    def link_evidence(self, case_id: str, evidence_id: str):
        return self.post(f"/api/v2/cases/{case_id}/evidence/{evidence_id}")

    def download_report(self, report_id: str):
        response = requests.get(f"{self.base_url}/api/v2/reports/{report_id}/download",
            headers={"X-NETRA-API-Key": self.api_key} if self.api_key else {},
            timeout=45, allow_redirects=False, stream=True)
        try:
            if 300 <= response.status_code < 400:
                raise RuntimeError("Backend redirects are not permitted.")
            response.raise_for_status()
            payload = bytearray()
            for chunk in response.iter_content(65536):
                payload.extend(chunk)
                if len(payload) > 20 * 1024 * 1024:
                    raise RuntimeError("Report exceeds download limit.")
            return bytes(payload)
        finally:
            response.close()

    def create_case(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.post("/api/v2/cases", json=payload)

    def update_case(self, case_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.patch(f"/api/v2/cases/{case_id}", json=payload)

    def add_note(self, case_id: str, note: str) -> Dict[str, Any]:
        return self.post(f"/api/v2/cases/{case_id}/notes", json={"note": note})

    def add_tag(self, case_id: str, tag: str) -> Dict[str, Any]:
        return self.post(f"/api/v2/cases/{case_id}/tags", json={"tag": tag})
