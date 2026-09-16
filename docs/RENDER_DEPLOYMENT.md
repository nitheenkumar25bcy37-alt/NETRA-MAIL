# Render deployment

The repository Blueprint creates two services:

- `netra-mail`: FastAPI, with a persistent disk for the SQLite forensic ledger and encrypted evidence.
- `netra-mail-dashboard`: Streamlit, connected to the API over HTTPS.

The API uses a paid Render compute plan because Render persistent disks are not available to free web services. Review the selected `1c-2g` plan and disk price before applying the Blueprint.

## 1. Generate deployment secrets

Run this once in a local terminal:

```powershell
.\.venv\Scripts\python.exe scripts/generate_render_secrets.py
```

Keep all four output values private. Do not commit them or paste them into an issue.

## 2. Create the Blueprint

In Render, choose **New > Blueprint**, connect the GitHub repository
`nitheenkumar25bcy37-alt/NETRA-MAIL`, and select the `main` branch. Render reads
`render.yaml` from the repository root.

Enter these prompted values for the API service:

- `NETRA_PUBLIC_ORIGIN`: the API's HTTPS Render URL, normally `https://netra-mail.onrender.com`.
- `NETRA_API_IDENTITIES`: the generated value with the same name.
- `NETRA_EVIDENCE_KEYS_JSON`: the generated value with the same name.

Enter these prompted values for the dashboard service:

- `NETRA_API_ACCESS_KEY`: the generated `DASHBOARD_ACCESS_KEY` value.

The Blueprint sets `NETRA_API_URL` and `NETRA_ALLOWED_API_ORIGINS` to the
standard NETRA API service. If Render assigns a different API hostname, update
both values to that HTTPS origin with no trailing slash.

Apply the Blueprint and wait for both health checks to pass. If Render changes the
API service name because the requested name is unavailable, update both URL values
to the URL Render assigned and redeploy.

## 3. Connect the Chrome extension

The packaged extension automatically uses the deployed NETRA API and SOC dashboard,
starts with Email Protection enabled, and can submit the currently selected Gmail
message without a shared access key. Open a Gmail message and select
**Analyze current email**.

Only that analysis submission route accepts the configured Chrome extension origin.
SOC, investigation, evidence, reporting and dashboard routes still require their
configured credentials. **Advanced connection settings** remains available for a
private or custom backend.
