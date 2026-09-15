# Render deployment

The repository Blueprint creates two services:

- `netra-mail-api`: FastAPI, with a persistent disk for the SQLite forensic ledger and encrypted evidence.
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

- `NETRA_PUBLIC_ORIGIN`: the API's HTTPS Render URL, normally `https://netra-mail-api.onrender.com`.
- `NETRA_API_IDENTITIES`: the generated value with the same name.
- `NETRA_EVIDENCE_KEYS_JSON`: the generated value with the same name.

Enter these prompted values for the dashboard service:

- `NETRA_API_URL`: the API's HTTPS Render URL, with no trailing slash.
- `NETRA_API_ACCESS_KEY`: the generated `DASHBOARD_ACCESS_KEY` value.

Apply the Blueprint and wait for both health checks to pass. If Render changes the
API service name because the requested name is unavailable, update both URL values
to the URL Render assigned and redeploy.

## 3. Connect the Chrome extension

Open the extension popup and expand **Backend authentication**. Set:

- **NETRA server address**: the API's HTTPS Render URL.
- **Access key**: the generated `EXTENSION_ACCESS_KEY` value.
- **SOC dashboard address**: the dashboard's HTTPS Render URL.

Choose **Use key for this browser session**, approve Chrome's requested permission
for the API host, open a Gmail message, and select **Analyze current email**.

The access key is intentionally stored only for the current browser session. Enter
it again after the browser session ends.
