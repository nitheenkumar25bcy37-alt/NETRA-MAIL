# Gmail original-message verification

The visible Gmail page contains reconstructed content, not the signed MIME bytes. It cannot establish SPF, DKIM, DMARC or ARC results.

## One-time deployment setup
1. Open Google Cloud Console and select or create your NETRA project.
2. Enable Gmail API. Configure Google Auth Platform branding, audience and data access for gmail.readonly. In testing, add each Gmail test account as a test user.
3. In Chrome extensions, enable Developer mode and copy NETRA's extension ID.
4. Create an OAuth client of type Chrome Extension using that exact extension ID.
5. Run the project Python runtime with scripts/configure_gmail_oauth.py --client-id YOUR_CLIENT_ID.apps.googleusercontent.com.
6. Reload the extension and Gmail tab. Analyze current email prompts for Google consent, then sends only the selected message ID and short-lived token to NETRA. The backend fetches original MIME directly from Gmail. Tokens are not saved by NETRA or exposed in reports.

Public distribution with Gmail read-only scope may require Google's OAuth verification. No shared user token belongs in Git.

## Without Google setup
Use the investigation dashboard's Verify an original email section. Gmail message menu > Show original > Download Original. Upload the .eml to create a new investigation. DKIM and ARC can be verified when signatures and DNS evidence are available; SPF claims in uploaded headers are not trusted. A message without signatures or a forwarding chain cannot produce a verified pass for those checks.

Local verification and Gmail's delivery-time results are displayed separately. Authentication passes establish identity/integrity evidence, not safe intent. Older investigations must be reanalyzed from original data.
