# Privacy, masking and retention policy

## Purpose and responsibility
Analyze only messages explicitly selected by the user for threat detection and investigation. The deployment operator is responsible for notices, lawful processing, consent management, grievance handling and applicable retention obligations. NETRA is not certified legally compliant.

## Data and safeguards
Original MIME and attachments are sensitive evidence. Restrict them to authorized identities, encrypt protected evidence, redact PII in ordinary reports, and preserve access/custody records. Gmail OAuth tokens are short-lived and must not be persisted in evidence or logs. IP providers receive only observed public IPs; original bodies are not sent to them. Domain reputation providers can receive extracted URLs: disclose this in the deployment notice and enable deliberately. Public benchmark messages stay local and are excluded from git.

## Retention and erasure
Recommended prototype policy: review raw evidence after 30 days and retain only for an active investigation, legal hold or applicable statutory requirement. This is an operator policy, not an implemented automatic purge or a universal legal deadline. Apply a documented retention schedule to encrypted evidence, reports, backups, caches and logs. Authorize erasure requests, record a non-PII custody tombstone, and preserve ledger verification semantics; do not silently remove hash-chain rows. Deleting a report alone does not erase source evidence. Production rollout requires tested erasure and backup expiry procedures.

## Framework mapping
The Digital Personal Data Protection Act, 2023 informs purpose limitation/notice, consent, reasonable security safeguards, correction/erasure and grievance handling. Applicability and commencement of the Act and Rules must be reviewed for the actual operator. Proposed 30-day prototype review does not override legal retention.

Official sources: [DPDP Act](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf), [DPDP Rules 2025](https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa?pageTitle=Digital-Personal-Data-Protection-Rules-2025).
