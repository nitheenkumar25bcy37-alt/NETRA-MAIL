# NETRA-Mail: SIH 2026 Finalist Demonstration Guide

## One-line proposition

NETRA-Mail transforms a suspicious email into an investigation-ready case: it
detects risk, explains the evidence, traces observed infrastructure, correlates
related campaigns, and preserves tamper-evident evidence for analyst review.

## Direct alignment with SIH Problem Statement 26106

| SIH requirement | NETRA-Mail implementation | Responsible boundary |
| --- | --- | --- |
| AI-powered fraud detection | Explainable NLP, ML, sender/domain checks, URL analysis, and static attachment analysis | A risk score assists analysts; it is not a guarantee. |
| Header and protocol analysis | Received-chain parsing; Return-Path, Reply-To, display-name, SPF/DKIM/DMARC-result and alignment analysis | Upstream authentication results are labelled as such; a DKIM header alone is never a PASS. |
| Origin traceability and geolocation | Public origin-candidate extraction, IP classification, optional provider-backed GeoIP, origin infrastructure map | A network location does not prove the physical location or identity of a sender. |
| Identity correlation | Campaign and case correlation through shared domains, IPs, URLs, and message indicators | Correlation requires analyst confirmation and is not human attribution. |
| Dashboard and forensic reporting | Case timeline, integrity checks, campaign view, HTML/JSON/PDF reports | Evidence hashes verify integrity, not truthfulness. |
| Privacy and evidentiary safeguards | PII masking, manual Gmail analysis, evidence hashes, versions, custody events, configurable protected deployment | Networked deployments must enable API authentication and use managed secrets. |

## Three-minute live demo

### 1. Detect — 35 seconds

Open a suspicious invoice or credential-phishing email and select **Analyze
current email** in the NETRA-Mail browser extension. Emphasize that analysis is
user-initiated; opening an email alone does not transmit its contents.

Show the final risk, confidence, and concise explanation: deceptive URL,
sender/Reply-To mismatch, urgent payment language, or dangerous attachment.

### 2. Explain and trace — 55 seconds

Open the analyst dashboard and select the analyzed email. Walk through:

1. Structured findings and their evidence.
2. Relay hops and the earliest observed public origin candidate.
3. The origin infrastructure map, ASN/provider, and VPN/proxy/Tor indicators
   when an intelligence provider is configured.
4. The explicit limitation: infrastructure intelligence supports investigation;
   it does not identify a human attacker.

### 3. Correlate and preserve — 55 seconds

Link the email to a case. Show related emails or campaign relationships,
evidence SHA-256, custody timeline, and integrity verification. Generate a PDF
or HTML report for an incident-response or legal-review workflow.

### 4. Close with measurable evidence — 35 seconds

Show the current evaluation report and test result. State only measured facts:

- Scenario checks: 23/24 passed; these are functional scenarios, not final
  population accuracy.
- URL benchmark recall: 40.74%; therefore a low-risk URL is never presented as
  conclusive proof of safety.
- Current full automated suite: 37 passing tests.

Finish with: **"NETRA-Mail does not merely label an email. It gives an analyst
the evidence, context, and custody record needed to act responsibly."**

## Judge questions: concise answers

**Why is this more than a spam filter?** It connects detection to relay-path
evidence, domain/IP intelligence, cases, campaign correlation, and a
tamper-evident evidence lifecycle.

**How do you prevent false confidence?** Every score is explainable; provider
results and limits are returned in the response; source-IP geolocation and
campaign correlation are explicitly labelled as investigative signals rather
than identity proof.

**How is privacy handled?** The extension is manual, PII is masked for
analyst/AI-facing processing, evidence uses controlled storage, and deployments
can require an API access key. Retention must be configured by the institution.

**What is the next technical milestone?** Cryptographic DKIM verification and
independent SPF/DMARC DNS evaluation on the original message bytes, followed by
evaluation on a labelled, previously unseen email corpus.

## Pre-demo checklist

- Run `python -m pytest -q tests` and show the passing result.
- Start the backend and dashboard before judges arrive.
- Preload one legitimate email, one BEC/invoice email, and one attachment or
  link-based phishing email.
- Configure an IP-intelligence endpoint only if it is stable; the demo remains
  honest and usable without it.
- Never claim a final email accuracy or human-attacker attribution unless you
  can present a valid dataset/evidence for that exact claim.
