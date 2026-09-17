# External chain checkpoints

`scripts/anchor_ledger.py` verifies the existing ledger and sends only timestamp, record count and chain hash to a separately operated HTTPS store. Configure NETRA_ANCHOR_URL and NETRA_ANCHOR_SIGNING_KEY; the store must preserve checkpoints and return a durable receipt_id. Run from the repository root with `python -m scripts.anchor_ledger --database forensic_ledger.db --receipt outputs/anchor-receipt.json`. Use the operator's scheduler to run periodically and retain receipts separately from NETRA's database. Verify the HMAC signature at the store and restrict signing credentials. No messages, identities or database paths are sent.

No external store is configured in this repository. A locally saved receipt is not independent proof unless the external store actually preserves its checkpoint. Anchoring is tamper evidence, not prevention, legal admissibility or human attribution.

## Release checkpoint
A verified checkpoint of the configured local legacy evidence-record chain is committed in evaluation_results/upgrades/ledger_checkpoint.json. The containing GitHub commit is one lightweight external anchor; record its commit ID and retain it outside the database. This covers the local chain snapshot only, not Render's database or every separate custody chain. Git history can be rewritten or the repository deleted, so retain independent copies and use the signed external store for periodic production anchoring. No message content or database paths are published.
