"""Publish a minimal signed ledger checkpoint to a separately operated HTTPS store."""
import argparse,hashlib,hmac,json,os
from datetime import datetime,timezone
from pathlib import Path
import requests
from backend.database import ForensicLedgerDB

def checkpoint(db):
    state=db.verify_chain_integrity()
    if not state.get("valid"): raise ValueError("Refusing to anchor an invalid chain")
    return {"version":1,"created_at":datetime.now(timezone.utc).isoformat(),"record_count":state["total_records"],"chain_hash":state["latest_hash"]}
def publish(payload,endpoint,key):
    from urllib.parse import urlparse
    parsed=urlparse(endpoint)
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password: raise ValueError("HTTPS endpoint required")
    body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    signature=hmac.new(key.encode(),body,hashlib.sha256).hexdigest()
    response=requests.post(endpoint,data=body,headers={"Content-Type":"application/json","X-NETRA-Checkpoint-Signature":signature},timeout=10,allow_redirects=False)
    if not 200<=response.status_code<300: raise RuntimeError("External anchor rejected checkpoint")
    receipt=response.json()
    if not isinstance(receipt,dict) or not receipt.get("receipt_id"): raise ValueError("External store must return a durable receipt_id")
    return {"checkpoint":payload,"receipt":receipt,"endpoint":endpoint}
def main():
    p=argparse.ArgumentParser();p.add_argument("--database",required=True);p.add_argument("--receipt",type=Path,required=True);a=p.parse_args()
    endpoint=os.environ.get("NETRA_ANCHOR_URL","");key=os.environ.get("NETRA_ANCHOR_SIGNING_KEY","")
    if not endpoint or not key: p.error("Configure external NETRA_ANCHOR_URL and NETRA_ANCHOR_SIGNING_KEY")
    if not Path(a.database).is_file(): p.error("Database must already exist; refusing to anchor an accidental empty ledger")
    result=publish(checkpoint(ForensicLedgerDB(a.database)),endpoint,key)
    a.receipt.parent.mkdir(parents=True,exist_ok=True);a.receipt.write_text(json.dumps(result,indent=2))
if __name__=="__main__":main()
