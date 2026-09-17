"""Explicitly configured local SHA-256 blocklist; no invented reputation."""
import json
import os
import re
from pathlib import Path
def apply_reputation(result):
    path=os.getenv("NETRA_ATTACHMENT_BLOCKLIST", "")
    reputation={"available":False,"matched":False,"source":"local_hash_blocklist"}
    if path:
        try:
            source=Path(path)
            if source.stat().st_size>1024*1024: raise ValueError("Blocklist exceeds limit")
            hashes=json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(hashes,list) or any(not isinstance(h,str) or not re.fullmatch(r"[0-9a-fA-F]{64}",h) for h in hashes): raise ValueError("Invalid blocklist")
            reputation.update(available=True,matched=str(result.get("sha256", "")).lower() in {h.lower() for h in hashes})
        except (OSError,ValueError) as exc: reputation["error"]=type(exc).__name__
    result["reputation"]=reputation
    if reputation["matched"]:
        result.update(score=100,risk_level="CRITICAL",suspicious=True)
        result["reasons"]=list(result.get("reasons",[]))+["Attachment SHA-256 matches configured malware blocklist"]
    return result
