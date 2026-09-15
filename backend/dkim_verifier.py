"""Verify original-message DKIM with bounded DNS. No message bodies leave here."""
from datetime import datetime, timezone
from email import policy
from email.parser import BytesHeaderParser
import time


class DKIMVerifier:
    def __init__(self, dnsfunc=None):
        self.dnsfunc = dnsfunc

    def verify(self, raw: bytes, source_type: str = "eml") -> dict:
        result = {
            "status": "unavailable", "source": "local_dkim_verification",
            "checked_at": datetime.now(timezone.utc).isoformat(), "signatures": [],
            "limitations": [
                "DKIM authenticates signed bytes and a signing domain, not sender intent.",
                "Current DNS keys may differ from keys at delivery time.",
                "SPF requires trusted SMTP connection context; full DMARC evaluation is separate."
            ],
        }
        if source_type != "eml":
            result["reason"] = "Original delivered message bytes are unavailable."
            return result
        headers = BytesHeaderParser(policy=policy.default).parsebytes(raw)
        signatures = headers.get_all("DKIM-Signature", [])
        if not signatures:
            result["status"] = "unsigned"
            return result
        try:
            import dkim
            import dns.resolver
        except ImportError:
            result["reason"] = "DKIM verification dependency is unavailable."
            return result

        deadline = time.monotonic() + 6
        queries = 0
        dns_failed = False

        def lookup(name, timeout=2):
            nonlocal queries, dns_failed
            queries += 1
            remaining = deadline - time.monotonic()
            if queries > 3 or remaining <= 0:
                dns_failed = True
                raise TimeoutError("DKIM DNS budget exhausted")
            try:
                if self.dnsfunc:
                    value = self.dnsfunc(name, timeout=min(2, remaining))
                    if not value:
                        dns_failed = True
                    return value
                answers = dns.resolver.resolve(name.decode("ascii"), "TXT", lifetime=min(2, remaining))
                values = [b"".join(answer.strings) for answer in answers]
                if len(values) != 1 or len(values[0]) > 8192:
                    dns_failed = True
                    return None
                return values[0]
            except Exception:
                dns_failed = True
                raise

        for index, signature in enumerate(signatures[:3]):
            tags = dict(
                part.strip().split("=", 1) for part in str(signature).split(";")
                if "=" in part
            )
            item = {"domain": tags.get("d", ""), "selector": tags.get("s", ""), "status": "unavailable"}
            dns_failed = False
            try:
                valid = dkim.DKIM(raw, minkey=1024, timeout=2).verify(idx=index, dnsfunc=lookup)
                item["status"] = "pass" if valid else "unavailable" if dns_failed else "fail"
            except dkim.ValidationError:
                item["status"] = "unavailable" if dns_failed else "fail"
            except Exception:
                item["status"] = "unavailable"
            result["signatures"].append(item)
        statuses = {item["status"] for item in result["signatures"]}
        result["status"] = "pass" if "pass" in statuses else "unavailable" if "unavailable" in statuses else "fail"
        if len(signatures) > 3:
            result["limitations"].append("Only the first three DKIM signatures were examined.")
        return result
