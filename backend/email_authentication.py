"""DKIM/ARC verification plus SPF/DMARC evaluation from trusted receiver results."""
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import os
import re
import time

from backend.dkim_verifier import DKIMVerifier


def _domain(value):
    address = parseaddr(value or "")[1]
    return address.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in address else ""


def _aligned(child, parent, strict=False):
    child, parent = (child or "").lower().rstrip("."), (parent or "").lower().rstrip(".")
    return bool(child and parent and (child == parent if strict else child == parent or child.endswith("." + parent) or parent.endswith("." + child)))


def _safe(value):
    if isinstance(value, bytes): return value.decode("utf-8", errors="replace")[:2000]
    if isinstance(value, dict): return {str(_safe(k)): _safe(v) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)): return [_safe(item) for item in value[:100]]
    return value if isinstance(value, (str, int, float, bool, type(None))) else str(value)[:2000]


class EmailAuthenticationVerifier:
    def __init__(self, dnsfunc=None, trusted_authserv_ids=None):
        self.dnsfunc = dnsfunc
        configured = trusted_authserv_ids if trusted_authserv_ids is not None else os.getenv("NETRA_TRUSTED_AUTHSERV_IDS", "")
        self.trusted = {item.strip().lower().rstrip(".") for item in configured.split(",") if item.strip()}

    def _arc(self, raw, source_type):
        result = {"status": "unavailable", "source": "local_arc_verification", "chain": [], "reason": "Original bytes or ARC chain unavailable."}
        if source_type != "eml": return result
        try:
            import dkim, dns.resolver
            deadline, queries = time.monotonic() + 6, 0
            def lookup(name, timeout=2):
                nonlocal queries
                queries += 1
                remaining = deadline - time.monotonic()
                if queries > 5 or remaining <= 0: raise TimeoutError("ARC DNS budget exhausted")
                if self.dnsfunc: return self.dnsfunc(name, timeout=min(2, remaining))
                answers = dns.resolver.resolve(name.decode("ascii"), "TXT", lifetime=min(2, remaining))
                values = [b"".join(item.strings) for item in answers]
                return values[0] if len(values) == 1 and len(values[0]) <= 8192 else None
            status, chain, reason = dkim.arc_verify(raw, dnsfunc=lookup, minkey=1024, timeout=3)
            result.update(status=status.decode() if isinstance(status, bytes) else str(status), chain=_safe(chain[:10]), reason=str(reason)[:500])
        except Exception as exc:
            result["reason"] = "ARC verification unavailable: " + type(exc).__name__
        return result

    @staticmethod
    def verify_spf_context(client_ip, mail_from, helo):
        """Evaluate SPF when a trusted SMTP gateway supplies the actual session tuple."""
        import ipaddress, spf
        ipaddress.ip_address(client_ip)
        if not mail_from or not helo:
            raise ValueError("SPF requires client IP, MAIL FROM and HELO")
        status, explanation = spf.check2(i=client_ip, s=mail_from, h=helo, timeout=2, querytime=5)
        return {"status": status.lower(), "domain": _domain(mail_from) or helo.lower().rstrip("."),
            "source": "trusted_smtp_context", "explanation": str(explanation)[:500]}

    def verify(self, raw, source_type="eml", *, trusted_receiver=None):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        dkim_result = DKIMVerifier(self.dnsfunc).verify(raw, source_type)
        arc_result = self._arc(raw, source_type)
        from_domain = _domain(msg.get("From", ""))
        # The caller supplies this only after fetching bytes from the provider.
        # Uploaded EML and reconstructed messages cannot select a trust boundary.
        permitted = ({"mx.google.com"} if trusted_receiver == "gmail" and source_type == "eml" else set())
        active_trust = permitted & (self.trusted or permitted)
        trusted = []
        for value in msg.get_all("Authentication-Results", []):
            authserv = str(value).split(";", 1)[0].strip().lower().rstrip(".")
            if authserv in active_trust:
                trusted.append(str(value))
                break  # Only the receiver's topmost result, not older claims.
        combined = " ".join(trusted)
        spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b[^;]*(?:smtp\.mailfrom|smtp\.helo)=([^\s;]+)", combined, re.I)
        spf_identity = spf_match.group(2) if spf_match else ""
        spf = {"status": spf_match.group(1).lower() if spf_match else "unavailable", "domain": _domain(spf_identity) or spf_identity.lower().rstrip("."), "source": "trusted_receiver" if spf_match else "unavailable"}
        spf["reason"] = ("The delivery receiver reported this SPF result at receipt." if spf_match else "SPF needs the real SMTP session or delivery results fetched directly from Gmail; visible text and uploaded headers cannot establish it.")
        # Only inspect the receiver's selected Authentication-Results SPF
        # segment, never arbitrary body text or older uploaded header claims.
        if trusted:
            import ipaddress
            segment = re.search(r"\bspf=[^;]+", combined, re.I)
            if segment:
                found = re.search(r"(?:client-ip\s*=\s*|designates\s+)([0-9a-fA-F:.]+)", segment.group(0), re.I)
                if found:
                    try:
                        address = ipaddress.ip_address(found.group(1))
                        if address.is_global:
                            spf["client_ip"] = str(address)
                            spf["client_ip_source"] = "gmail_authentication_results"
                    except ValueError:
                        pass
        receiver_dkim = re.search(r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b", combined, re.I)
        if receiver_dkim:
            dkim_result["receiver_status"] = receiver_dkim.group(1).lower()
            dkim_result["receiver_source"] = "trusted_receiver"
        passing_dkim = [item.get("domain", "") for item in dkim_result.get("signatures", []) if item.get("status") == "pass"]
        dmarc_match = re.search(r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b[^;]*header\.from=([^\s;]+)", combined, re.I)
        dmarc = {"status": "unavailable", "from_domain": from_domain, "source": "local_alignment"}
        if from_domain and (spf["status"] == "pass" or passing_dkim):
            dmarc["spf_aligned"] = spf["status"] == "pass" and _aligned(spf["domain"], from_domain)
            dmarc["dkim_aligned"] = any(_aligned(item, from_domain) for item in passing_dkim)
            dmarc["status"] = "pass" if dmarc["spf_aligned"] or dmarc["dkim_aligned"] else "fail"
        if dmarc_match:
            dmarc["receiver_status"] = dmarc_match.group(1).lower()
            dmarc["receiver_from_domain"] = dmarc_match.group(2).lower().rstrip(".")
        dmarc["reason"] = "Local alignment uses verified signatures and trusted sending-server results." if dmarc["status"] != "unavailable" else "No verified aligned signature or trusted sending-server result was available for local alignment."
        # Receipt-time verification can use signing keys no longer available
        # during a later recheck. Only provider-fetched bytes establish trust;
        # an uploaded Authentication-Results header never enters this branch.
        if dmarc_match and dmarc["receiver_from_domain"] == from_domain and dmarc["receiver_status"] in {"pass", "fail"}:
            dmarc["local_alignment_status"] = dmarc["status"]
            dmarc["status"] = dmarc["receiver_status"]
            dmarc["source"] = "trusted_receiver"
            dmarc["reason"] = "Gmail reported this DMARC result at delivery for the visible sender domain. The later local alignment recheck is recorded separately."
        return {"status": dkim_result.get("status", "unavailable"), "signatures": dkim_result.get("signatures", []),
            "dkim": dkim_result, "spf": spf, "dmarc": dmarc, "arc": arc_result,
            "trusted_authserv_ids": sorted(active_trust),
            "delivery_source": trusted_receiver if active_trust else "untrusted_upload",
            "limitations": ["SPF can only be evaluated at SMTP receipt; NETRA accepts it solely from explicitly trusted receiver Authentication-Results.", "DMARC uses locally verified DKIM alignment and trusted receiver SPF evidence. ARC validates custody, not message safety."]}
