"""Offline PSL boundaries for link-label comparison, including private tenants."""
from functools import lru_cache
from threading import RLock
import ipaddress
import idna
import tldextract

_lock = RLock()
_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# These Indian financial-sector namespaces allocate one organization name below
# the listed zone (for example, ``sbi.bank.in``).  The public suffix snapshot
# bundled with tldextract currently treats only ``in`` as the suffix, which
# incorrectly collapses every bank to the shared identity ``bank.in``.
# RBI/IDRBT operate these as controlled registration boundaries.
CONTROLLED_ORGANIZATION_ZONES = {"bank.in", "fin.in"}

def canonical_host(host):
    host = str(host or "").lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        try:
            return idna.encode(host, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            return ""

@lru_cache(maxsize=4096)
def registered_identity(host):
    host = canonical_host(host)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    for zone in CONTROLLED_ORGANIZATION_ZONES:
        zone_labels = zone.split(".")
        if host.endswith("." + zone) and len(labels) > len(zone_labels):
            return ".".join(labels[-(len(zone_labels) + 1):])
    with _lock:
        result = _extractor(host)
    return result.top_domain_under_public_suffix if result.suffix else ""

def compare_link_hosts(visible, actual):
    visible, actual = canonical_host(visible), canonical_host(actual)
    visible_domain, actual_domain = registered_identity(visible), registered_identity(actual)
    same_domain = bool(visible_domain and actual_domain and visible_domain == actual_domain)
    return {"visible_host": visible, "actual_host": actual, "visible_registered_domain": visible_domain,
            "actual_registered_domain": actual_domain, "same_registered_domain": same_domain,
            "host_differs": bool(visible and visible != actual),
            "deceptive_domain_mismatch": bool(visible and visible != actual and not same_domain)}
