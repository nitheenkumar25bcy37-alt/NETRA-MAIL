"""HEAD-only redirect inspection with validated, pinned destination IPs."""
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit, urlunsplit


def expand_url(url):
    original = str(url or "")
    current, chain = original, []
    result = {"original_url": original, "final_url": original,
        "redirect_chain": chain, "expanded": False}
    deadline = time.monotonic() + 20
    try:
        for hop in range(6):
            if len(current) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in current):
                raise ValueError("invalid_url")
            parsed = urlsplit(current)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                raise ValueError("invalid_url")
            host = parsed.hostname.encode("idna").decode("ascii")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if port != (443 if parsed.scheme == "https" else 80):
                raise ValueError("port_not_allowed")
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not addresses or len(addresses) > 32:
                raise ValueError("dns_unavailable")
            for _, _, _, _, target in addresses:
                address = ipaddress.ip_address(target[0])
                if not address.is_global or address.is_multicast or address.is_unspecified or getattr(address, "ipv4_mapped", None) is not None:
                    raise ValueError("non_public_destination")
                # Reject IPv6 translation/tunneling ranges that can embed IPv4.
                if address.version == 6 and any(address in ipaddress.ip_network(net) for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")):
                    raise ValueError("translated_destination")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            family, kind, proto, _, target = addresses[0]
            # Connect to the checked sockaddr directly; no second DNS lookup.
            connection = http.client.HTTPConnection(host, port, timeout=min(3, remaining))
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(min(3, remaining))
                sock.connect(target)
                if parsed.scheme == "https":
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                connection.sock = sock
                path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                connection.request("HEAD", path, headers={"User-Agent": "NETRA-Static-Inspector/4.4", "Connection": "close"})
                response = connection.getresponse()
                if sum(len(k) + len(v) for k, v in response.getheaders()) > 32768:
                    raise ValueError("headers_too_large")
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location or hop == 5:
                        raise ValueError("redirect_limit")
                    next_url = urljoin(current, location)
                    if next_url in chain or next_url == current:
                        raise ValueError("redirect_loop")
                    chain.append(current)
                    current = next_url
                    continue
                if not 200 <= response.status < 300:
                    raise ValueError("remote_rejected")
                result.update(final_url=current, expanded=current != original, status_code=response.status)
                return result
            finally:
                connection.close()
                sock.close()
        raise ValueError("redirect_limit")
    except Exception:
        result["error"] = "url_inspection_unavailable_or_blocked"
        return result
