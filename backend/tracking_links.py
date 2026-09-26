"""Decode bounded redirect syntax without opening links or claiming live resolution."""
import re
from urllib.parse import parse_qs, unquote, urlsplit


def embedded_destination(url):
    if len(url) > 16384:
        return None
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or '').lower()
        if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            return None
        query = parse_qs(parsed.query, max_num_fields=100)
        target = None
        provider = None
        if host in {'google.com', 'www.google.com'} and parsed.path == '/url':
            values = query.get('q') or query.get('url') or []
            target = values[0] if len(values) == 1 else None
            provider = 'Google redirect'
        elif re.fullmatch(r'[a-z0-9-]+\.r\.[a-z]{2}(?:-[a-z]+)+-\d\.awstrack\.me', host):
            match = re.fullmatch(r'/(?:CL0|L0)/(.+)/[0-9]+/[^/]+/[^/]+/?', parsed.path)
            target = unquote(match.group(1)) if match else None
            provider = 'Amazon SES click tracking'
        elif parsed.path.rstrip('/') == '/email/click-tracking':
            values = query.get('redirect_uri', [])
            target = values[0] if len(values) == 1 else None
            provider = 'Embedded redirect parameter'
        if not target or len(target) > 16384:
            return None
        destination = urlsplit(target)
        if destination.scheme not in {'http', 'https'} or not destination.hostname:
            return None
        return {'target': target, 'provider': provider,
                'standard_provider': provider != 'Embedded redirect parameter'}
    except (ValueError, UnicodeError):
        return None


def opaque_tracking_provider(url):
    """Recognize a provider route, never certify its hidden destination.

    Exact host/path matching avoids accepting a lookalike or an open redirect
    elsewhere on a provider domain. No tracking URL is visited.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
            return None
        if parsed.hostname == "email.jiocx.com" and re.fullmatch(r"/interface/ctr/v2/[A-Za-z0-9_=-]{32,4096}", parsed.path) and not parsed.query:
            return "JioCX opaque click route"
    except ValueError:
        pass
    return None
