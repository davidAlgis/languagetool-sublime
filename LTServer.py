# LTServer.py

import json
import time  # NEW

import sublime


def _is_ST2():
    return int(sublime.version()) < 3000


if _is_ST2():
    from urllib import urlencode, urlopen

    from urllib2 import HTTPError, Request, URLError
    from urlparse import urlparse, urlunparse
else:
    try:
        from urllib2 import HTTPError, Request, URLError, urlopen
        from urlparse import urlencode, urlparse, urlunparse
    except ImportError:
        from urllib.error import HTTPError, URLError
        from urllib.parse import urlencode, urlparse, urlunparse
        from urllib.request import Request, urlopen


def _debug_print(msg):
    try:
        print("[LanguageTool][LTServer]", msg)
    except Exception:
        pass


def _escape_preview(s, limit):
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if len(s) > limit:
        return s[:limit] + "...(truncated)"
    return s


def _debug_text_stats(text, where, url):
    try:
        chars = len(text)
        bts = len(text.encode("utf-8"))
        non_ascii = sum(1 for c in text if ord(c) > 127)
        head = _escape_preview(text[:200], 200)
        tail = _escape_preview(text[-200:], 200)
        _debug_print(
            "{} | URL: {} | chars={} bytes={} non_ascii={} | head='{}' | tail='{}'".format(
                where, url, chars, bts, non_ascii, head, tail
            )
        )
    except Exception as e:
        _debug_print(
            "{} | error while computing text stats: {}".format(where, e)
        )


def getResponse(server, text, language, disabledRules):
    _debug_text_stats(text, "getResponse:payload", server)
    payload = {
        "language": language,
        "text": text,
        "disabledRules": ",".join(disabledRules),
    }
    content = _post(server, payload)
    if content:
        j = json.loads(content.decode("utf-8"))
        return j["matches"]
    else:
        return None


def _normalize_public_endpoint(server):
    try:
        p = urlparse(server)
        if p.netloc == "languagetool.org":
            p = p._replace(netloc="api.languagetool.org")
            return urlunparse(p)
        return server
    except Exception:
        return server


def _post(server, payload):
    """
    POST with headers, normalization, and a single timed retry on timeout/URLError.
    """
    server = _normalize_public_endpoint(server)
    data = urlencode(payload).encode("utf8")

    def _do_request(url, timeout_seconds):
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Accept": "application/json",
                "User-Agent": "Sublime-LanguageTool",
                "Connection": "close",  # reduce chance of hanging reads
            },
        )
        _debug_print(
            "POST -> {} (timeout={}s, payload_bytes={})".format(
                url, timeout_seconds, len(data)
            )
        )
        resp = urlopen(req, timeout=timeout_seconds)
        content = resp.read()
        _debug_print("POST <- {} OK (bytes_read={})".format(url, len(content)))
        return content

    try:
        return _do_request(server, 20)  # was 15s
    except HTTPError as e:
        body_snip = ""
        try:
            body_bytes = e.read() if hasattr(e, "read") else b""
            if body_bytes:
                body_snip = _escape_preview(
                    body_bytes.decode("utf-8", errors="replace"), 400
                )
        except Exception:
            body_snip = ""
        _debug_print(
            "HTTPError {} from {} | body='{}'".format(
                getattr(e, "code", "unknown"), server, body_snip
            )
        )
        if getattr(e, "code", None) in (426, 301, 302, 307, 308):
            fallback = _normalize_public_endpoint(
                "https://api.languagetool.org/v2/check"
            )
            _debug_print(
                "Retrying once on canonical host: {}".format(fallback)
            )
            return _do_request(fallback, 35)
        raise
    except URLError as e:
        _debug_print(
            "URLError from {} | reason='{}'".format(
                server, getattr(e, "reason", e)
            )
        )
        fallback = _normalize_public_endpoint(
            "https://api.languagetool.org/v2/check"
        )
        _debug_print("Retrying once on canonical host after short backoff...")
        time.sleep(0.5)
        return _do_request(fallback, 35)
