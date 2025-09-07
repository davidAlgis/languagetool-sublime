# LTServer.py

import json

import sublime


def _is_ST2():
    return int(sublime.version()) < 3000


if _is_ST2():
    from urllib import urlencode, urlopen

    # HTTPError/URLError on ST2
    from urllib2 import HTTPError, Request, URLError
else:
    try:
        from urllib2 import HTTPError, Request, URLError, urlopen
        from urlparse import urlencode
    except ImportError:
        from urllib.error import HTTPError, URLError
        from urllib.parse import urlencode
        from urllib.request import Request, urlopen


def getResponse(server, text, language, disabledRules):
    payload = {
        # Keep as str; urlencode will encode properly.
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


# internal functions:


def _post(server, payload):
    """
    POST with headers and bounded retries to handle transient timeouts
    and occasional 429/5xx responses from the public LanguageTool endpoint.
    """
    data = urlencode(payload).encode("utf8")

    # Basic headers improve compatibility and sometimes reduce timeouts.
    req = Request(
        server,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "Sublime-LanguageTool",
        },
    )

    # Three attempts with increasing timeouts.
    timeouts = [10, 15, 25]
    last_err = None

    for t in timeouts:
        try:
            resp = urlopen(req, timeout=t)
            content = resp.read()
            return content
        except HTTPError as e:
            # Retry on rate limit or server errors; otherwise bubble up.
            if e.code == 429 or 500 <= e.code < 600:
                last_err = e
                continue
            raise
        except URLError as e:
            # Network hiccup or timeout (e.reason may be socket.timeout) -> retry.
            last_err = e
            continue
        except Exception as e:
            # Any other transient-ish error -> retry once more.
            last_err = e
            continue

    # Exhausted retries: let caller show a precise message.
    raise last_err
