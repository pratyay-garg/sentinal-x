"""
A deterministic, in-process target. The Module 2 analogue of the 30-node graph
fixture: the control engine and every oracle are complete and testable against
this before Nuclei is wired or an authorised target is live (LAW / protocol:
build against a fixture first).

It is a plain Fetcher -- Request in, Response out -- so it plugs in wherever the
real httpx client will. Behaviours are chosen by mode:

  stable     every path returns one fixed page; nonsense paths 404. The honest,
             low-volatility server.
  dynamic    like stable but the page carries a per-request timestamp and CSRF
             token, so baselines are highly-but-not-perfectly similar -- this is
             what exercises the learned volatility threshold.
  catch_all  EVERY path, including nonsense, returns 200 with the homepage. The
             liar the sanity canary must catch.
  blocking   every path returns 403 (a WAF wall). The other untrustworthy mode.

Timing is deterministic: a fixed base latency plus a seeded per-call jitter, so
median/MAD are stable across runs.
"""
from __future__ import annotations

import random
import re as _re
from urllib.parse import urlsplit as _urlsplit

from .http import Request, Response

_HOME = (
    "<html><head><title>ShopMart</title></head><body>"
    "<nav>Home Products Cart Account Help About Contact</nav>"
    "<main><h1>Welcome to ShopMart</h1>"
    "<p>Browse thousands of products across every category. "
    "Fast shipping, easy returns, trusted by millions of customers "
    "worldwide every single day of the year.</p>"
    "<ul><li>Electronics</li><li>Books</li><li>Home</li><li>Toys</li></ul>"
    "</main><footer>(c) ShopMart Inc</footer></body></html>"
)

_NOT_FOUND = "<html><body><h1>404 Not Found</h1></body></html>"


class MockTarget:
    def __init__(self, mode: str = "stable", *, base_ms: float = 20.0,
                 jitter_ms: float = 4.0, seed: int = 1337):
        self.mode = mode
        self.base_ms = base_ms
        self.jitter_ms = jitter_ms
        self._rng = random.Random(seed)
        self._n = 0

    def _timing(self) -> float:
        # deterministic sequence: same call order -> same timings
        return round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)

    def __call__(self, request: Request) -> Response:
        self._n += 1
        t = self._timing()
        path = request.url

        if self.mode == "catch_all":
            return Response(200, _HOME, elapsed_ms=t)

        if self.mode == "blocking":
            return Response(403, "<html><body>Forbidden</body></html>",
                            elapsed_ms=t)

        is_known = path in ("/", "/products", "/search", "/account")

        if self.mode == "dynamic" and is_known:
            token = "".join(self._rng.choice("0123456789abcdef") for _ in range(12))
            body = _HOME.replace(
                "</footer>",
                f"<span id=ts>req-{self._n}</span>"
                f"<input type=hidden name=csrf value={token}></footer>")
            return Response(200, body, elapsed_ms=t)

        if is_known:
            return Response(200, _HOME, elapsed_ms=t)

        return Response(404, _NOT_FOUND, elapsed_ms=t)


# --------------------------------------------------------------- IDOR target

def _account_of(request: Request) -> str | None:
    for k, v in request.headers:
        if k.lower() == "authorization":
            v = v.strip()
            return v[7:] if v.lower().startswith("bearer ") else v
    return None


def _object_id(url: str) -> str:
    return (_urlsplit(url).path or url).rstrip("/").split("/")[-1]


class MockAuthzTarget:
    """A resource server for exercising the authorization oracle.

    Each object has an owner and a body. With `enforce=False` any authenticated
    account may read any object (the IDOR); with `enforce=True` only the owner
    may (secure). `session_valid=False` models a dead session -- every request
    401s, so the oracle's positive control fails and it must return inconclusive
    rather than inventing a finding.
    """
    def __init__(self, objects: dict[str, tuple[str, str]], *,
                 enforce: bool = False, session_valid: bool = True,
                 base_ms: float = 20.0, jitter_ms: float = 4.0, seed: int = 1337):
        self.objects = objects
        self.enforce = enforce
        self.session_valid = session_valid
        self.base_ms = base_ms
        self.jitter_ms = jitter_ms
        self._rng = __import__("random").Random(seed)

    def _t(self) -> float:
        return round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)

    def __call__(self, request: Request) -> Response:
        t = self._t()
        caller = _account_of(request)
        if not self.session_valid or caller is None:
            return Response(401, "<html><body>Unauthorized</body></html>", elapsed_ms=t)
        oid = _object_id(request.url)
        if oid not in self.objects:
            return Response(404, "<html><body>Not Found</body></html>", elapsed_ms=t)
        owner, data = self.objects[oid]
        if self.enforce and caller != owner:
            return Response(403, "<html><body>Forbidden</body></html>", elapsed_ms=t)
        return Response(200, data, elapsed_ms=t)

    # -- named scenarios --------------------------------------------------
    @classmethod
    def _std(cls, **kw):
        objs = {
            "10": ("acct-A", "<user id=10 name=Alice email=alice@corp.test "
                             "address='12 Oak St' phone=555-1000 role=member>"),
            "11": ("acct-B", "<user id=11 name=Bob email=bob@corp.test "
                             "address='9 Elm Ave' phone=555-2000 role=member>"),
        }
        return cls(objs, **kw)

    @classmethod
    def vulnerable(cls, **kw):
        return cls._std(enforce=False, **kw)

    @classmethod
    def secure(cls, **kw):
        return cls._std(enforce=True, **kw)

    @classmethod
    def dead_session(cls, **kw):
        return cls._std(enforce=False, session_valid=False, **kw)

    @classmethod
    def indistinguishable(cls, **kw):
        """Both objects carry identical content -- a cross-read cannot be told
        from a legitimate match, so the oracle must abstain."""
        same = "<user profile page: generic template with no distinguishing data>"
        return cls({"10": ("acct-A", same), "11": ("acct-B", same)},
                   enforce=False, **kw)


# --------------------------------------------------------------- SQLi target

_CATALOG = ["The Book of Sand", "Booking Systems Handbook", "Cookbook Deluxe",
            "Python Cookbook", "Java Programming", "Network Security Basics"]


def _param(request: Request, name: str) -> str | None:
    for k, v in request.params:
        if k == name:
            return v
    return None


def _term(value: str) -> str:
    m = _re.match(r"[A-Za-z0-9]+", value or "")
    return m.group(0) if m else (value or "")


def _rows(term: str) -> list[str]:
    t = term.lower()
    return [x for x in _CATALOG if t and t in x.lower()]


def _render(rows: list[str]) -> str:
    if not rows:
        return ("<html><body><nav>ShopMart search</nav>"
                "<p>No results found for your search query.</p>"
                "<footer>ShopMart</footer></body></html>")
    items = "".join(f"<li>{t}</li>" for t in rows)
    return (f"<html><body><nav>ShopMart search</nav><ul>{items}</ul>"
            f"<p>Showing {len(rows)} matching products.</p>"
            f"<footer>ShopMart</footer></body></html>")


class MockSqliTarget:
    """Boolean-based blind SQLi target for the differential oracle.

    modes:
      vulnerable    the boolean is evaluated only when a quote breaks the string
      secure        parameterised query: payloads are treated as literal terms
      error_on_quote any quote yields HTTP 500 (the classic scanner hallucination)
      confounded    the difference is driven by the *presence of 1=2* even with
                    no quote break (a WAF-like signature) -- the two-sided rule
                    alone would fire, and only the negative control catches it
    """
    def __init__(self, mode: str = "vulnerable", *, endpoint: str = "/search",
                 param: str = "q", base_ms: float = 20.0, jitter_ms: float = 4.0,
                 seed: int = 1337):
        self.mode, self.endpoint, self.param = mode, endpoint, param
        self.base_ms, self.jitter_ms = base_ms, jitter_ms
        self._rng = __import__("random").Random(seed)

    def _t(self):
        return round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)

    def __call__(self, request: Request) -> Response:
        t = self._t()
        path = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(request.url).path
        if path == "/":
            return Response(200, "<html><body><nav>ShopMart search</nav>"
                                 "<p>Home</p><footer>ShopMart</footer></body></html>",
                            elapsed_ms=t)
        if path != self.endpoint:
            return Response(404, "<html><body>Not Found</body></html>", elapsed_ms=t)

        value = _param(request, self.param) or ""
        false_boolean = "1=2" in value or "'a'='b'" in value

        if self.mode == "error_on_quote" and "'" in value:
            return Response(500, "<html><body><h1>500 Internal Server Error</h1>"
                                 "<p>SQL syntax error near unexpected token</p>"
                                 "</body></html>", elapsed_ms=t)
        if self.mode == "secure":
            rows = _rows(value)                       # whole value is literal
        elif self.mode == "confounded":
            rows = [] if false_boolean else _rows(_term(value))
        else:  # vulnerable
            if "'" in value:
                rows = [] if false_boolean else _rows(_term(value))
            else:
                rows = _rows(_term(value))            # no break-out: boolean ignored
        return Response(200, _render(rows), elapsed_ms=t)


# --------------------------------------------------------------- SSTI target

class MockSstiTarget:
    """Server-side template injection target for expression-mode differential.

    vulnerable  {{a*b}} in the input is evaluated and the product rendered
    secure      the input is auto-escaped and rendered literally
    """
    _EXPR = _re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")

    def __init__(self, mode: str = "vulnerable", *, endpoint: str = "/hello",
                 param: str = "name", base_ms: float = 20.0, jitter_ms: float = 4.0,
                 seed: int = 1337):
        self.mode, self.endpoint, self.param = mode, endpoint, param
        self.base_ms, self.jitter_ms = base_ms, jitter_ms
        self._rng = __import__("random").Random(seed)

    def _t(self):
        return round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)

    def __call__(self, request: Request) -> Response:
        t = self._t()
        path = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(request.url).path
        if path == "/":
            return Response(200, "<html><body><p>Home</p></body></html>", elapsed_ms=t)
        if path != self.endpoint:
            return Response(404, "<html><body>Not Found</body></html>", elapsed_ms=t)

        value = _param(request, self.param) or ""
        if self.mode == "vulnerable":
            rendered = self._EXPR.sub(lambda m: str(int(m.group(1)) * int(m.group(2))),
                                      value)
        else:  # secure: escape the braces so nothing evaluates
            rendered = value.replace("{", "&#123;").replace("}", "&#125;")
        body = (f"<html><body><h1>Hello, {rendered}</h1>"
                f"<p>Welcome to your profile page.</p></body></html>")
        return Response(200, body, elapsed_ms=t)


# --------------------------------------------------------------- timing target

_SLEEP = _re.compile(r"SLEEP\((\d+)\)", _re.IGNORECASE)


class MockTimingTarget:
    """Time-based blind SQLi target. Returns a simulated elapsed_ms (no real
    sleeping), so tests are instant AND deterministic.

    vulnerable  a conditional SLEEP executes only when a quote breaks out; the
                delay equals the requested seconds
    secure      parameterised: no sleep ever executes
    tarpit      a WAF adds a CONSTANT delay to anything containing SLEEP,
                regardless of the argument -- high z-score but no scaling
    """
    def __init__(self, mode="vulnerable", *, endpoint="/search", param="q",
                 base_ms=20.0, jitter_ms=3.0, seed=1337):
        self.mode, self.endpoint, self.param = mode, endpoint, param
        self.base_ms, self.jitter_ms = base_ms, jitter_ms
        self._rng = __import__("random").Random(seed)

    def __call__(self, request: Request) -> Response:
        jitter = self._rng.uniform(0, self.jitter_ms)
        path = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(request.url).path
        if path == "/":
            return Response(200, "<html><body>Home</body></html>",
                            elapsed_ms=round(self.base_ms + jitter, 3))
        if path != self.endpoint:
            return Response(404, "<html><body>Not Found</body></html>",
                            elapsed_ms=round(self.base_ms + jitter, 3))
        value = _param(request, self.param) or ""
        m = _SLEEP.search(value)
        secs = int(m.group(1)) if m else 0
        delay = 0.0
        if self.mode == "vulnerable" and "'" in value and secs:
            delay = secs * 1000.0
        elif self.mode == "tarpit" and m:
            delay = 3000.0                       # constant, ignores the argument
        elif self.mode == "const_on_break" and "'" in value and m:
            delay = 3000.0                       # constant, but only on break-out:
            # clean negative control, yet no scaling -> isolates the scaling check
        return Response(200, _render(_rows(_term(value))),
                        elapsed_ms=round(self.base_ms + jitter + delay, 3))


# --------------------------------------------------------------- XSS target

class MockXssTarget:
    """Reflected XSS target for the execution oracle.

    vulnerable       the input is reflected UNESCAPED (the script tag executes)
    secure           the input is HTML-escaped (inert)
    reflected_safe   the marker STRING is reflected but the script tags are
                     stripped -- reflection without execution, the case the
                     oracle must NOT fire on
    """
    def __init__(self, mode="vulnerable", *, endpoint="/echo", param="msg",
                 base_ms=20.0, jitter_ms=3.0, seed=1337):
        self.mode, self.endpoint, self.param = mode, endpoint, param
        self.base_ms, self.jitter_ms = base_ms, jitter_ms
        self._rng = __import__("random").Random(seed)

    def __call__(self, request: Request) -> Response:
        t = round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)
        path = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(request.url).path
        if path == "/":
            return Response(200, "<html><body>Home</body></html>", elapsed_ms=t)
        if path != self.endpoint:
            return Response(404, "<html><body>Not Found</body></html>", elapsed_ms=t)
        value = _param(request, self.param) or ""
        if self.mode == "secure":
            reflected = value.replace("<", "&lt;").replace(">", "&gt;")
        elif self.mode == "reflected_safe":
            reflected = value.replace("<script>", "").replace("</script>", "")
        else:
            reflected = value                    # unescaped
        return Response(200, f"<html><body><p>You said: {reflected}</p></body></html>",
                        elapsed_ms=t)


# --------------------------------------------------------------- OOB target

class CanaryListener:
    """Stand-in for a real interactsh/DNS listener. In production the target
    reaches this over the network; here the vulnerable mock records the hit
    synchronously so the test is deterministic."""
    def __init__(self, base="oob.canary.test", seed=1337):
        self.base = base
        self._rng = __import__("random").Random(seed)
        self._hits: set[str] = set()

    def issue(self) -> str:
        return "".join(self._rng.choice("0123456789abcdef") for _ in range(12))

    def url(self, token: str) -> str:
        return f"http://{token}.{self.base}/"

    def record(self, token: str) -> None:
        self._hits.add(token)

    def received(self, token: str) -> bool:
        return token in self._hits


class MockOOBTarget:
    """SSRF/RCE/XXE target keyed on a canary callback.

    vulnerable       fetches (records) any canary URL in the payload
    secure           ignores it
    egress_filtered  vulnerable but the callback is blocked -> no hit (which is
                     why 'no callback' can never be a false_positive)
    """
    def __init__(self, listener: CanaryListener, mode="vulnerable",
                 *, endpoint="/fetch", param="url", base_ms=20.0, jitter_ms=3.0,
                 seed=1337):
        self.listener, self.mode = listener, mode
        self.endpoint, self.param = endpoint, param
        self.base_ms, self.jitter_ms = base_ms, jitter_ms
        self._rng = __import__("random").Random(seed)
        self._token_re = _re.compile(r"([0-9a-f]{12})\." + _re.escape(listener.base))

    def __call__(self, request: Request) -> Response:
        t = round(self.base_ms + self._rng.uniform(0, self.jitter_ms), 3)
        value = _param(request, self.param) or ""
        m = self._token_re.search(value)
        if self.mode == "vulnerable" and m:
            self.listener.record(m.group(1))     # server "fetched" the canary
        return Response(200, "<html><body>request submitted</body></html>",
                        elapsed_ms=t)
