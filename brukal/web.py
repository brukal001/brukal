r"""
web.py — the GOVERNED web-exploitation surface.

Web testing (intercept a request, tamper with a header/body, replay it, fill a
field with a payload, follow a redirect to a vhost) needs a different primitive
than "run a shell tool" — but it must obey the SAME governance. So this module
mirrors executor.py exactly:

    WebAction  ->  check_web()  ->  [ALLOW] -> WebCage.run()  -> audit log
                                \->  [DENY]                    -> audit, do not run

Every web action is scope-checked in DETERMINISTIC code before it touches the
network: the action's host must be an authorised IP *or* an authorised hostname
(e.g. a HTB vhost like `nexus.htb`, set at scope time — never resolved from DNS at
runtime, so a hostile DNS answer cannot widen scope). The scheme must be http/https
(a `javascript:` / `file:` / `data:` URL is refused). Anything unparseable is
DENIED (fail-closed). No language model sits in this decision (invariant 1); the
host is re-read from the URL, not trusted from a declared field (invariant 3).

Agents are handed a `GovernedBrowser`, never a raw `WebCage` — the same structural
guarantee that makes gate-bypass impossible for shell actions (invariant 4). Two
backends: `FakeWebCage` (deterministic, for tests) and `HttpWebCage` (real crafted
HTTP requests — the interception/replay/tamper primitive). A full Chrome/CDP
backend for live browser interaction + request interception plugs in here next.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import redact
from .audit import AuditLog
from .gate import Decision
from .scope import Scope

# Actions that carry their own URL (host read from it) vs. actions that operate on
# the currently-loaded page (host read from the browser's current URL).
_URL_ACTIONS = frozenset({"navigate", "get", "request"})
_PAGE_ACTIONS = frozenset({"click", "fill", "screenshot", "eval"})
_INTERCEPT_ACTIONS = frozenset({"intercept"})
_ALL_ACTIONS = _URL_ACTIONS | _PAGE_ACTIONS | _INTERCEPT_ACTIONS
_OK_SCHEMES = frozenset({"http", "https"})


@dataclass
class WebAction:
    """One governed web action the model proposes (text in, structured here)."""
    kind: str                                   # navigate|get|request|click|fill|screenshot|eval|intercept
    url: str = ""                               # for navigate/get/request (and intercept match)
    method: str = "GET"                         # for request
    headers: dict = field(default_factory=dict)  # for request / intercept-modify
    body: str = ""                              # for request / intercept-modify
    selector: str = ""                          # for click/fill
    value: str = ""                             # for fill (an attack payload, NOT sanitised)
    expression: str = ""                        # for eval (JS in page context)

    def describe(self) -> str:
        if self.kind in _URL_ACTIONS:
            m = f"{self.method} " if self.kind == "request" else ""
            return f"{self.kind}: {m}{self.url}"
        if self.kind == "fill":
            return f"fill {self.selector} = {self.value[:40]}"
        if self.kind in ("click", "eval"):
            return f"{self.kind} {self.selector or self.expression[:40]}"
        return f"{self.kind} {self.url or self.selector}".strip()


@dataclass
class WebResult:
    status: int | None = None                   # HTTP status (get/request), else None
    url: str = ""
    body: str = ""
    headers: dict = field(default_factory=dict)
    note: str = ""


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _scheme_of(url: str) -> str:
    try:
        return (urlsplit(url).scheme or "").lower()
    except ValueError:
        return ""


def check_web(action: WebAction, scope: Scope, current_url: str = "",
              agent: str = "web") -> Decision:
    """Deterministically rule on one web action. Scope is enforced on the HOST the
    action touches; the scheme must be http/https; unparseable => DENY (fail-closed).
    Returns the same Decision object the shell gate emits, so web and shell actions
    share one audit schema."""
    from .identity import (CAPABILITY_DENIED_REASON, required_capability_for_web,
                           resolve_identity)

    kind = (action.kind or "").lower()
    desc = action.describe()
    # `agent` may be an AgentIdentity or the historical bare role string. Capabilities
    # are re-derived from the role either way, so nothing handed in widens itself.
    ident = resolve_identity(agent)
    agent = ident.role or "unknown"

    def deny(reason, layer="hard:web"):
        return Decision(verdict="DENY", action=desc, target="", agent=agent,
                        reason=reason, layer=layer,
                        agent_id=ident.agent_id, engagement_id=ident.engagement_id)

    if kind not in _ALL_ACTIONS:
        return deny(f"unknown web action '{action.kind}'")

    # Which URL does this action touch? URL-actions carry it; page-actions inherit
    # the currently-loaded page (which only a prior gated navigate could have set).
    if kind in _URL_ACTIONS or kind in _INTERCEPT_ACTIONS:
        url = action.url
        if not url:
            return deny(f"{kind} requires a url")
    else:
        url = current_url
        if not url:
            return deny(f"{kind} needs an in-scope page loaded first (navigate)")

    scheme = _scheme_of(url)
    if scheme and scheme not in _OK_SCHEMES:
        return deny(f"scheme '{scheme}' not allowed (only http/https)", "hard:web-scheme")
    host = _host_of(url)
    if not host:
        return deny("could not parse a host from the url")
    if not scope.contains_host(host):
        return deny(f"host '{host}' is out of scope", "hard:web-scope")

    # CAPABILITY — last, so every earlier denial keeps its own reason and layer and
    # this can only ever ADD denials. Same decision procedure as the shell path
    # (identity.required_capability_for_web), no LLM, fail-closed on an unrecognised
    # action kind.
    needed = required_capability_for_web(action)
    if not ident.can(needed):
        d = deny(f"role '{agent}' lacks capability {needed} required by this web "
                 f"action", "hard:web-capability")
        d.reason_code = CAPABILITY_DENIED_REASON
        return d

    return Decision(verdict="ALLOW", action=desc, target=host, agent=agent,
                    reason=f"in-scope web {kind} on {host}", layer="web:allow",
                    agent_id=ident.agent_id, engagement_id=ident.engagement_id)


# --------------------------------------------------------------------------- #
# cages (backends)
# --------------------------------------------------------------------------- #

class FakeWebCage:
    """Deterministic web backend for tests: records actions, returns canned
    results, and remembers interception rules — no real network or browser."""

    def __init__(self, responses: dict | None = None):
        self.actions: list[WebAction] = []
        self.intercepts: list[WebAction] = []
        self._responses = responses or {}      # url-substring -> body

    def run(self, action: WebAction) -> WebResult:
        self.actions.append(action)
        if action.kind == "intercept":
            self.intercepts.append(action)
            return WebResult(url=action.url, note=f"interception armed for {action.url}")
        if action.kind in ("get", "request"):
            body = next((b for frag, b in self._responses.items() if frag in action.url),
                        f"[fake {action.method} {action.url}]")
            return WebResult(status=200, url=action.url, body=body,
                             headers={"x-fake": "1"})
        if action.kind == "navigate":
            return WebResult(status=200, url=action.url, body="[fake page]")
        return WebResult(url=action.url, note=f"[fake {action.kind}] {action.describe()}")


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    """Do NOT auto-follow redirects. urllib normally chases a 3xx transparently —
    which means an in-scope host that 302s to an out-of-scope host would be reached
    with NO second scope check (a real escape). Returning None from redirect_request
    makes urllib raise the 3xx as an HTTPError instead, so the cage can surface the
    Location and require the caller to resubmit the next hop as a fresh, gated
    WebAction through check_web()."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# One opener, shared: build_opener installs default handlers plus ours, so the
# no-follow behaviour applies to every HttpWebCage request.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoAutoRedirect)


class HttpWebCage:
    """Real crafted-HTTP-request backend (the interception/replay/tamper primitive):
    sends an arbitrary method/headers/body to an in-scope URL and returns the real
    response. Redirects are NOT auto-followed — a 3xx is surfaced with its Location so
    the next hop is re-checked by the gate (no cross-scope redirect escape). Browser-
    only actions (navigate/click/fill/intercept) raise until the Chrome/CDP backend
    lands — use FakeWebCage or the Chrome backend for those."""

    # A JavaScript bundle is a MAP, not a page, and it is read for the endpoints named
    # inside it. Twenty kilobytes is ample for a page and useless for a bundle: OWASP
    # Juice Shop's main.js is about a megabyte, its API routes are spread throughout,
    # and truncating at 20 000 characters yielded ZERO of them. A direct read of the
    # same file finds forty. That single cap is why single-page applications — most of
    # the modern web — presented Brukal with an empty attack surface.
    _SCRIPT_MAX_BODY = 2_000_000
    _SCRIPT_RE = re.compile(r"\.(?:js|mjs|json|map)(?:$|[?#])", re.I)

    def __init__(self, timeout: int = 20, max_body: int = 20000):
        self.timeout = timeout
        self.max_body = max_body
        # TLS policy is NOT the cage's to choose. It arrives from the immutable scope
        # through GovernedBrowser (`set_tls_verify`), and the default is to verify.
        self.tls_verify = True

    def set_tls_verify(self, verify: bool) -> None:
        """Install the engagement's disclosed TLS policy. Only GovernedBrowser calls
        this, and only with what the scope says."""
        self.tls_verify = bool(verify)

    def _opener(self):
        if self.tls_verify:
            return _NO_REDIRECT_OPENER
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.build_opener(_NoAutoRedirect,
                                           urllib.request.HTTPSHandler(context=ctx))

    def _cap_for(self, url: str, content_type: str = "") -> int:
        """How much of this response is worth reading. Scripts get the larger allowance;
        everything else keeps the small one, so an accidental download of a huge asset
        still cannot exhaust memory."""
        ctype = (content_type or "").lower()
        if self._SCRIPT_RE.search(url or "") or "javascript" in ctype or "json" in ctype:
            return self._SCRIPT_MAX_BODY
        return self.max_body

    def run(self, action: WebAction) -> WebResult:
        if action.kind not in ("get", "request"):
            raise NotImplementedError(
                f"'{action.kind}' needs the Chrome backend; HttpWebCage does get/request")
        method = "GET" if action.kind == "get" else (action.method or "GET").upper()
        data = action.body.encode() if action.body else None
        req = urllib.request.Request(action.url, data=data, method=method,
                                     headers=action.headers or {})
        # An unverified request carries a note saying so on EVERY response, because a
        # body fetched without validating who served it is a different kind of evidence
        # from one fetched with it, and the difference must survive into the record.
        unverified_note = ("" if self.tls_verify else
                           "TLS verification DISABLED by scope (tls_verify=false); "
                           "certificate NOT validated")
        try:
            with self._opener().open(req, timeout=self.timeout) as resp:
                _ct = ""
                try:
                    _ct = resp.headers.get("content-type", "") or ""
                except Exception:
                    _ct = ""
                body = resp.read(self._cap_for(action.url, _ct)).decode(errors="replace")
                return WebResult(status=resp.status, url=resp.geturl(), body=body,
                                 headers=dict(resp.headers),
                                 note=unverified_note if action.url.lower().startswith("https")
                                 else "")
        except urllib.error.HTTPError as e:
            if e.code in _REDIRECT_CODES:
                loc = (e.headers.get("Location") if e.headers else "") or ""
                # DO NOT follow. Surface the Location; the caller must resubmit it as a
                # new gated action so the redirect target is scope-checked.
                return WebResult(status=e.code, url=action.url,
                                 headers=dict(e.headers or {}),
                                 note=f"redirect NOT followed -> {loc} "
                                      f"(resubmit as a new gated action to re-check scope)")
            body = e.read(self.max_body).decode(errors="replace")
            return WebResult(status=e.code, url=action.url, body=body,
                             headers=dict(e.headers or {}), note="http error")
        except urllib.error.URLError as e:
            return WebResult(url=action.url, note=f"unreachable: {e.reason}")


class DockerHttpWebCage:
    """Real crafted-request backend that runs INSIDE the Kali cage, so it reaches
    targets only the cage can route to (e.g. a HTB box over the cage's VPN). The
    request is executed by a fixed python one-liner passed a safe argument vector
    (never a shell string), so there is no shell-injection surface even though the
    URL/headers/body are attacker-controlled payloads."""

    # NB: a no-follow redirect handler (class NR) is installed so a 3xx to an
    # out-of-scope host is surfaced, never chased — same guarantee as HttpWebCage.
    # How much of a response body to bring back. 20 KB silently truncated every modern
    # web app: a live Juice Shop bundle is 783 KB, so route mining saw the first 2.5% of
    # main.js and the app's real endpoints (including its LLM chat API) simply did not
    # exist as far as Brukal was concerned. The bundle IS the attack surface of a SPA,
    # so it has to be read whole; the ceiling only guards against pulling a huge binary
    # into memory.
    _MAX_BODY = 4_000_000
    _SCRIPT = (
        "import sys,json,urllib.request,urllib.error,ssl\n"
        f"MAXB={_MAX_BODY}\n"
        # argv[4] carries the engagement's TLS policy. "0" builds an unverified context;
        # anything else verifies. The cage never decides this for itself.
        "VERIFY=sys.argv[4]!='0'\n"
        "class NR(urllib.request.HTTPRedirectHandler):\n"
        " def redirect_request(self,*a):return None\n"
        "op=urllib.request.build_opener(NR)\n"
        "u,m,b=sys.argv[1],sys.argv[2],sys.argv[3]\n"
        "h=dict(x.split(': ',1) for x in sys.argv[5:] if ': ' in x)\n"
        "if not VERIFY:\n"
        " c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE\n"
        " op=urllib.request.build_opener(NR,urllib.request.HTTPSHandler(context=c))\n"
        "UN='' if VERIFY or not u.lower().startswith('https') else 'TLS verification DISABLED by scope (tls_verify=false); certificate NOT validated'\n"
        "rq=urllib.request.Request(u,data=b.encode() if b else None,method=m,headers=h)\n"
        "try:\n"
        " r=op.open(rq,timeout=20)\n"
        " print(json.dumps({'status':r.status,'url':r.geturl(),'headers':dict(r.headers),'note':UN,'body':r.read(MAXB).decode('utf-8','replace')}))\n"
        "except urllib.error.HTTPError as e:\n"
        " if e.code in (301,302,303,307,308):\n"
        "  loc=(e.headers.get('Location') if e.headers else '') or ''\n"
        "  print(json.dumps({'status':e.code,'url':u,'headers':dict(e.headers or {}),'note':'redirect NOT followed -> '+loc+' (resubmit as a new gated action to re-check scope)'}))\n"
        " else:\n"
        "  print(json.dumps({'status':e.code,'url':u,'headers':dict(e.headers or {}),'body':e.read(MAXB).decode('utf-8','replace'),'note':'http error'}))\n"
        "except Exception as e:\n"
        " print(json.dumps({'status':None,'url':u,'note':str(e)}))\n"
    )

    def __init__(self, container: str = "brukal-kali", user: str = "brukalop",
                 timeout: int = 30):
        self.container = container
        self.user = user
        self.timeout = timeout
        self.tls_verify = True

    def set_tls_verify(self, verify: bool) -> None:
        self.tls_verify = bool(verify)

    def run(self, action: WebAction) -> WebResult:
        import subprocess
        if action.kind not in ("get", "request"):
            raise NotImplementedError(
                f"'{action.kind}' needs the Chrome backend; this cage does get/request")
        method = "GET" if action.kind == "get" else (action.method or "GET").upper()
        argv = ["docker", "exec", "-u", self.user, self.container,
                "python3", "-c", self._SCRIPT, action.url, method, action.body or "",
                "1" if self.tls_verify else "0"]
        argv += [f"{k}: {v}" for k, v in (action.headers or {}).items()]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception as e:
            return WebResult(url=action.url, note=f"cage web error: {e}")
        return WebResult(status=payload.get("status"), url=payload.get("url", action.url),
                         body=payload.get("body", ""), headers=payload.get("headers", {}),
                         note=payload.get("note", ""))


# --------------------------------------------------------------------------- #
# the one door for web
# --------------------------------------------------------------------------- #

def parse_web_action(text: str) -> "WebAction | None":
    """Parse a strategist `WEB:` line into a WebAction. Grammar (verb first):
      navigate|get|render <url>      · request <METHOD> <url> [body]
      fill <selector> <payload...>   · click <selector>   · eval <js...>
      screenshot <url>               · intercept <url-pattern>
    A bare http(s) URL is treated as `get`. Returns None if unparseable."""
    toks = (text or "").strip().split()
    if not toks:
        return None
    verb = toks[0].lower()
    rest = toks[1:]
    if verb in ("navigate", "get", "render", "screenshot", "intercept"):
        return WebAction(kind={"render": "get"}.get(verb, verb), url=rest[0] if rest else "")
    if verb == "eval":
        return WebAction(kind="eval", expression=" ".join(rest))
    if verb in ("click", "fill"):
        return WebAction(kind=verb, selector=rest[0] if rest else "",
                         value=" ".join(rest[1:]))
    if verb == "request":
        method = rest[0].upper() if rest else "GET"
        url = rest[1] if len(rest) > 1 else ""
        return WebAction(kind="request", url=url, method=method, body=" ".join(rest[2:]))
    if verb.startswith("http://") or verb.startswith("https://"):
        return WebAction(kind="get", url=verb)
    return None


class CompositeWebCage:
    """One cage that routes each action to the backend that can do it: page
    rendering (navigate/get/screenshot) to the Chrome cage, crafted requests to
    the HTTP cage. Live interactive actions (click/fill/eval/intercept) need the
    CDP backend — until that is wired live they return an explanatory note rather
    than crashing the hunt."""

    def __init__(self, render_cage, request_cage):
        self._render = render_cage
        self._request = request_cage

    def set_tls_verify(self, verify: bool) -> None:
        """Delegate the engagement's TLS policy to both halves. A composite that
        forwarded it to one of them would leave a plane verifying while the other did
        not, and nothing in the record would say which answered."""
        for cage in (self._render, self._request):
            setter = getattr(cage, "set_tls_verify", None)
            if callable(setter):
                setter(verify)

    def run(self, action: WebAction) -> WebResult:
        k = (action.kind or "").lower()
        # `get` goes to the HTTP cage, not Chrome: it is jar-aware (carries the
        # GovernedBrowser session cookie jar, so authenticated pages are reachable
        # after login) and returns the RAW HTML/JS — which is what the crawl needs
        # to mine forms, params and API routes from the JS bundle. Chrome render
        # (`navigate`) stays for when JS execution / a screenshot is actually needed.
        if k in ("navigate", "screenshot"):
            return self._render.run(action)
        if k in ("get", "request"):
            return self._request.run(action)
        return WebResult(url=action.url,
                         note=f"'{k}' needs the live CDP browser (interactive) — "
                              f"not wired live yet; use navigate/get/request/screenshot")


def map_cage_host(host: str, ip: str, container: str = "brukal-kali") -> bool:
    """Best-effort: add `<ip> <host>` to the cage's /etc/hosts so a vhost resolves for
    cage-run web requests and the headless browser. `ip` is validated as an IP and
    `host` as a plain hostname before use (no shell-injection surface). Wildcards are
    skipped (they can't be /etc/hosts entries). Returns True on a mapping attempt."""
    import ipaddress
    import subprocess
    host = (host or "").strip().lower()
    ip = (ip or "").strip()
    if not host or host.startswith("*") or not re.fullmatch(r"[a-z0-9.\-]+", host):
        return False
    try:
        ipaddress.ip_address(ip)                 # reject anything that isn't a clean IP
    except ValueError:
        return False
    try:
        subprocess.run(
            ["docker", "exec", "-u", "root", container, "sh", "-c",
             f"grep -qw {host} /etc/hosts || echo '{ip} {host}' >> /etc/hosts"],
            capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def ensure_cage_vhosts(scope: Scope, container: str = "brukal-kali",
                       target_ip: str = "") -> list[str]:
    """Map the scope's authorised hostnames to an IP inside the cage's /etc/hosts, so a
    vhost like `nexus.htb` actually resolves for cage-run web requests and the browser.
    The IP is `target_ip` (the host being worked — authorised vhosts belong to it), or,
    when no target is given, the single-host /32 the scope authorises. Wildcards are
    skipped. Returns the hostnames it mapped (best-effort; failures ignored)."""
    hosts = sorted(h for h in scope.authorized_hosts if not h.startswith("*"))
    ip = (target_ip or "").strip()
    if not ip:                                   # fall back to a single-host /32 scope
        nets = scope.authorized_networks
        if len(nets) == 1 and nets[0].num_addresses == 1:
            ip = str(nets[0].network_address)
    if not hosts or not ip:
        return []
    return [h for h in hosts if map_cage_host(h, ip, container)]


class GovernedBrowser:
    """The single path from a proposed web action to the network. Gate first, log
    always, run only if ALLOWed — exactly like Executor, but for the web. Agents
    receive THIS, never the raw cage."""

    def __init__(self, scope: Scope, cage, audit: AuditLog):
        self._scope = scope
        self._cage = cage
        self._audit = audit
        self._hits = deque()                   # timestamps, for the rate limit
        self.current_url = ""                  # set only by a gated, successful navigate
        self._cookies: dict = {}               # session cookie jar (name -> value)
        self.auth_header: str = ""             # e.g. "Bearer <jwt>" / "Basic <b64>" (token/basic auth)
        # Rolling health of whatever we are pointed at. A rate limit bounds how fast
        # requests leave; nothing was asking whether the target still answers them.
        from .health import TargetHealth
        self.health = TargetHealth()
        # Certificate observations, kept for the report: "this host's certificate cannot
        # be validated" is information ABOUT THE TARGET, and an exception swallowed into
        # a counter threw it away. One per host.
        self.tls_observations: list = []
        self._tls_seen: set = set()
        self._tls_announced = False
        # THE ONLY PLACE TLS POLICY IS SET. It comes from the immutable scope; a cage
        # never chooses, and never keeps a default that could diverge from it.
        setter = getattr(cage, "set_tls_verify", None)
        if callable(setter):
            setter(bool(getattr(scope, "tls_verify", True)))

    def _apply_cookies(self, action: "WebAction") -> None:
        """Attach the session to an outgoing request so authenticated pages are reachable
        after a login — cookies for cookie sessions, an Authorization header for
        token/bearer/basic auth. Real-world apps use one or the other (or both); this
        carries whichever the login produced. Never overrides a value the caller set."""
        original = action.headers or {}
        # A credential header carrying a REDACTION PLACEHOLDER is not a credential — it is
        # a record artifact that has looped back into an action (the model was shown a
        # masked token and copied it). Left in place it would count as "the caller set
        # one" below and SUPPRESS the real session, so the request would go out
        # unauthenticated with no denial and no error: an authenticated run silently
        # becomes a logged-out one, and the ledger cannot tell the difference. Dropped
        # here so the real credential is attached in its place. Only the placeholder
        # shape is treated this way; a genuine caller-set header still wins, because that
        # is how a cross-account prover issues a request as the OTHER principal.
        hdrs = {k: v for k, v in original.items()
                if not (k.lower() in ("authorization", "cookie") and redact.has_placeholder(v))}
        dropped = len(hdrs) != len(original)
        have = {k.lower() for k in hdrs}
        add = {}
        if self._cookies and "cookie" not in have:
            add["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        if self.auth_header and "authorization" not in have:
            add["Authorization"] = self.auth_header
        # `dropped` covers the case where a placeholder was removed and there was no real
        # credential to put back: the masked value must still not be SENT.
        if add or dropped:
            action.headers = {**hdrs, **add}

    def _absorb_cookies(self, result) -> None:
        """Fold any Set-Cookie from the response into the jar, so the session persists
        across web actions (the basis of authenticated scanning). Robust to a headers
        dict that collapsed multiple Set-Cookie values into one comma-joined string."""
        if result is None:
            return
        for k, v in (result.headers or {}).items():
            if k.lower() != "set-cookie":
                continue
            for piece in re.split(r",(?=[^;=]+=)", str(v)):
                first = piece.strip().split(";", 1)[0]
                if "=" in first:
                    name, val = first.split("=", 1)
                    name = name.strip()
                    if name and val.strip() not in ("deleted", ""):
                        self._cookies[name] = val.strip()

    def _rate_ok(self) -> bool:
        now = time.time()
        while self._hits and now - self._hits[0] > 60:
            self._hits.popleft()
        if len(self._hits) >= self._scope.rate_limit_per_min:
            return False
        self._hits.append(now)
        return True

    def _announce_tls(self, action: "WebAction") -> None:
        """Say once, in the ledger, which TLS policy this engagement runs under and where
        it came from. Announced on first https use rather than at construction so the
        entry sits next to the requests it governs."""
        if self._tls_announced or not (action.url or "").lower().startswith("https"):
            return
        self._tls_announced = True
        self._audit.append("tls_policy", {
            "verify": bool(getattr(self._scope, "tls_verify", True)),
            "source": "scope",
            "engagement": getattr(self._scope, "engagement", ""),
            "note": ("certificates are validated" if getattr(self._scope, "tls_verify", True)
                     else "certificates are NOT validated — disclosed parameter of this "
                          "engagement, recorded with its authorisation")})

    def _observe_tls(self, action: "WebAction", result) -> None:
        """A certificate that does not validate is a finding-class observation about the
        TARGET's configuration, and it is kept whether or not the engagement proceeds.

        Bounded on purpose: it says the certificate cannot be validated. It does not say
        anyone got in and it does not say anything went down — this is a transport
        configuration observation, not an authorization or availability result, and a
        reader must not be able to mistake it for either."""
        note = (getattr(result, "note", "") or "")
        low = note.lower()
        failed = "certificate verify failed" in low or "certificate_verify_failed" in low
        proceeded = "certificate not validated" in low
        if not (failed or proceeded):
            return
        host = _host_of(action.url) or (self._scope.engagement or "")
        if host in self._tls_seen:
            return
        self._tls_seen.add(host)
        obs = {"title": "TLS certificate could not be validated",
               "severity": "low", "category": "tls", "target": host,
               "evidence": note[:300],
               "bounded": ("transport configuration only: the certificate does not chain "
                           "to a trusted root (self-signed or untrusted issuer). This is "
                           "not evidence of access and not evidence of downtime."),
               "verification": "off" if proceeded else "on"}
        self.tls_observations.append(obs)
        self._audit.append("tls_observation", obs)

    def run(self, action: WebAction, agent: str = "web"):
        """Judge, log, and (only if permitted) perform one web action.
        Returns (Decision, WebResult | None)."""
        decision = check_web(action, self._scope, self.current_url, agent)
        self._audit.append("web_decision", decision)
        if decision.verdict != "ALLOW":
            return decision, None
        if not self._rate_ok():
            blocked = Decision(verdict="DENY", action=decision.action, target=decision.target,
                               agent=agent, reason="web rate limit exceeded",
                               layer="hard:web-rate")
            self._audit.append("web_decision", blocked)
            return blocked, None

        self._apply_cookies(action)            # carry the session into this request
        self._announce_tls(action)
        result = self._cage.run(action)
        self._observe_tls(action, result)
        # THE WEB PLANE'S SINGLE DOOR, and the registration point every plane shares.
        # `web_result` below records {status, url, note, bytes} and no body, so this
        # plane's responses never reached the LEDGER — and the audit log was therefore
        # clean while `_absorb_web` folded the same responses into notes and findings that
        # DO reach the vault. Bundle CM6 caught the target echoing a password hash under
        # the key `password` into `vault/findings.jsonl` unmasked for exactly that reason.
        # A clean ledger beside an unclean vault is a partial result, not a result.
        redact.observe_response(getattr(result, "body", "") or "")
        # Health is judged on whether bytes came back, NOT on the status code: a 404 or
        # a 500 is the target answering, and several of the flaws Brukal looks for are
        # found precisely by making an application error. Only silence counts against it
        # — and only silence THE TARGET caused. The note decides which: a TLS
        # verification failure, a name we could not resolve, a route our own egress lock
        # refused, or a cage that never made the request are all OUR failures, and the
        # CR1 pre-flight halted with `target-unhealthy` against a target answering 200s
        # because they were counted as its silence. `record` returns the cause label for
        # exactly those, and a harness limit is recorded HERE, at the plane's own door,
        # so it lands in the ledger as ours instead of as a target refusal.
        _cause = self.health.record(bool(getattr(result, "status", None)),
                                    note=getattr(result, "note", "") or "")
        if _cause:
            self._audit.append("harness_limit", {
                "plane": "web", "cause": _cause, "url": getattr(action, "url", ""),
                "note": (getattr(result, "note", "") or "")[:300],
                "attribution": "HARNESS-LIMIT"})
        self._absorb_cookies(result)           # remember any Set-Cookie for the next one
        self._audit.append("web_result", {"status": result.status, "url": result.url,
                                           "note": result.note,
                                           "bytes": len(result.body or "")})
        if action.kind == "navigate" and result.status:
            self.current_url = action.url      # now interaction actions are in-scope
        self._self_capture(action, result)
        return decision, result

    # ---- SELF-CAPTURE ---------------------------------------------------- #
    # Brukal recording its own traffic. `--capture` was consume-only: the operator ran
    # Burp or mitmproxy, exported a HAR and handed it over, so the harness never saw a
    # request it had not itself decided to make.
    #
    # This door is the right and only place: every web action already passes through
    # `run`, so recording here needs no new plumbing and inherits the gate — a DENIED
    # request returns before this line, which is what keeps a refused, out-of-scope host
    # from entering a capture by the back door.
    #
    # The value is not surface enrichment (we already fetched these URLs); it is the
    # REPLAY consumer. A request made as `self` becomes an experiment whose control
    # provably worked, re-issued as `second` or `anonymous`. That machinery has existed
    # since capture.py landed and had no way to be fed without an operator's file.
    _SELF_CAPTURE_MAX = 25

    def captured(self) -> list:
        return list(getattr(self, "_captured_self", []) or [])

    def _self_capture(self, action, result) -> None:
        st = getattr(result, "status", None)
        if result is None or not st:
            return                             # never happened; not evidence
        # AN ABSENCE IS NOT A CONTROL. Capturing anything with a status meant a 404
        # became an experiment whose "control that provably worked" was the target saying
        # NO SUCH THING — a live cold run produced 10 `both_sides_absent` outcomes that
        # way. GAP #19's floor stops a 404/404 being FILED as evidence; this stops one
        # being MANUFACTURED. 5xx goes too: the application broke rather than behaved.
        #
        # A 401/403 is KEPT deliberately — a refusal is not an absence. The resource
        # exists and we were denied it, which is the most interesting control available:
        # another principal may be allowed.
        if st == 404 or st >= 500:
            return
        store = getattr(self, "_captured_self", None)
        if store is None:
            store = self._captured_self = []
        if len(store) >= self._SELF_CAPTURE_MAX:
            return
        try:
            from . import capture as _capture
            rec = _capture._record(
                getattr(action, "method", None) or "GET", action.url,
                dict(getattr(action, "headers", None) or {}),
                getattr(action, "body", None), result.status,
                len(getattr(result, "body", "") or ""),
                "", self._scope, _capture.IngestReport(), "self")
        except Exception:
            return                             # capture must never break a run
        if rec is not None:
            store.append(rec)

    def write_har(self, path) -> int:
        """Write what Brukal did as a HAR — importable into Burp or ZAP, and readable by
        our own `parse_har`. A round-trip test asserts the writer and the reader agree,
        because if they disagree the reader is the one carrying the scope and credential
        guarantees."""
        import json as _json
        from pathlib import Path as _Path
        caps = self.captured()
        entries = []
        for c in caps:
            entry = {
                "startedDateTime": "1970-01-01T00:00:00.000Z", "time": 0,
                "request": {"method": c.method, "url": c.url, "httpVersion": "HTTP/1.1",
                            "headers": [{"name": k, "value": v}
                                        for k, v in (c.headers or {}).items()],
                            "queryString": [], "cookies": [],
                            "headersSize": -1, "bodySize": -1},
                "response": {"status": c.status or 0, "statusText": "",
                             "httpVersion": "HTTP/1.1", "headers": [], "cookies": [],
                             "content": {"size": c.resp_bytes or 0,
                                         "mimeType": c.content_type or "text/html"},
                             "redirectURL": "", "headersSize": -1,
                             "bodySize": c.resp_bytes or 0},
                "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
            if c.body:
                entry["request"]["postData"] = {
                    "mimeType": "application/x-www-form-urlencoded", "text": c.body}
            entries.append(entry)
        doc = {"log": {"version": "1.2",
                       "creator": {"name": "brukal", "version": "self-capture"},
                       "entries": entries}}
        _Path(path).write_text(_json.dumps(doc, indent=1))
        return len(entries)
