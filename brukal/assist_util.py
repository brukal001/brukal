"""
assist_util.py — pure, dependency-light helpers and module constants shared by
AssistSession, its mixins and the assist CLI. Extracted verbatim from assist.py
(no logic change) so there is one copy of each.
"""
from __future__ import annotations

import re


__all__ = [
    '_VERDICT_COLOUR',
    '_AGENT_ICON',
    '_PHASE_COLOUR',
    '_HIGHLIGHTS',
    '_WEB_PORT_RE',
    '_LIKELY_WEB_PORTS',
    '_UNSURE_SVC_RE',
    '_SIGNUP_MAX_ROUNDS',
    '_JSON_SIGNUP_PATHS',
    '_IDENTITY_PROBE_PATHS',
    '_SESSION_COOKIE_NAMES',
    '_CONFIG_SET_RE',
    '_changes_target_state',
    '_LOGOUT_RE',
    '_ASSET_RE',
    '_NON_HTML_RE',
    '_FAMILY_QUOTA',
    '_MAX_NON_HTML',
    '_MINING_READS',
    '_ENTRY_BUNDLE_RE',
    '_LAZY_CHUNK_RE',
    '_bundle_rank',
    '_CALIBRATION_MIN_RATE',
    '_looks_non_html',
    '_path_family',
    '_TECH_HINTS',
    '_INTERNAL_ERRORS',
    'record_engagement_stop',
    '_url_in',
    '_explain_run_error',
    '_outcome_feedback',
    'highlight_findings',
    '_COVERAGE_WORDS',
    '_norm_ws',
    '_issued_session',
    '_norm_body',
    '_RAW_FETCH_TOOLS',
    '_COOKIE_INJECT',
    '_PLACEHOLDER_AUTH_ARG_RE',
    '_HEADER_INJECT',
    '_PATH_SCANNERS',
    '_tool_of',
    '_is_raw_fetch',
    '_SAVED_PLAN_LINE',
    '_parse_saved_plan',
]


_VERDICT_COLOUR = {"ALLOW": "green", "ESCALATE": "yellow", "DENY": "red"}
# Icon per specialist role, shown in the live views when multi-agent mode routes a
# step to that agent (recon enumerates, exploit attacks, verify confirms).
_AGENT_ICON = {"recon": "🔎", "exploit": "🔨", "verify": "✔"}
_PHASE_COLOUR = {"recon": "cyan", "enumeration": "cyan", "exploitation": "magenta",
                 "privilege-escalation": "red", "looting": "yellow"}

# Patterns that mark a line as an important RESULT worth surfacing to the operator.
_HIGHLIGHTS = [
    (re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(.*)$", re.I), "open port"),
    (re.compile(r"\b(200|301|302|401|403)\b.*(/\S*)", re.I), "web path"),
    (re.compile(r"(user(?:name)?|login|account)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"(pass(?:word)?)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|\$[0-9a-z]{1,3}\$\S+)\b", re.I), "hash"),
    (re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I), "CVE"),
    (re.compile(r"(anonymous|guest)\s+(login|access|allowed)", re.I), "anon access"),
    (re.compile(r"(disallow|robots|/admin|/backup|\.git|\.env|phpmyadmin)", re.I), "interesting"),
]


# Open web-service ports in an nmap highlight line ("80/tcp open http ...").
_WEB_PORT_RE = re.compile(r"(\d{1,5})/tcp\s+open\s+(\S+)", re.I)
# Ports that carry a web app often enough to be worth ONE fetch even when nmap fails to
# label them http. Modern app servers routinely defeat service detection: OWASP Juice
# Shop on 3000 fingerprints as "ppp?", so trusting the label alone silently drops the
# ENTIRE web surface of any Node/React/Django/Rails app on its dev port.
_LIKELY_WEB_PORTS = frozenset({
    "3000", "3001", "4200", "4443", "5000", "5001", "5173", "7001", "8000", "8001",
    "8008", "8080", "8081", "8088", "8180", "8443", "8800", "8888", "9000", "9090",
    "9443",
})
# Service labels that mean "nmap could not tell" — a guess ("ppp?"), an unknown, or a
# firewalled banner. Never a reason to conclude the port is NOT web.
_UNSURE_SVC_RE = re.compile(r"\?$|^unknown$|^tcpwrapped$|^ppp$", re.I)

# Registration path SHAPES a JSON signup may be reached at, for a target that serves no
# server-rendered <form> — an SPA, which is most modern applications and the population
# where authorization bugs are both most common and most valuable.
#
# An ALLOWLIST, in the same spirit as `schema._NO_RESOLVE_FLAGS`: small, explicit and
# reviewable, rather than a regex that grows by accident. Candidates are drawn from what
# the CRAWL actually observed and then filtered through this — never assumed, and never
# fired at every route the crawl mined, because a real surface has dozens of them and
# some are destructive. A path not on this list is not tried, and adding one is a
# deliberate act by a maintainer rather than something a target can talk us into.
# How many times a registration endpoint may name further required fields before we stop
# asking. Four is one minimal attempt plus three rounds of reading its own refusal: enough
# for crAPI (one round, two fields at once) and short enough that an endpoint refusing for
# a reason it will not name cannot turn into a POST loop at somebody's signup.
_SIGNUP_MAX_ROUNDS = 4

_JSON_SIGNUP_PATHS = (
    "/api/users", "/api/user", "/users",
    "/register", "/api/register", "/auth/register", "/api/auth/register",
    "/rest/user/register", "/signup", "/api/signup", "/accounts",
)
# WHERE to ask "who am I", and WHAT a session cookie is conventionally called. Both are
# explicit allowlists for the same reason `_JSON_SIGNUP_PATHS` is one: the alternative is
# a regex loose enough to match anything, which is how a probe starts POSTing at
# arbitrary routes or a "session cookie" turns out to be a CSRF token or a locale
# preference. Never a guess — a documented, conventional name or nothing.
#
# Read-only GETs, tried in order, stopping at the first that tells an authenticated
# caller apart from an anonymous one.
# Ordered: the conventional ones first, because they answer on most targets in one
# request. Target-specific entries go at the END so they never displace a convention.
#
# `/identity/api/v2/user/dashboard` is crAPI's, added 2026-09-17 after the CR1 pre-flight
# found the list had no path that reached it. It earns its place on the property this
# list exists for: it READS THE AUTHORIZATION HEADER and returns a numeric id (measured —
# bearer -> {"id":9,...}; the same token as a cookie -> 404; anonymous -> 404), which is
# exactly what Juice Shop's cookie-only `/rest/user/whoami` could not do for a bearer-
# carrying second principal. That gap is what CM5 and CM6 had to disclose on every
# `variant_as: second` claim.
#
# The cost of an allowlist is that a new target needs a new entry, and that cost is real.
# It is still the right mechanism: the alternative is a pattern loose enough to match
# "anything profile-shaped", which is how a probe starts GETting arbitrary routes on a
# live target. The cost is paid where it can be counted — the portability tally.
_IDENTITY_PROBE_PATHS = (
    "/rest/user/whoami", "/api/me", "/me", "/api/user/me", "/rest/user/me",
    "/api/users/me", "/api/account", "/api/profile", "/user/profile", "/whoami",
    "/identity/api/v2/user/dashboard",
)
# Cookie names that conventionally CARRY a session token. Ordered: the first that proves
# itself wins. `csrf`/`XSRF` are deliberately absent — those are anti-forgery values, not
# credentials, and setting a token as one would prove nothing and corrupt a real one.
_SESSION_COOKIE_NAMES = (
    "token", "jwt", "access_token", "auth_token", "authToken",
    "session", "sessionid", "session_id", "sid", "connect.sid",
)
# URLs that DESTROY the session: never fetch these during a crawl, or we log
# ourselves out and the rest of an AUTHENTICATED crawl runs unauthenticated (a
# classic authenticated-scanning trap — the scanner clicks its own "logout").
# A link that SETS a configuration value. `/difficulty/hard` is a plain GET with no
# destructive word in it, and following it during a crawl silently switched a live
# target from easy mode to hard mode — disabling GraphQL introspection PARTWAY THROUGH
# Brukal's own assessment. The finding made before that request was true and the
# verification after it failed, because they were made against two different
# applications.
#
# Three things are wrong with that, in rising order of seriousness: the run is not
# reproducible, it is not internally consistent, and on a real engagement Brukal would
# have altered a client's security posture without being asked. The existing
# destructive-path doctrine — "read-only is a property of the METHOD, not the endpoint"
# — was already written down here; the crawl simply never applied it.
#
# The shape is a configuration noun followed by the value it is being set to. Matching
# the noun alone would refuse `/settings`, which is an ordinary page worth reading.
_CONFIG_SET_RE = re.compile(
    r"/(?:difficulty|mode|level|setting|config|configuration|preference|theme|locale|"
    r"lang|language|toggle|switch|feature[-_]?flag|env|environment)s?/"
    r"[A-Za-z0-9_.-]{1,40}/?$", re.I)


def _changes_target_state(url: str) -> bool:
    """Whether following this link would change the APPLICATION rather than read it.

    Used to keep a crawl read-only in EFFECT, not merely in method."""
    return bool(_CONFIG_SET_RE.search(url or ""))


_LOGOUT_RE = re.compile(r"(?:log[-_]?out|sign[-_]?out|log[-_]?off|/logoff\b"
                        r"|[?&](?:action|do|page|op)=(?:log[-_]?out|sign[-_]?out))", re.I)

# --- crawl budget discipline ------------------------------------------------------
# A page budget is the crawl's scarcest resource, and on an unfamiliar application it
# was being spent almost entirely on things that could not contain a vulnerability. A
# live authenticated run on DVNA mapped twenty pages: twelve renderings of one
# documentation template, four URLs invented by parsing a JS bundle as HTML, three
# static assets — and zero of /products, /admin, /usersearch, /calc or /ping, which is
# the whole application. Breadth on an unfamiliar target is exactly the capability
# being defended here, so the budget is now spent on things that can answer a question.

# Cannot hold a form, a parameter, or a route. Note .js is deliberately ABSENT: a
# bundle is the one non-HTML response worth reading, because an SPA keeps its endpoints
# there. It is mined for routes without being treated as a page.
_ASSET_RE = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|otf|eot|mp[34]|webm|"
    r"pdf|zip|gz|tgz|map)(?:$|[?#])", re.I)

_NON_HTML_RE = re.compile(r"\.(?:js|mjs|json|xml|txt)(?:$|[?#])", re.I)

# How many pages ONE deep templated family may take before the rest wait for leftovers,
# and how many non-HTML bodies are worth mining. Both small: the point is to sample a
# shape, not to enumerate it.
_FAMILY_QUOTA = 3
_MAX_NON_HTML = 5
# Extra reads for ROUTE DISCOVERY only, after the page budget is spent. Deliberately
# small: their whole purpose is to harvest path strings from pages a quota deferred.
_MINING_READS = 8

# Bundles worth reading FIRST. A modern SPA build emits one entry bundle that names the
# API and many lazy chunks that mostly do not — and the crawl sorted its frontier
# alphabetically, so `chunk-5K74DZ2F.js` came before `main.js` every time. On OWASP
# Juice Shop that spent the entire non-HTML allowance on five chunks, never read
# main.js, and mined eleven routes instead of forty: the endpoint carrying the
# application's best-known SQL injection was simply never seen.
_ENTRY_BUNDLE_RE = re.compile(r"/(?:main|app|index|bundle|vendor)[.-]", re.I)
_LAZY_CHUNK_RE = re.compile(r"/(?:chunk|polyfill|runtime|scripts?|styles?)[.-]", re.I)


def _bundle_rank(url: str) -> int:
    """Read order for a link. Lower is sooner. HTML pages keep their place; among
    scripts, the entry bundle is worth more than any number of lazy chunks."""
    if not _looks_non_html(url):
        return 0
    if _ENTRY_BUNDLE_RE.search(url or ""):
        return 1
    if _LAZY_CHUNK_RE.search(url or ""):
        return 3
    return 2
# Below this many requests per minute, calibration's few probes are a material fraction
# of the whole engagement and are better spent on findings.
_CALIBRATION_MIN_RATE = 60


def _looks_non_html(url: str) -> bool:
    return bool(_NON_HTML_RE.search(url or ""))


def _path_family(url: str) -> str:
    """The templated family a URL belongs to, or "" when it is not deep enough to be
    one. `/learn/vulnerability/a1_injection` and `/learn/vulnerability/a7_xss` share the
    family `/learn/vulnerability`; `/admin/users` and `/products` have none, because
    capping shallow paths would throttle the top-level routes that matter most."""
    from urllib.parse import urlsplit
    try:
        sp = urlsplit(url or "")
    except ValueError:
        return ""
    segs = [s for s in (sp.path or "").split("/") if s]
    if len(segs) < 3:
        return ""
    return f"{sp.scheme}://{sp.netloc}/" + "/".join(segs[:-1])

# Services / technologies worth pulling a red-team playbook for, mined from the
# highlights so skill retrieval follows what we've actually discovered on the box.
_TECH_HINTS = re.compile(
    r"\b(http|https|ssh|ftp|smtp|smb|nfs|rpc|snmp|dns|ldap|kerberos|rdp|winrm|"
    r"nginx|apache|tomcat|iis|jetty|node|express|php|jsp|aspx|python|ruby|"
    r"mysql|mssql|postgres|postgresql|oracle|redis|mongodb|memcached|elastic|"
    r"wordpress|drupal|joomla|jenkins|gitlab|jira|confluence|struts|spring|"
    r"api|graphql|jwt|oauth|saml|upload|login|admin|cms|webdav|cgi)\b", re.I)


# Exceptions that mean BRUKAL is broken, not the model or the cage. Reporting a
# NameError as "check the model is reachable and the cage is up" sent a real debugging
# session chasing infrastructure while the bug was a missing import in the loop's hot
# path — so these are named as internal errors and always print their traceback.
_INTERNAL_ERRORS = (NameError, AttributeError, TypeError, ImportError, IndexError,
                    KeyError, UnboundLocalError, AssertionError)


def record_engagement_stop(audit, reason: str, detail: str, steps: int = 0,
                           executed: int = 0, blocked: int = 0) -> None:
    """Write HOW THIS RUN ENDED into the ledger.

    The CR1 measurement run (2026-09-18) stopped at step ~60 of 70 because the model
    provider refused — and nothing in the artifacts said so. The message went to stdout,
    no report was written, and the ledger's last entry was an ordinary `web_decision`.

    Looking for the fix showed the hole was wider than the crash: `GroundedLoop._finish`
    emits `stop` to the DISPLAY, never to the audit log, so no run of any kind recorded
    its ending there. CR1's definition of done requires a run to complete "or stop for a
    named reason RECORDED IN THE LEDGER", which made that clause unmeetable by
    construction — and without it "found nothing" and "died before it could look" read
    identically in a bundle.

    Carries an attribution on the same taxonomy as every experiment outcome: a run killed
    by our own model access or plumbing is a HARNESS-LIMIT, not the target refusing.

    Instrumentation, so it can never end an engagement: a broken audit sink is swallowed.
    """
    from . import hypothesis as _hyp
    try:
        audit.append("engagement_stop", {
            "reason": reason,
            "detail": (detail or "")[:400],
            "steps": steps,
            "executed": executed,
            "blocked": blocked,
            # `aborted` is ours by definition — the run did not choose to end. Every other
            # ending is a measurement that completed on its own terms.
            "attribution": ("HARNESS-LIMIT" if reason == "aborted"
                            else _hyp.attribution("confirmed")),
        })
    except Exception:
        pass


def _url_in(command: str) -> str:
    """The http(s) URL a command addressed, or "". Deterministic and quoted-safe — the
    command is the agent's own text, so nothing here may execute or interpret it."""
    import re as _re
    m = _re.search(r"https?://[^\s'\"<>|]+", command or "")
    return m.group(0).rstrip("'\"") if m else ""


def _explain_run_error(e: BaseException) -> tuple[str, str]:
    """(headline, advice) for an exception that ended a run. Distinguishes OUR bug from
    an environment problem, because the two need opposite responses from the operator."""
    if isinstance(e, _INTERNAL_ERRORS):
        import traceback
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        where = ""
        for line in reversed(tb.splitlines()):
            if line.strip().startswith("File ") and "/brukal/" in line:
                where = line.strip()
                break
        return (f"internal error in Brukal: {type(e).__name__}: {e}",
                f"This is a bug in Brukal, NOT your model or cage. {where}\n"
                f"  Please report it with the trace below.\n{tb}")
    return (f"model/cage error: {e}",
            "Check the model is reachable (key set, or Ollama running) and the "
            "cage is up. Set BRUKAL_DEBUG=1 for the trace.")


def _outcome_feedback(decision, result, raw: str) -> str:
    """Digest an executed command's outcome into a note the strategist can learn
    from — a timeout or empty result becomes an explicit 'do it differently' cue."""
    timed_out = (getattr(result, "returncode", 0) == 124
                 or "timed out" in (getattr(result, "stderr", "") or "").lower())
    if timed_out:
        return (f"{decision.verdict}: TIMED OUT — the command was too slow and got "
                f"killed with no result. Use a FASTER, more targeted command "
                f"(fewer ports, drop -A/-p-).")
    # A tool that FAILED is not a tool that found nothing. nikto given -Format without
    # -output exits rc=13 after printing its banner, and Brukal recorded that as "no
    # notable output" — indistinguishable from a clean scan, which is a false negative
    # dressed as a result. Surface the failure and the reason.
    rc = getattr(result, "returncode", 0) or 0
    err = (getattr(result, "stderr", "") or "").strip()
    if rc not in (0, None) and len(raw.strip()) < 200:
        why = err.splitlines()[0][:200] if err else f"exit code {rc}"
        return (f"{decision.verdict}: TOOL FAILED — it exited {rc} without scanning, so "
                f"this is NOT a clean result. Reason: {why}. Fix the invocation or use "
                f"another tool; do not treat the silence as 'nothing found'.")
    if not raw:
        return (f"{decision.verdict}: (no output — this returned nothing useful; "
                f"try a different tool or target)")
    return f"{decision.verdict}: {raw[:800]}"


def highlight_findings(output: str, limit: int = 12) -> list[tuple[str, str]]:
    """Pull the lines from raw tool output that a pentester actually cares about.
    Returns (tag, line) pairs — open ports, web paths, creds, hashes, CVEs, ..."""
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or len(line) > 200:
            continue
        for rx, tag in _HIGHLIGHTS:
            if rx.search(line) and line not in seen:
                hits.append((tag, line))
                seen.add(line)
                break
        if len(hits) >= limit:
            break
    return hits


# Which finding titles belong to which assessed class, so "we probed X and found
# nothing" can be distinguished from "we probed X and here it is".
_COVERAGE_WORDS = {
    "SQL injection": ("sql injection",),
    "NoSQL injection": ("nosql injection",),
    "Command injection": ("command injection",),
    "Path traversal / LFI": ("local file", "path traversal"),
    "Template injection": ("template injection",),
    "Cross-site scripting": ("cross-site scripting", "xss"),
    "SSRF": ("server-side request",),
    "Open redirect": ("open redirect",),
    "Object-level authz (BOLA)": ("object-level authorization", "idor",
                                  "horizontal account takeover"),
    # A new detector whose title matches no word here produces a report that
    # CONTRADICTS ITSELF: the finding list carries a CRITICAL while the coverage table
    # says the class found nothing. That has now happened three times — model-proposed
    # experiments, then both cookie-session authz checks — so the words are kept beside
    # the titles the detectors actually emit, and test_coverage asserts every finding a
    # live run produced maps to a class.
    "Function-level authz (BFLA)": ("function-level authorization",
                                    "self-registered account",
                                    "administrative endpoint"),
    "Credential recovery": ("reset token", "password reset"),
    "Default credentials": ("default credentials",),
    "Session management": ("session fixation", "not rotated", "session not revoked"),
    "Password policy": ("password complexity", "password policy"),
    "Blind injection (out-of-band)": ("blind ssrf", "blind rce", "out-of-band"),
    "Insecure deserialization": ("insecure deserialization",),
    # Probed for a long time with no words here at all, so however much they found the
    # table reported "none found" — the report contradicting its own finding list. That
    # makes five instances; test_coverage_consistency now makes it impossible.
    "Credential storage": ("recoverable form", "plaintext password"),
    "Signup abuse": ("rate limiting on account creation",),
    "Mass assignment": ("mass assignment",),
    "JWT / token handling": ("jwt", "forged"),
    "Authentication posture": ("rate limiting", "enumeration", "session not revoked"),
    "Unauthenticated exposure": ("unauthenticated exposure", "unauthenticated access"),
    "Prompt injection (LLM)": ("prompt injection",),
    "GraphQL": ("graphql",),
    "Transport / browser hygiene": ("security header", "cors",
                                    "cookie set without"),
    "Debug exposure": ("debug console",),
    # Model-proposed experiments carry titles the model chose, so they cannot be matched
    # by keyword like the fixed detectors. They are recognised by CATEGORY instead —
    # without this the coverage table said "none found" for a class that had just
    # produced two critical findings.
    "Model-proposed experiments": ("\x00never-matches",),
}


def _norm_ws(text) -> str:
    """Collapse whitespace, so two renderings of the same page compare equal.

    Referenced by the recovery-enumeration differential before it existed anywhere — a
    NameError that would have been swallowed whole by the caller's `except Exception`,
    turning a detector into a silent no-op indistinguishable from a clean target. That
    is the fifth time an unwired or unreachable check has hidden behind broad exception
    handling in this file."""
    return re.sub(r"\s+", " ", (text or "")).strip()


def _issued_session(body: str) -> bool:
    """Whether a login response actually handed back a credential.

    The status code cannot answer this: an API returning 200 with
    {"status": "fail"} is common, and so is 401 with a token in a redirect body. What
    settles it is the presence of something session-shaped."""
    text = (body or "")[:2000]
    if re.search(r'"(?:auth_token|access_token|id_token|token|jwt|session)"\s*:\s*"[^"]{8,}"',
                 text, re.I):
        return True
    return bool(re.search(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", text))


def _norm_body(text: str, *drop: str) -> str:
    """A response body reduced to what is COMPARABLE between two probes.

    Collapses whitespace and removes the tokens we ourselves submitted. That second
    part is load-bearing for the enumeration check: an API that echoes the attempted
    username back ("no such user: bob") would otherwise differ on every pair of probes
    and make every target look like an oracle. Removing the input leaves only the part
    of the answer the SERVER chose."""
    out = text or ""
    for token in drop:
        if token:
            out = out.replace(token, "")
    return re.sub(r"\s+", " ", out).strip()


_RAW_FETCH_TOOLS = frozenset({"curl", "wget", "http", "https", "httpie", "cat",
                             "aws", "hurl", "xh"})

# How each web tool takes a cookie string, so an authenticated session can be handed
# to a shell tool. `{C}` is the "name=value" cookie string (single-cookie only — see
# _session_cookie_for; multi-cookie sessions use WEB actions to avoid the gate's ';').
_COOKIE_INJECT = {
    "curl": "-b '{C}'", "wget": "--header='Cookie: {C}'", "sqlmap": "--cookie='{C}'",
    "ffuf": "-H 'Cookie: {C}'", "gobuster": "-c '{C}'", "feroxbuster": "-b '{C}'",
    "nuclei": "-H 'Cookie: {C}'", "nikto": "-Add-header 'Cookie: {C}'", "dirb": "-H 'Cookie: {C}'",
    "wpscan": "--cookie-string '{C}'", "dirsearch": "--cookie '{C}'",
}
# How each web tool takes an arbitrary header, for a bearer/basic Authorization session
# (token APIs). `{H}` is the full header line "Authorization: Bearer <token>".
# One whole auth ARGUMENT whose value is a redaction placeholder — `-H 'Authorization:
# Bearer [REDACTED:1f3a9c02]'`, `--cookie='sid=[REDACTED:...]'`, and the long forms. Only
# ever used to REMOVE a masked credential from a proposed command so the real one can be
# injected; it never adds, authorises, or widens anything.
_PLACEHOLDER_AUTH_ARG_RE = re.compile(
    r"""\s*(?:-H|--header|-b|--cookie|--cookie-string|-c|-Add-header)(?:=|\s+)"""
    r"""(['"])[^'"]*\[REDACTED:[0-9a-f]{8}\][^'"]*\1""", re.I)

_HEADER_INJECT = {
    "curl": "-H '{H}'", "sqlmap": "-H '{H}'", "ffuf": "-H '{H}'", "nuclei": "-H '{H}'",
    "gobuster": "-H '{H}'", "feroxbuster": "-H '{H}'", "wget": "--header='{H}'",
    "dirsearch": "-H '{H}'", "wfuzz": "-H '{H}'", "httpie": "'{H}'",
    "nikto": "-Add-header '{H}'",
}

# Pure path-discovery scanners: they only tell you a path "exists". On a soft-404 host
# (200 for everything) that verdict is meaningless, so their findings are downgraded.
_PATH_SCANNERS = frozenset({"nikto", "gobuster", "ffuf", "dirb", "feroxbuster",
                           "dirsearch", "wfuzz", "dirbuster"})


def _tool_of(command: str) -> str:
    """Basename of the tool a command invokes, lowercased ('' if unparseable)."""
    import shlex
    try:
        toks = shlex.split(command)
    except ValueError:
        return ""
    return toks[0].rsplit("/", 1)[-1].lower() if toks else ""


def _is_raw_fetch(command: str) -> bool:
    """True if `command`'s tool emits a raw response/file body (so exposure signatures
    are meaningful), False for scanners/attack tools whose verbose output would
    false-positive the content signatures."""
    # A governed-browser fetch IS a raw response body — the same thing curl returns,
    # just through the web door instead of the shell one. Without this the crawl could
    # read a stack trace or a leaked key on 20 pages and record nothing.
    if (command or "").startswith("WEB "):
        return True
    return _tool_of(command) in _RAW_FETCH_TOOLS


# A saved plan line is "N. [mark] [phase] text" where mark is x (done), > (current)
# or blank (pending) — distinct from the strategist's fresh "N. [phase] text".
_SAVED_PLAN_LINE = re.compile(
    r"^\s*\d+\.\s*\[(?P<mark>[x> ])\]\s*(?:\[(?P<phase>[^\]]+)\]\s*)?(?P<text>.+?)\s*$")
def _parse_saved_plan(text: str) -> list:
    from .agents.strategist import PlanStep
    steps: list = []
    for line in (text or "").splitlines():
        m = _SAVED_PLAN_LINE.match(line)
        if not m:
            continue
        steps.append(PlanStep(text=m.group("text").strip(),
                              phase=(m.group("phase") or "").strip().lower(),
                              done=m.group("mark") == "x"))
    return steps
