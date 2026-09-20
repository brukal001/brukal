"""
discovery.py — asking the target what it HAS, instead of guessing what it might be.

WHY THIS EXISTS (cold target 1, DVWA, 2026-09-20)
    The harness fetched 30 URLs against an unfamiliar application. Two were real paths.
    Nineteen were API-shaped guesses carried over from the previous two targets —
    `/api/v1/coupon/apply`, `/coupons`, `/swagger.json`, `/graphql/console`. `/setup.php`
    answers 200 and was never requested.

    Nothing in the harness had ever asked a target what it has. `ffuf`, `gobuster`, `dirb`
    and `wfuzz` were installed in the cage the entire time and not one had ever been
    invoked in a measured engagement. That is the whole of GAP #26: recon was memory, and
    memory does not transfer.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
    One BOUNDED sweep whose command is built here rather than inherited from a tool's
    defaults, so the cost of recon is a number somebody chose: an explicit wordlist size
    and an explicit rate derived from the engagement's own limit. It is not a licence to
    sweep, and every path it reports is still confirmed by the harness's own request
    before anything acts on it.
"""
from __future__ import annotations

import json

# Kali ships these; the first that exists is used. `common.txt` is ~4.7k entries, which is
# a sweep measured in minutes at a lab rate limit, so callers cut it with `max_words`.
WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
)


def should_discover(surface) -> bool:
    """Never sweep a host that answers 200 for everything.

    `surface.soft_404` exists because such a host makes EVERY discovery tool report the
    entire wordlist as found. Running there would hand the model a fabricated map of
    thousands of paths — a louder version of the exact failure this module was written to
    remove. Fail closed, like mount discovery, which declines to invent a surface it
    cannot prove."""
    return not bool(getattr(surface, "soft_404", False))


def sweep_seconds_for(max_words: int, rate_per_min: int) -> int:
    """How long `max_words` actually takes at the engagement's rate, plus slack.

    Without this the time bound and the word bound contradict each other silently: a run
    asks for 4749 words at 2/sec inside a 180-second budget, gets through ~360, and
    reports as though the list had been searched. A fraction presented as the whole answer
    is the same confusion GAP #16 exists to prevent."""
    per_sec = max(1, int(rate_per_min) // 60)
    return int(max_words / per_sec * 1.2) + 30


# What a stack actually serves. Derived from the fingerprint, never guessed: sweeping a
# Node app for `.php` is the crAPI path-wishlist failure one layer down.
_EXTENSIONS = (
    (("php", "wordpress", "drupal", "joomla"), ".php"),
    (("asp.net", "iis", "asp"), ".aspx,.asp"),
    (("java", "tomcat", "jboss", "spring"), ".jsp,.do,.action"),
    (("python", "django", "flask"), ".py"),
)


def extensions_for(techs) -> str:
    """File extensions this target plausibly serves, from what fingerprinting FOUND.

    MEASURED: 900 requests of `common.txt` against DVWA found exactly one path,
    `/.gitignore`. The list carries no extensions and DVWA serves `.php`, so `/setup.php`
    — 200, unauthenticated, and never requested in the cold run — could not be found at
    all. An unknown stack gets NO extensions rather than a guessed set, because a wrong
    guess spends the whole budget on paths that cannot exist."""
    blob = " ".join(str(t).lower() for t in (techs or ()))
    for needles, exts in _EXTENSIONS:
        if any(n in blob for n in needles):
            return exts
    return ""


def build_ffuf_command(base: str, rate_per_min: int = 120, max_words: int = 1500,
                       wordlist: str | None = None, out_path: str = "/tmp/ffuf.json",
                       techs=None) -> str:
    """One bounded ffuf invocation.

    `-rate` is the engagement's own limit expressed per second, so a sweep cannot spend an
    allowance other parts of the run depend on — run 14 lost crAPI's identity oracle
    exactly that way, to a sweep that exhausted the budget before the probe that mattered.
    `-ac` calibrates against the host's own not-found response, which is what stops a
    soft-404 or a catch-all from reporting everything."""
    wl = wordlist or WORDLISTS[0]
    per_sec = max(1, int(rate_per_min) // 60)
    # `-maxtime` is DERIVED from the words asked for, not a constant. A fixed 180s with a
    # 4749-word list meant the sweep was cut off mid-list every time while reporting
    # nothing about having been cut off.
    maxtime = sweep_seconds_for(max_words, rate_per_min)
    exts = extensions_for(techs)
    ext_flag = f"-e {exts} " if exts else ""
    return (f"ffuf -u {base.rstrip('/')}/FUZZ -w {wl} -ac {ext_flag}-rate {per_sec} "
            f"-t 4 -timeout 5 -maxtime {maxtime} -s -of json -o {out_path}")


def parse_ffuf_json(text: str, max_results: int = 200) -> list:
    """(path, status, length) for each hit, or nothing at all.

    A UNIFORM WALL IS NOT A SURFACE. Even with calibration a host can answer identically
    to everything; if every hit shares one length the result is a wall, and reporting it
    would put a fabricated map in front of the model. Discarded whole, because a partial
    truth here is worse than silence."""
    try:
        doc = json.loads(text)
        results = doc.get("results")
    except Exception:
        return []
    if not isinstance(results, list):
        return []

    out = []
    for r in results[:max_results]:
        try:
            from urllib.parse import urlsplit
            path = urlsplit(str(r["url"])).path or "/"
            out.append((path, int(r.get("status") or 0), int(r.get("length") or 0)))
        except Exception:
            continue
    # More than a handful of hits, every one the same size => the host answers uniformly.
    if len(out) >= 10 and len({ln for _p, _s, ln in out}) == 1:
        return []
    return out


# Names that actually pay, measured rather than collected. On DVWA a 22-word list built
# this way found ELEVEN paths where 900 requests of `common.txt` found one — because under
# an engagement's own rate limit what matters is yield per request, not list size. A
# generic 4749-word sweep at 2 req/s is 79 minutes and never reaches the letter `s`.
_BASE_WORDS = (
    # The eight in the first group each ANSWERED on DVWA in the measured run; they are
    # here because they paid, not because they looked plausible.
    "index", "login", "logout", "setup", "security", "instructions", "about", "phpinfo",
    "config", "docs",
    "admin", "test", "backup", "install", "readme", "home", "dashboard",
    "upload", "uploads", "api", "status", "health", "debug", "server-status",
)
# Extension-free names worth asking for on ANY stack.
_ALWAYS = ("/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.gitignore",
           "/crossdomain.xml", "/.well-known/security.txt")


def high_yield_candidates(techs=None, limit: int = 80) -> list:
    """Paths worth asking for FIRST, shaped by what the target is.

    Deliberately small. This runs through the governed browser rather than a sweeper, so
    every hit is gated, audited, and self-captured — which means a discovered path becomes
    a replay candidate for free, instead of a line in a tool's output that nothing reads."""
    exts = extensions_for(techs)
    suffixes = [e for e in exts.split(",") if e] if exts else []
    out = list(_ALWAYS)
    for w in _BASE_WORDS:
        out.append(f"/{w}")
        for e in suffixes:
            out.append(f"/{w}{e}")
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:limit]
