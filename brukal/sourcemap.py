"""
sourcemap.py — read the application's source to decide WHERE to look, never WHAT is true.

A white-box competitor scored well on the same target partly by reading
`SECRET_KEY = 'random'` straight out of the repository and reporting it as a finding.
Brukal reached the same conclusion black-box, by recovering the key offline from a
captured token's own signature — slower to write, and it works on a target whose source
nobody has.

So the interesting question is not "should Brukal read source" but "what may it conclude
from having read it". The answer here is: **nothing**. Source analysis is pattern
matching over text an attacker cannot be assumed to have; treating a regex hit as proof
would put an unverified claim next to fourteen proven ones and quietly destroy the
distinction the whole report rests on.

Everything this module produces is a LEAD — a place to point a deterministic prover at.
A hardcoded secret becomes "try this key against a real token"; a string-formatted SQL
query becomes "probe this route for injection". If the dynamic proof fails, there is no
finding, however incriminating the source looked. That is the same contract signature
packs have: contributed data selects, it never confirms.

Read-only, standard library, and it never executes anything it finds.
"""
from __future__ import annotations

import re
from pathlib import Path

# Files worth reading. Deliberately narrow: this is a lead generator, not a SAST engine,
# and walking a node_modules tree would cost minutes to produce noise.
_SOURCE_SUFFIXES = (".py", ".js", ".ts", ".rb", ".php", ".go", ".java", ".env",
                    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
              "vendor", "site-packages", ".mypy_cache", ".pytest_cache", "target"}
_MAX_FILES = 400
_MAX_BYTES = 400_000

# (pattern, lead-kind, what a prover should DO with it). Every one of these is a
# suggestion; none is a finding.
_LEADS = (
    # The name is often a dict KEY rather than a bare identifier —
    # `config['SECRET_KEY'] = 'x'`, `{"SECRET_KEY": "x"}` — so allow the closing quote
    # and bracket between the name and the assignment. Matching only the bare form
    # missed the real declaration in every Flask and Django app tried.
    (re.compile(r"""(?:SECRET_KEY|JWT_SECRET|SIGNING_KEY|TOKEN_SECRET)['"\]]*\s*[:=]\s*"""
                r"""['"]([^'"]{3,64})['"]""", re.I),
     "signing-secret", "try this value as the token signing key against a live token"),
    (re.compile(r"""(?:PASSWORD|PASSWD|DB_PASS)['"\]]*\s*[:=]\s*['"]([^'"]{3,64})['"]""",
                re.I),
     "credential", "try these credentials at the login endpoint"),
    (re.compile(r"""(?:API_KEY|APIKEY|ACCESS_TOKEN)['"\]]*\s*[:=]\s*"""
                r"""['"]([^'"]{8,80})['"]""", re.I),
     "api-key", "check whether this key is accepted by the live API"),
    (re.compile(r"""(?:execute|query|cursor\.execute|db\.raw)\s*\(\s*(?:f['"]|['"][^'"]*"""
                r"""['"]\s*(?:%|\+|\.format))""", re.I),
     "sql-interpolation", "probe the route served by this handler for SQL injection"),
    (re.compile(r"""\bdebug\s*[:=]\s*True\b""", re.I),
     "debug-mode", "check for an interactive debugger reachable over the network"),
    (re.compile(r"""(?:verify|check)_(?:signature|token)\s*[:=]\s*False|"""
                r"""verify\s*=\s*False""", re.I),
     "signature-check-off", "test whether an unsigned or altered token is accepted"),
)


# Values that are plainly PROSE rather than a secret. Without this the credential
# pattern happily matched `'Password': 'Updated.'` — a response message in a handler —
# and offered it as a login to try. A lead that wastes a request is cheap, but a lead
# list full of obvious nonsense is one an operator stops reading.
_PROSE_WORDS = frozenset({
    "updated", "changed", "required", "invalid", "incorrect", "missing", "success",
    "failed", "error", "none", "null", "true", "false", "todo", "changeme", "example",
    "your_password_here", "xxx", "redacted",
})


def _looks_like_prose(value: str) -> bool:
    """True when a matched value is English rather than a credential."""
    v = (value or "").strip()
    if not v or " " in v or "\t" in v:
        return True                      # secrets do not contain spaces
    if v.endswith(".") or v.endswith("!"):
        return True                      # sentences do
    return v.lower().strip(".!") in _PROSE_WORDS


def _candidate_files(root: Path):
    seen = 0
    for path in sorted(root.rglob("*")):
        if seen >= _MAX_FILES:
            return
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        seen += 1
        yield path


def scan(root, max_leads: int = 40) -> list[dict]:
    """Leads from a source tree. Never raises, never executes, never concludes.

    Each lead is {kind, value, hint, where} — `value` is what a prover should TRY, and
    `where` exists so a human can see why Brukal went looking, not so the lead can be
    reported on its own."""
    base = Path(root)
    if not base.is_dir():
        return []
    leads: list[dict] = []
    seen: set = set()
    for path in _candidate_files(base):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rx, kind, hint in _LEADS:
            for m in rx.finditer(text):
                value = (m.group(1) if m.groups() else m.group(0)).strip()
                key = (kind, value)
                if key in seen or not value:
                    continue
                if kind in ("signing-secret", "credential", "api-key") \
                        and _looks_like_prose(value):
                    continue
                seen.add(key)
                try:
                    where = str(path.relative_to(base))
                except ValueError:
                    where = path.name
                leads.append({"kind": kind, "value": value[:120], "hint": hint,
                              "where": where})
                if len(leads) >= max_leads:
                    return leads
    return leads


def secrets_to_try(leads) -> list[str]:
    """Candidate signing keys, for the JWT prover to attempt against a real token.

    This is the whole white-box benefit expressed honestly: a key too long or odd to
    brute-force may sit in plain sight in the repository, and trying it costs one
    offline signature check. If it does not verify against a token the target actually
    issued, there is no finding — the source said so, and the source is not evidence."""
    return [lead["value"] for lead in leads if lead["kind"] == "signing-secret"]


def summarise(leads) -> str:
    """One line for the operator, phrased so it can never be mistaken for findings."""
    if not leads:
        return ""
    kinds = sorted({lead["kind"] for lead in leads})
    return (f"[source] {len(leads)} lead(s) from the supplied tree "
            f"({', '.join(kinds)}) — leads only; each must still be proved against the "
            f"running target before it becomes a finding")
