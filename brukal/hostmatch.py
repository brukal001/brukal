"""
hostmatch.py — deterministic host extraction for the scope gate (safety core).

Standard library ONLY (no third-party imports — this file is part of the
untrickable core alongside gate/scope/risk/executor/web/audit).

Given a command string or a session line, find EVERY host it references and
normalise each to a canonical string the scope check can look up:

  * URL tokens (anything containing ``://``) -> the parsed ``hostname``.
  * IPv4 / IPv6 literals.
  * Integer / 0x-hex / 0o-octal encodings that denote a routable IP — the classic
    "decimal IP" smuggle (``curl http://134744072/`` == ``8.8.8.8``). Only values
    at or above 1.0.0.0 are treated as IPs, so ``--top-ports 100`` stays a number.
  * NETWORKS: CIDRs (``10.10.10.0/24``) and nmap octet ranges (``10.10.10.11-20``,
    ``10.10.10.*``) are reported as canonical CIDR string(s); the gate requires a
    network to lie wholly inside scope (SEC-001 — these used to be dropped as paths).
  * Scheme-less ``host/path``, ``host:port/path`` and ``ip:port`` — the host before
    the first '/' or ':' (SEC-002). A token that starts like a filesystem path
    (``/etc``, ``./x``, ``~/x``) has no host part.
  * Bare dotted hostnames used as arguments (``nmap evil.com``, ``ssh u@evil.com``),
    conservatively — a token with a known file extension is a filename, NOT a host.

Tokens are split on whitespace and shell operators, with quotes/backslashes removed
and numeric brace expansion rewritten (see ``_tokens``).

The gate enforces the policy: every host this returns must be in scope, or the
action is denied (fail-closed). This module only *finds* hosts; it never decides.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Integers below 1.0.0.0 (2**24) canonicalise into the 0.0.0.0/8 "this-network"
# block, which is never a routable target — that is exactly where ports, thread
# counts, and timeouts live. Only integers at/above it are read as an encoded IP,
# so `--top-ports 100` is a number while `134744072` (8.8.8.8) is a host.
_INT_HOST_MIN = 1 << 24

# A whole token that is a decimal / hex / octal integer (no leading-zero decimal).
_INT_TOKEN_RE = re.compile(r"(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|[1-9][0-9]*)\Z")

# A bare dotted hostname shape: dot-separated labels ending in an ALPHABETIC TLD
# (2-63 letters). Requiring an alphabetic final label is both correct (a real
# hostname can't have an all-numeric TLD — that would be an IP, handled above) and
# the thing that keeps dotted COMMAND names out: `mkfs.ext4`, `python3.11`, and
# `nmap.nse` end in a digit/short token, so they are not mistaken for hosts, while
# `evil.com` / `nexus.htb` still match.
_DOTTED_HOST_RE = re.compile(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}\Z")

# Known file extensions, so a filename / wordlist / script token is never read as a
# host (e.g. common.txt, linpeas.sh, exploit.py, scan.gnmap, backup.tar.gz).
_FILE_EXT_RE = re.compile(
    r"\.(?:txt|lst|list|log|conf|cfg|ini|json|xml|ya?ml|toml|sh|bash|zsh|py|rb|pl|"
    r"php|js|ts|go|c|cpp|h|java|html?|css|md|rst|csv|tsv|pem|key|pub|crt|cer|der|"
    r"p12|pfx|db|sqlite3?|sql|bak|old|orig|tmp|swp|zip|gz|tgz|bz2|xz|7z|rar|tar|"
    r"png|jpe?g|gif|svg|ico|bmp|webp|pdf|docx?|xlsx?|pptx?|bin|exe|dll|so|o|a|"
    r"out|dump|pcap|cap|nmap|gnmap|xsl|dtd|env|lock)\Z", re.I)


def canonical_ip(token: str) -> str | None:
    """Canonical IP string for a token that denotes an IP — a dotted IPv4, an IPv6
    literal, or an integer/hex/octal encoding at or above 1.0.0.0. Returns None for
    anything that is not an IP (including small integers that are ports/counts)."""
    t = (token or "").strip()
    if not t:
        return None
    try:
        return str(ipaddress.ip_address(t))          # dotted IPv4 or IPv6 literal
    except ValueError:
        pass
    if not _INT_TOKEN_RE.match(t):
        return None
    try:
        val = int(t, 0)
    except ValueError:
        return None
    if val < _INT_HOST_MIN:
        return None                                  # a port / count, not a host
    try:
        return str(ipaddress.ip_address(val))
    except ValueError:
        return None


def _clean(tok: str) -> str:
    return tok.strip().strip("\"'`(),<>[]{}")


# A CIDR token: a dotted-quad or a colon-bearing IPv6 literal, '/', a numeric prefix
# length (`10.10.10.0/24`, `10.10.10.11/32`, `2001:db8::/32`). Deliberately NOT
# matching `1/2` or `HTTP/1.1`, which are not networks.
_CIDR_RE = re.compile(r"(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*)/[0-9]{1,3}\Z")

# An nmap-style IPv4 target spec: four dot-separated octet specs, each built from
# digits, '-', ',' and '*' (`10.10.10.11-20`, `10.10.10.*`, `10.10.10.10,11`).
_OCTET_SPEC_RE = re.compile(r"(?:[0-9*,-]+\.){3}[0-9*,-]+\Z")


def _octet_bounds(spec: str) -> tuple[int, int] | None:
    """(lowest, highest) value an nmap octet spec can take, or None if malformed.
    `*` is 0-255; `a-b`, `-b` (0-b) and `a-` (a-255) are ranges; ',' joins parts."""
    lo, hi = 256, -1
    for part in spec.split(","):
        if part == "*":
            a, b = 0, 255
        elif "-" in part:
            left, _, right = part.partition("-")
            if not (left.isdigit() or left == "") or not (right.isdigit() or right == ""):
                return None
            a = int(left) if left else 0
            b = int(right) if right else 255
        elif part.isdigit():
            a = b = int(part)
        else:
            return None
        if not (0 <= a <= b <= 255):
            return None
        lo, hi = min(lo, a), max(hi, b)
    return (lo, hi) if hi >= 0 else None


def _network_targets(tok: str) -> list[str] | None:
    """SEC-001: a token that names a NETWORK rather than one host — a CIDR or an nmap
    octet range. Returns the canonical network(s) it covers (a range is summarised to
    the CIDR blocks spanning its lowest..highest address — a superset, so the scope
    check can only be stricter than the real target set), or None if the token is not
    network-shaped. A network-shaped token that does not parse is returned VERBATIM so
    the scope check denies it (fail-closed) instead of it being dropped as a path."""
    if _CIDR_RE.match(tok):
        try:
            return [str(ipaddress.ip_network(tok, strict=False))]
        except ValueError:
            return [tok]
    if _OCTET_SPEC_RE.match(tok) and any(c in tok for c in "-,*"):
        bounds = [_octet_bounds(o) for o in tok.split(".")]
        if any(b is None for b in bounds):
            return [tok]
        lo = ipaddress.IPv4Address(".".join(str(b[0]) for b in bounds))
        hi = ipaddress.IPv4Address(".".join(str(b[1]) for b in bounds))
        return [str(n) for n in ipaddress.summarize_address_range(lo, hi)]
    return None


# Shell control operators. A session line is typed into a real bash, so `curl
# 10.10.10.11;id` reaches 10.10.10.11 — the operator glued to the host must not hide
# it from the scan (it did: the token `10.10.10.11;id` matched nothing).
_SHELL_SPLIT_RE = re.compile(r"[\s;|&<>()`$]+")


def _tokens(text: str) -> list[str]:
    """Split a command/session line into candidate tokens the way bash would see
    the words that can name a host: on whitespace AND shell operators; with quotes
    and backslashes removed inside a word (`10.10.10."11"` and `1\\0.10.10.11` are
    10.10.10.11 to bash); and with numeric brace expansion rewritten as an nmap
    octet spec (`10.10.10.{10,11}` -> `10.10.10.10,11`, `{10..20}` -> `10-20`) so
    the range rule covers it. A word with any other brace list is also offered
    split at `{`, `,` and `}`, so `{10.10.10.11,x}` still yields 10.10.10.11.

    This is word-level parsing, not a bash interpreter: a host assembled at run time
    from a variable or a decoded string is NOT visible here. For the session door
    that residual must be held by the cage's egress firewall, not by this module."""
    out: list[str] = []
    for word in _SHELL_SPLIT_RE.split(text or ""):
        word = re.sub(r"[\"'\\]", "", word)
        if not word:
            continue
        word = re.sub(r"\{([0-9]+)\.\.([0-9]+)\}", r"\1-\2", word)
        word = re.sub(r"\{([0-9,]+)\}", r"\1", word)
        out.append(word)
        if "{" in word:
            out.extend(p for p in re.split(r"[{},]", word) if p)
    return out


def extract_hosts(text: str) -> list[str]:
    """Every host referenced in `text`, canonicalised and de-duplicated (order kept).
    See the module docstring for the classes of reference recognised. Conservative on
    bare dotted tokens so filenames/paths are not mistaken for hosts."""
    hosts: list[str] = []
    seen: set[str] = set()

    def add(h: str) -> None:
        h = (h or "").strip().lower()
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)

    for raw in _tokens(text):
        tok = _clean(raw)
        if not tok:
            continue

        # 1. URL token — the host is whatever the scheme points at (canonicalise it,
        #    so an IP-encoded URL host like http://0x08080808/ becomes 8.8.8.8).
        if "://" in tok:
            host = urlsplit(tok).hostname
            if host:
                add(canonical_ip(host) or host)
            continue

        # user@host argument (ssh user@evil.com, scp f user@evil.com:/p) — the host
        # is after the '@' (only when the user part isn't itself a path).
        if "@" in tok and "/" not in tok.split("@", 1)[0]:
            tok = tok.split("@", 1)[1]

        # 2. A NETWORK, not a host (SEC-001): CIDR or nmap octet range. Checked before
        #    the '/' path rule below, which used to swallow `10.10.10.0/24` as a path.
        nets = _network_targets(tok)
        if nets is not None:
            for n in nets:
                add(n)
            continue

        # 3. IP literal / integer / hex / octal encoding (checked before the :port
        #    trim so an IPv6 literal's own colons are not mangled).
        ip = canonical_ip(tok)
        if ip is not None:
            add(ip)
            continue

        # a bracketed IPv6 with a port and/or path ([2001:db8::1]:80/x; _clean has
        # already dropped the leading '[') -> the literal inside the brackets.
        if "]" in tok:
            ip = canonical_ip(tok.split("]", 1)[0])
            if ip is not None:
                add(ip)
            continue

        # 4. scheme-less host/path (SEC-002): `curl 10.10.10.11/x` reaches that host
        #    exactly as `curl http://10.10.10.11/x` does. The host is everything
        #    before the first '/'. A token that STARTS like a filesystem path
        #    (/etc, ./x, ../x, ~/x) has no host part and is skipped.
        if "/" in tok or "\\" in tok:
            if tok[0] in "/.~\\":
                continue
            tok = re.split(r"[/\\]", tok, maxsplit=1)[0]

        # a single trailing :port on a host (evil.com:8080, 10.10.10.11:80, and the
        # scp form host:) -> keep the host.
        base = tok.split(":", 1)[0] if tok.count(":") == 1 else tok
        if not base:
            continue

        # an IP with a :port (SEC-002: `curl 10.10.10.11:80` was never extracted,
        # because the dotted-hostname rule below rejects an all-numeric TLD).
        ip = canonical_ip(base)
        if ip is not None:
            add(ip)
            continue

        # 5. bare dotted hostname — conservative: reject known filenames.
        if _FILE_EXT_RE.search(base):
            continue
        if _DOTTED_HOST_RE.match(base):
            # Fail-closed: if it is host-shaped but urlsplit can't extract a name,
            # still hand the literal to the scope check (which will almost certainly
            # deny it) rather than silently dropping it.
            add(urlsplit("//" + base).hostname or base)

    return hosts
