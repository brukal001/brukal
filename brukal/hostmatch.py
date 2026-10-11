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

Tokens come from a quote-aware shell lexer: split on UNQUOTED whitespace/operators,
quotes and escapes removed, command substitutions lexed as commands, unquoted numeric
brace expansion rewritten (see ``_lex`` / ``_tokens``). Quoted text stays one word.

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


# Characters that are only special to bash OUTSIDE quotes. Inside quotes they are
# literal data — `-d '{"email":"a@b.io"}'` or `--eval "db.getSiblingDB('x')"` is ONE
# word, and splitting it would invent hosts (`b.io`, `db.getsiblingdb`) and DENY
# legitimate commands. Quoted brace/comma characters are carried through the lexer as
# placeholders so brace expansion — also unquoted-only — never touches them.
_QUOTED = {"{": "\x00", "}": "\x01", ",": "\x02"}
_UNQUOTED = {v: k for k, v in _QUOTED.items()}
_OPERATOR_CHARS = set(";|&<>()")
_PIPE = "\x04|"   # seps-mode marker: the next command reads the previous one's stdout
_BASH_BLANKS = " \t\n"   # bash's default IFS — NOT Python isspace() (U+2028 etc.)
_EXPANSION = "\x03"   # an unexpanded $VAR inside a word: content unknown, not a host


def _close_paren(text: str, i: int) -> int:
    """Index of the ')' closing the '(' at text[i] (quote-aware), or len(text)."""
    depth, quote, n = 0, None, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _lex(text: str, depth: int = 0, seps: bool = False) -> list:
    """Words of a shell line roughly as bash builds them: split on unquoted whitespace
    and control operators (`curl 10.10.10.11;id` reaches 10.10.10.11 — the operator glued
    to the host must not hide it); quotes and backslash escapes removed and adjacent
    pieces joined (`10.10.10."11"` and `1\0.10.10.11` are 10.10.10.11 to bash); an
    unquoted `$` ends a word (`curl${IFS}10.10.10.11`); and every command substitution
    — `$(...)` or backticks, unquoted or inside double quotes — lexed as a command of
    its own, so `echo "$(curl 10.10.10.11)"` still shows its host.

    With `seps=True` a None is emitted at every unquoted control operator (and before
    each substitution's words), so a caller can see where each simple command starts."""
    words: list[str] = []
    subs: list[str] = []
    cur: list[str] = []
    quote = None
    i, n = 0, len(text or "")

    def flush() -> None:
        if cur:
            words.append("".join(cur))
            cur.clear()

    while i < n:
        ch = text[i]
        if quote == "'":                              # single quotes: all literal
            if ch == "'":
                quote = None
            else:
                cur.append(_QUOTED.get(ch, ch))
            i += 1
            continue
        if ch == "\\" and i + 1 < n:                  # escape (unquoted or in "...")
            nxt = text[i + 1]
            cur.append(_QUOTED.get(nxt, nxt) if quote else nxt)
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            end = _close_paren(text, i + 1)
            subs.append(text[i + 2:end])
            flush()
            i = end + 1
            continue
        if ch == "`":
            end = text.find("`", i + 1)
            end = n if end < 0 else end
            subs.append(text[i + 1:end])
            flush()
            i = end + 1
            continue
        if quote == '"':                              # double quotes: literal but $( `
            if ch == '"':
                quote = None
            else:
                cur.append(_QUOTED.get(ch, ch))
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch in _OPERATOR_CHARS:
            flush()
            if seps:
                single_pipe = (ch == "|" and text[i + 1:i + 2] != "|"
                               and text[i - 1:i] != "|")
                words.append(_PIPE if single_pipe else None)
        elif ch == "$":
            # `$IFS` / `${IFS…}` expands to a word break (`curl${IFS}host`); any other
            # expansion (`$i`, `${URL}`) is opaque content INSIDE the current word —
            # kept as a placeholder so `…/orders/$i` never yields a word `i`.
            m = re.match(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9#?@*!$-])", text[i:])
            if m and re.match(r"\{?IFS\b", m.group(1)):
                flush()
            elif m:
                cur.append(_EXPANSION)
            else:
                cur.append(ch)
            i += m.end() if m else 1
            continue
        elif ch in _BASH_BLANKS:
            flush()
        else:
            cur.append(ch)
        i += 1
    flush()
    if depth < 8:                                     # bounded: nesting is not a DoS
        for sub in subs:
            if seps:
                words.append(None)
            words.extend(_lex(sub, depth + 1, seps))
    return words


def _tokens(text: str) -> list[str]:
    """Candidate host tokens of a command/session line: `_lex`'s words, with UNQUOTED
    numeric brace expansion rewritten as an nmap octet spec (`10.10.10.{10,11}` ->
    `10.10.10.10,11`, `{10..20}` -> `10-20`) so the range rule covers it, and a word
    with any other unquoted brace list also offered split at `{`, `,`, `}` (so
    `{10.10.10.11,x}` still yields 10.10.10.11).

    The plain whitespace split the gate always used is ALSO offered (union): it is
    what catches a host inside a quoted nested command (`bash -c 'curl 10.10.10.11'`,
    `ssh box 'curl …'`), which the lexer rightly keeps as one quoted word. The union
    means this function finds every host the original scan found (no governance
    regression) plus the lexer-only cases, while the lexer — being quote-aware — adds
    no hosts out of quoted data (no capability regression; replayed against the
    historical ALLOWed-command corpus).

    This is word-level parsing, not a bash interpreter: a host assembled at run time
    from a variable or a decoded string is NOT visible here. For the session door
    that residual must be held by the cage's egress firewall, not by this module."""
    out: list[str] = [w for w in re.split(r"\s+", text or "") if w]
    for word in _lex(text):
        if word is None or word == _PIPE:
            continue
        # A lexer word holding whitespace came from a quoted string with spaces — a
        # script or data (`python3 -c "…{'email':'a@b.io'}…"`), never ONE host argument.
        # Hosts inside it are still seen by the whitespace view above, as they always were.
        if any(c.isspace() for c in word):
            continue
        word = re.sub(r"\{([0-9]+)\.\.([0-9]+)\}", r"\1-\2", word)
        word = re.sub(r"\{([0-9,]+)\}", r"\1", word)
        pieces = [p for p in re.split(r"[{},]", word) if p] if "{" in word else []
        for w in [word, *pieces]:
            w = "".join(_UNQUOTED.get(c, c) for c in w)
            if w:
                out.append(w)
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
            # A comma-joined URL list (`-u http://a,http://b:8080`, the form scanners
            # take for several targets) is several URLs, each judged on its own host —
            # read whole, `a,http` was one bogus host and a valid list was DENIED.
            parts = [p for p in tok.split(",") if "://" in p] if tok.count("://") > 1 \
                else [tok]
            for part in parts:
                try:
                    host = urlsplit(part).hostname
                except ValueError:
                    host = part            # unparseable URL: hand it to the scope check
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
        #    A token with a backslash is skipped as before — that is an escape inside
        #    quoted data (`-d "{\\"email\\":\\"a@b.io\\"}"`), not a path to a host.
        if "\\" in tok:
            continue
        if "/" in tok:
            if tok[0] in "/.~":
                continue
            tok = tok.split("/", 1)[0]

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

    # 6. SEC-003: dotless / loopback names in host positions of known network tools.
    for h in tool_position_hosts(text):
        add(h)

    return hosts


# --------------------------------------------------------------------------------- #
# SEC-003 — dotless / loopback hosts in HOST POSITIONS of known network tools.
#
# A bare word like `intranet`, `crapi-identity` or `localhost` resolves (cage DNS,
# Docker service names, /etc/hosts) to a host, but it is indistinguishable from an
# ordinary word (`cat flag`, `-X GET`, `--script vuln`, a `Host:` header value). So
# such names are read ONLY where a tool actually connects to its argument — nmap
# targets, a curl/wget URL, an ssh destination, an nc host, a proxy option, `-u` of a
# URL scanner, `--host` of a DB client, an ssh tunnel's target — never in header or
# data values. A word in a host position that is not an option's value is a target.
#
# Each entry: (positional policy, options taking a value, options whose value is a
# HOST). Policies: "all" (every positional is a target), "first" (only the first —
# what follows is a remote command / service), "none" (targets come only via
# host options). An option missing from the value set can only cause a false DENY
# (fail-closed), never a miss; tools with "none" cannot false-DENY that way at all.
# --------------------------------------------------------------------------------- #

_LOOPBACK_NAMES = {"localhost": "127.0.0.1", "localhost.localdomain": "127.0.0.1",
                   "ip6-localhost": "::1", "ip6-loopback": "::1"}


def loopback_ip(name: str) -> str | None:
    """The loopback IP a loopback NAME always denotes (RFC 6761: `localhost` and every
    `*.localhost`), or None. Lets the gate judge `localhost` as 127.0.0.1."""
    n = (name or "").strip().lower().rstrip(".")
    if n in _LOOPBACK_NAMES:
        return _LOOPBACK_NAMES[n]
    if n.endswith(".localhost"):
        return "127.0.0.1"
    return None


def _opts(s: str) -> frozenset:
    return frozenset(s.split())


_CURL_VALUE = _opts(
    "-H --header -d --data --data-raw --data-binary --data-urlencode --data-ascii --json "
    "-F --form --form-string -o --output -X --request -A --user-agent -e --referer -u "
    "--user -b --cookie -c --cookie-jar -m --max-time --connect-timeout -w --write-out "
    "-T --upload-file -K --config -r --range -C --continue-at -y --speed-time -Y "
    "--speed-limit --limit-rate --retry --retry-delay --retry-max-time --max-redirs "
    "--max-filesize --cacert --capath --cert -E --key --key-type --cert-type --pass "
    "--ciphers --tls-max --interface --local-port --dns-servers --dns-interface "
    "--oauth2-bearer --proxy-user -U --proxy-header --request-target --unix-socket "
    "--abstract-unix-socket --noproxy -Q --quote --trace --trace-ascii --stderr -D "
    "--dump-header --pinnedpubkey --mail-from --mail-rcpt --mail-auth -z --time-cond "
    "--aws-sigv4 --variable --etag-save --etag-compare --output-dir --expect100-timeout "
    "--keepalive-time --resolve --connect-to -P --ftp-port --telnet-option -t "
    "--proto --proto-redir --proto-default --sasl-authzid --service-name --hostpubmd5 "
    "--hostpubsha256 --crlfile --egd-file --random-file --engine --delegation "
    "--happy-eyeballs-timeout-ms --parallel-max --rate --create-file-mode")
_CURL_HOST = _opts("-x --proxy --preproxy --socks4 --socks4a --socks5 --socks5-hostname "
                   "--url")

_NMAP_VALUE = _opts(
    "-p -e -S -D -g -iL -iR -oN -oX -oS -oG -oA -oM -b --script --script-args "
    "--script-args-file --script-help --script-timeout --top-ports --port-ratio "
    "--max-retries --host-timeout --min-rate --max-rate --exclude --excludefile "
    "--exclude-ports --data --data-string --data-length --ttl --spoof-mac "
    "--version-intensity --scan-delay --max-scan-delay --mtu --dns-servers "
    "--min-hostgroup --max-hostgroup --min-parallelism --max-parallelism "
    "--min-rtt-timeout --max-rtt-timeout --initial-rtt-timeout --stats-every --resume "
    "--stylesheet --datadir --servicedb --versiondb --ip-options --source-port "
    "--scanflags -sI --proxies --proxy")
_NMAP_HOST = _opts("-sI --proxies --proxy")

_TOOLS: dict[str, tuple[str, frozenset, frozenset]] = {
    "curl": ("all", _CURL_VALUE, _CURL_HOST),
    "wget": ("all", _opts(
        "-O --output-document -o --output-file -a --append-output -U --user-agent "
        "--header --post-data --post-file --body-data --body-file --method -t --tries "
        "-T --timeout -w --wait -P --directory-prefix -l --level -A --accept -R --reject "
        "-D --domains --exclude-domains -I -X --user --password --http-user "
        "--http-password --load-cookies --save-cookies -i --input-file -B --base "
        "--bind-address --limit-rate -Q --quota -e --execute --ca-certificate "
        "--certificate --private-key --referer --dns-timeout --connect-timeout "
        "--read-timeout --waitretry --restrict-file-names --default-page"), frozenset()),
    "nmap": ("all", _NMAP_VALUE, _NMAP_HOST),
    "masscan": ("all", _opts(
        "-p --ports --rate --max-rate -oX -oL -oJ -oG -oB --source-ip --source-port "
        "--router-mac --adapter -e --exclude --excludefile -iL --wait --ttl --retries "
        "--connection-timeout -c --conf --resume --shard --seed --output-format "
        "--output-filename --interface --adapter-ip --adapter-mac --ping"), frozenset()),
    "whatweb": ("all", _opts(
        "-a --aggression -U --user-agent -H --header -p --plugins --log-brief "
        "--log-verbose --log-json --log-xml --log-object --log-errors -i --input-file "
        "--url-prefix --url-suffix --url-pattern --max-threads -t --open-timeout "
        "--read-timeout --wait --max-redirects --cookie -c --cookiejar --user -u "
        "--proxy --proxy-user --color --colour -e --extra --header"), _opts("--proxy")),
    "sslscan": ("all", _opts("--xml --sni-name --certs --ipv4 --ipv6"), frozenset()),
    "ping": ("all", _opts("-c -i -W -w -s -t -I -p -Q -l -m -M -S"), frozenset()),
    "traceroute": ("all", _opts("-f -m -N -p -q -s -t -w -z -i -g -M -A"), frozenset()),
    "nc": ("all", _opts(
        "-p -s -w -i -q -e -c -x -X -O -I -T -g -G -o --output -m --max-conns "
        "--proxy --proxy-type --proxy-auth --sh-exec --exec --ssl-cert --ssl-key "
        "--allow --deny --allowfile --denyfile"), _opts("-x --proxy")),
    "ssh": ("first", _opts(
        "-p -i -l -o -F -L -R -D -J -W -b -c -m -E -e -O -Q -S -w -B -I"),
        _opts("-J")),
    "telnet": ("first", _opts("-l -b -e -n"), frozenset()),
    "ftp": ("first", _opts("-P -s"), frozenset()),
    "dirb": ("first", _opts("-a -c -H -o -p -P -r -u -X -x -z"), frozenset()),
    "hydra": ("first", _opts(
        "-l -L -p -P -C -M -o -b -s -t -T -w -W -c -m -x -e"), frozenset()),
    "smbclient": ("first", _opts(
        "-U --user -W --workgroup -p --port -I --ip-address -c --command -D --directory "
        "-A --authentication-file -m --max-protocol -n --netbiosname -s --configfile "
        "-L --list -O -T -t"), _opts("-L --list")),
    "nikto": ("none", frozenset(), _opts("-h -host")),
    "nuclei": ("none", frozenset(), _opts("-u -target")),
    "ffuf": ("none", frozenset(), _opts("-u")),
    "gobuster": ("none", frozenset(), _opts("-u --url")),
    "feroxbuster": ("none", frozenset(), _opts("-u --url")),
    "sqlmap": ("none", frozenset(), _opts("-u --url")),
    "httpx": ("none", frozenset(), _opts("-u")),
    "mongo": ("none", frozenset(), _opts("--host")),
    "mongosh": ("none", frozenset(), _opts("--host")),
    "mysql": ("none", frozenset(), _opts("-h --host")),
    "psql": ("none", frozenset(), _opts("-h --host")),
    "redis-cli": ("none", frozenset(), _opts("-h")),
}
for _alias, _real in (("ncat", "nc"), ("netcat", "nc"), ("ping6", "ping"),
                      ("traceroute6", "traceroute"), ("tracepath", "traceroute")):
    _TOOLS[_alias] = _TOOLS[_real]

# Options whose value is a forward/tunnel spec ending in host:port — the host there is
# contacted (from wherever the tool runs). `ssh -L 8080:intranet:80`, `curl
# --connect-to a:80:intranet:80`, `curl --resolve a:80:10.10.10.11`.
_SPEC_HOST_FIELD = {("ssh", "-L"): -2, ("ssh", "-R"): -2, ("curl", "--connect-to"): -2,
                    ("curl", "--resolve"): -1}

_SHELLS = _opts("bash sh zsh dash ksh ash")

# Wrappers that run the command after them, and the options each takes a value for.
_WRAPPERS = {
    "sudo": _opts("-u -g -C -p -U -r -t -T -D -h"), "doas": _opts("-u -C"),
    "env": _opts("-u -C -S"), "timeout": _opts("-s -k --signal --kill-after"),
    "nice": _opts("-n"), "nohup": frozenset(), "stdbuf": _opts("-i -o -e"),
    "time": frozenset(), "exec": frozenset(), "command": frozenset(),
    "proxychains": _opts("-f"), "proxychains4": _opts("-f"),
    "sshpass": _opts("-p -f -d -P"), "watch": _opts("-n -d"),
}
_WRAPPER_POSITIONAL = {"timeout": 1, "nice": 0}   # timeout DURATION cmd...
# Shell keywords that may precede a command in the same simple-command slot.
_KEYWORDS = _opts("do then else elif if while until ! { }")

# One DNS label (<= 63 chars): a longer bare word can never resolve, so it is not a host.
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
_VAR_PREFIX_RE = re.compile(r"\A\{[A-Za-z_][A-Za-z0-9_]*\}")    # left by ${IFS}


def _host_of_arg(arg: str) -> str:
    """The host a host-position argument names: scheme and user stripped, then the part
    before any '/' path and ':port'. '' if there is none."""
    a = _VAR_PREFIX_RE.sub("", arg.strip())
    if "://" in a:
        return urlsplit(a).hostname or ""
    if a.startswith("//"):                         # UNC: //host/share
        a = a[2:]
    if "@" in a:
        a = a.rsplit("@", 1)[1]
    a = a.split("/", 1)[0]
    if a.startswith("["):                          # [v6]:port
        return a[1:].split("]", 1)[0]
    if a.count(":") == 1:
        a = a.split(":", 1)[0]
    return a


def _emit(arg: str, out: list, variables: list | None = None) -> None:
    """Report a host-position argument when it names a dotless or loopback host — the
    shapes the generic scan cannot safely see. (Dotted names, IPs and URLs are already
    found by extract_hosts' generic rules.) A host position whose host part is a shell
    variable goes to `variables`: its value is unknowable here (SEC-008)."""
    raw = _host_of_arg(arg)
    if variables is not None and _EXPANSION in (raw or arg.split("/", 1)[0]):
        variables.append(arg.replace(_EXPANSION, "$VAR"))
        return
    h = raw.lower().rstrip(".")
    if not h or h.isdigit():
        return                                     # a port / count, not a host
    if loopback_ip(h) or _LABEL_RE.match(h):
        out.append(h)


def _skip_prefix(words: list) -> int:
    """Index of the real command word: past VAR=value assignments, shell keywords and
    wrappers (sudo, timeout 5, env X=1, ...)."""
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        if ("=" in w and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", w)) or w in _KEYWORDS:
            i += 1
            continue
        tool = w.rsplit("/", 1)[-1]
        if tool not in _WRAPPERS:
            break
        values, i = _WRAPPERS[tool], i + 1
        skip_pos = _WRAPPER_POSITIONAL.get(tool, 0)
        while i < n and words[i].startswith("-"):
            i += 2 if (words[i] in values and "=" not in words[i]) else 1
        while i < n and skip_pos:
            i, skip_pos = i + 1, skip_pos - 1
    return i


def _command_hosts(words: list, out: list, depth: int, variables: list | None = None
                   ) -> None:
    """Host-position arguments of ONE simple command (already split into words).
    A host position holding a shell variable is reported to `variables` (SEC-008)."""
    i, n = _skip_prefix(words), len(words)
    if i >= n:
        return
    tool = words[i].rsplit("/", 1)[-1]
    rest = words[i + 1:]

    if depth < 4 and (tool in _SHELLS or tool == "eval"):
        if tool == "eval":
            _line_hosts(" ".join(rest), out, depth + 1, variables)
        else:
            for k, w in enumerate(rest[:-1]):
                if w in ("-c", "-lc", "-ic", "-xc"):
                    _line_hosts(rest[k + 1], out, depth + 1, variables)
                    break
        return

    spec = _TOOLS.get(tool)
    if spec is None:
        return
    policy, values, host_opts = spec
    positional: list[str] = []
    k = 0
    while k < len(rest):
        w = rest[k]
        if w == "--":
            positional.extend(rest[k + 1:])
            break
        if w.startswith("-") and len(w) > 1:
            opt, eq, val = w.partition("=")
            if not eq and (opt in values or opt in host_opts) and k + 1 < len(rest):
                val, k = rest[k + 1], k + 1
                eq = "="
            if eq:
                field = _SPEC_HOST_FIELD.get((tool, opt))
                if field is not None:
                    parts = val.split(":")
                    if len(parts) >= -field:
                        _emit(parts[field], out, variables)
                elif opt in host_opts:
                    _emit(val, out, variables)
            k += 1
            continue
        positional.append(w)
        k += 1

    if tool == "hydra" and "-M" in rest:
        positional = []                # with -M the positional is the SERVICE (ssh)
    if policy == "all":
        targets = positional
    elif policy == "first":
        targets = positional[:1]
    else:
        targets = []
    for t in targets:
        _emit(t, out, variables)
    if tool == "ssh" and len(positional) > 1 and depth < 4:
        # the remote command runs FROM the box — a pivot is still a host it reaches
        _line_hosts(" ".join(positional[1:]), out, depth + 1, variables)


def _line_hosts(text: str, out: list, depth: int = 0, variables: list | None = None
                ) -> None:
    cmd: list[str] = []
    for w in _lex(text, seps=True) + [None]:
        if w is None or w == _PIPE:
            if cmd:
                _command_hosts(cmd, out, depth, variables)
            cmd = []
        else:
            cmd.append(w)


def tool_position_hosts(text: str) -> list[str]:
    """SEC-003: dotless and loopback host names in host positions of known network
    tools (see the block comment above). Order kept, de-duplicated."""
    out: list[str] = []
    _line_hosts(text or "", out)
    seen: set[str] = set()
    return [h for h in out if not (h in seen or seen.add(h))]


# --------------------------------------------------------------------------------- #
# SEC-008 — targets the gate cannot SEE.
#
# The scope check judges every host written in the command. Some forms choose targets
# that are not written there at all: a target-list file (`nmap -iL`, `nuclei -l`), a
# request/config file that carries the host (`sqlmap -r`, `curl -K`), a random or
# search-engine source (`nmap -iR`, `sqlmap -g`, `nuclei -uncover`), stdin (`cat hosts |
# httpx`, `... | xargs curl`), or a shell variable in a host position (`curl $T`).
# None can be placed in scope, so the gate denies them (fail-closed) — and says how to
# restate the command with the targets written out, so capability is one retry away.
# --------------------------------------------------------------------------------- #

_UNSEEN_OPTS: dict[str, frozenset] = {
    "nmap": _opts("-iR -iL --resume"),
    "masscan": _opts("-iL --includefile -c --conf --resume"),
    "nuclei": _opts("-l -list -resume -uncover -uc"),
    "httpx": _opts("-l -list"),
    "naabu": _opts("-l -list"),
    "katana": _opts("-l -list"),
    "wget": _opts("-i --input-file"),
    "curl": _opts("-K --config"),
    "whatweb": _opts("-i --input-file"),
    "sqlmap": _opts("-r -m -l -g -c"),
    "hydra": _opts("-M"),
}
_ATTACHED_OK = _opts("-iR -iL")             # nmap also accepts -iLfile
_STDIN_TARGET_TOOLS = _opts("httpx nuclei naabu katana")
_EXPLICIT_TARGET_OPTS = _opts("-u -target -host")
_FANOUT = _opts("xargs parallel")


def _command_unseen(words: list, piped: bool, out: list, depth: int) -> None:
    i = _skip_prefix(words)
    if i >= len(words):
        return
    tool = words[i].rsplit("/", 1)[-1]
    rest = words[i + 1:]
    if depth < 4 and (tool in _SHELLS or tool == "eval"):
        if tool == "eval":
            _line_unseen(" ".join(rest), out, depth + 1)
        else:
            for k, w in enumerate(rest[:-1]):
                if w in ("-c", "-lc", "-ic", "-xc"):
                    _line_unseen(rest[k + 1], out, depth + 1)
                    break
        return
    if tool in _FANOUT:
        inner = [w for w in rest if not w.startswith("-")]
        if any(w.rsplit("/", 1)[-1] in _TOOLS or w.rsplit("/", 1)[-1] in _UNSEEN_OPTS
               for w in inner):
            out.append(f"{tool} feeding a network tool its targets from stdin")
        return
    for w in rest:
        opt = w.split("=", 1)[0]
        bad = _UNSEEN_OPTS.get(tool, frozenset())
        if opt in bad or any(w.startswith(a) and len(w) > len(a) and tool == "nmap"
                             for a in _ATTACHED_OK):
            out.append(f"{tool} {opt if opt in bad else w[:3]}")
    if tool == "nikto":
        for k, w in enumerate(rest[:-1]):
            if w in ("-h", "-host"):
                v = rest[k + 1]
                if "://" not in v and ("/" in v or _FILE_EXT_RE.search(v)):
                    out.append(f"nikto {w} <file>")
    if piped and tool in _STDIN_TARGET_TOOLS and not any(
            w.split("=", 1)[0] in _EXPLICIT_TARGET_OPTS for w in rest):
        out.append(f"{tool} reading its targets from stdin")


def _line_unseen(text: str, out: list, depth: int = 0) -> None:
    cmd: list[str] = []
    piped = next_piped = False
    for w in _lex(text, seps=True) + [None]:
        if w is None or w == _PIPE:
            if cmd:
                _command_unseen(cmd, piped, out, depth)
            cmd = []
            piped = next_piped = (w == _PIPE)
        else:
            if not cmd:
                piped = next_piped
            cmd.append(w)


def unseen_targets(text: str) -> list[str]:
    """SEC-008: every way `text` picks targets the scope check cannot see — target-list
    / request / config files, random or search-engine sources, stdin-fed scanners,
    fan-out, and shell variables in host positions. Empty means every target is
    written in the command (and so is judged by extract_hosts)."""
    out: list[str] = []
    _line_unseen(text or "", out)
    variables: list[str] = []
    _line_hosts(text or "", [], 0, variables)
    out.extend(f"variable target {v}" for v in variables)
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]
