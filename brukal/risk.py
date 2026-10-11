"""
risk.py — Milestone 3: the SOFT risk layer (Layer 2 of the Trust Governance Plane).

Runs ONLY after the deterministic hard gate has already confirmed an action is
in-scope, allowlisted, injection-free and under the rate limit. It therefore
**cannot widen scope or overturn a hard DENY** — it can only add caution: leave a
safe action ALLOWed, raise a broad-or-irreversible one to ESCALATE (human
sign-off), or refuse one that crosses the risk ceiling (DENY).

Like the hard gate, this layer contains **no language model**. Reversibility and
blast radius are derived deterministically from the *command text itself* — never
from the agent's self-declared `intent` (invariant 3) — so the soft layer is as
untrickable as the hard one (invariant 1). Anything it cannot classify is treated
as *more* dangerous, never less (invariant 2, fail-closed).

Two scalar risk features, each in {0,1,2}, are summed into a 0–4 score:

    reversibility : reversible(0)  < unknown(1)  < irreversible(2)
    blast_radius  : host(0)        < subnet(1)   < wide(2)

    score <= THETA_LOW (0)      -> LOW    -> ALLOW
    THETA_LOW < score <= THETA_HIGH (2) -> MEDIUM -> ESCALATE
    score >  THETA_HIGH (2)     -> HIGH   -> DENY

Milestone 6 will feed an *adaptive per-agent trust* value into `assess` (lower
trust => more caution). Milestone 3 uses the neutral default `trust=1.0`, which
adds nothing, so M3's behaviour is a pure function of the command.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

# ---- feature vocabulary (ordered least -> most risky) ----------------------
_REVERSIBILITY = ("reversible", "unknown", "irreversible")
_BLAST = ("host", "subnet", "wide")
_REV_WEIGHT = {"reversible": 0, "unknown": 1, "irreversible": 2}
_BLAST_WEIGHT = {"host": 0, "subnet": 1, "wide": 2}

# ---- decision thresholds ----------------------------------------------------
THETA_LOW = 0    # score <= THETA_LOW              -> ALLOW
THETA_HIGH = 2   # THETA_LOW < score <= THETA_HIGH -> ESCALATE ; above -> DENY
_TRUST_SCALE = 2  # a fully-distrusted agent (trust=0) adds +2 to every score

# ---- what the current allowlist can do -------------------------------------
# Tools that observe but do not change target state. Traffic *volume* is a
# blast-radius concern (handled below), not a reversibility one.
_READ_ONLY_TOOLS = frozenset(
    {  # --- read-only enumeration across the Kali arsenal. These ALLOW on a single
       # host. Write-capable / interactive ones are deliberately absent, so they
       # score "unknown" and the soft layer escalates them to a human.
     "nmap", "masscan", "curl", "wget", "ping", "fping", "arp-scan", "netdiscover",
     # web content / vuln enumeration
     "gobuster", "ffuf", "feroxbuster", "dirb", "dirsearch", "wfuzz", "gau",
     "nikto", "whatweb", "wafw00f", "nuclei", "wpscan", "joomscan", "droopescan",
     "httpx", "waybackurls", "katana", "hakrawler", "cewl",
     # dns / osint recon
     "dig", "host", "nslookup", "whois", "dnsrecon", "dnsenum", "fierce",
     "dnsx", "subfinder", "sublist3r", "amass", "assetfinder", "theharvester",
     # smb / netbios / rpc (read-only surface)
     "smbmap", "enum4linux", "enum4linux-ng", "nbtscan", "rpcclient", "nmblookup",
     # snmp / ldap / other services (read)
     "snmpwalk", "snmp-check", "onesixtyone", "ldapsearch", "showmount",
     # tls / ssh posture
     "sslscan", "sslyze", "testssl", "testssl.sh", "ssh-audit",
     # local lookups
     "searchsploit", "hashid", "hash-identifier", "hashcat-utils", "dnsutils"}
)

# Tools that actively ATTACK a target (brute force, exploitation, cracking,
# shells). They are ALLOWLISTED — an operator can use them — but they are always
# IRREVERSIBLE, so the soft layer routes them to human sign-off (ESCALATE) on a
# single host and refuses them (DENY) once the blast radius widens. Capability
# grows; the safety boundary does not.
_ATTACK_TOOLS = frozenset(
    {"hydra", "medusa", "ncrack", "patator", "crowbar", "brutespray",  # credential brute force
     "sqlmap", "commix", "nosqlmap", "tplmap",        # active injection/exploitation
     "crackmapexec", "netexec", "nxc", "kerbrute", "responder", "mitm6", "evil-winrm",
     "impacket-secretsdump", "impacket-psexec", "impacket-smbexec",
     "impacket-wmiexec", "impacket-getuserspns", "impacket-getnpusers",
     "impacket-ntlmrelayx", "smbexec", "wmiexec", "psexec",
     "john", "hashcat",                               # offline cracking
     "msfconsole", "msfvenom", "metasploit", "msf",   # exploitation framework
     "setoolkit", "beef", "beef-xss",                 # social eng / xss framework
     "aircrack-ng", "reaver", "wifite", "bully",      # wireless attack
     "ettercap", "bettercap", "arpspoof", "dsniff",   # mitm / sniffing attack
     "hping3", "slowhttptest", "slowloris", "t50",    # flood / dos
     "sshpass",                                       # scripted auth
     "ftp", "tftp", "rsh", "rlogin",                  # interactive access (smbclient
                                                      # left "unknown" -> still escalates)
     "nc", "ncat", "netcat", "socat", "chisel", "ligolo"}  # shells / pivots / transfer
)

# Signals that an action WRITES / ATTACKS remote state -> irreversible.
_HTTP_WRITE_METHODS = {"post", "put", "delete", "patch"}
_CURL_BODY_FLAGS = {"-d", "--data", "--data-raw", "--data-binary",
                    "--data-urlencode", "-T", "--upload-file"}
_IRREVERSIBLE_SCRIPT_CATS = {"exploit", "dos", "intrusive", "malware"}

# SEC-009 — spellings the exact-token checks above missed.
_CURL_WRITE_LONG = ("--data", "--data-raw", "--data-binary", "--data-urlencode",
                    "--data-ascii", "--json", "--form", "--form-string", "--upload-file")
# curl short options that take a VALUE: in a cluster like `-sSd x` everything after the
# first of these is its value, so only letters before it are flags.
_CURL_SHORT_VALUE = set("dFTHoXuAbcemwxKrCEyYzUPQDt")
_CURL_SHORT_WRITE = set("dFT")
_WGET_WRITE = ("--post-data", "--post-file", "--body-data", "--body-file")
_SAFE_HTTP_METHODS = {"get", "head", "options"}
# nmap script NAMES (not categories) that are intrusive by their own description.
_RISKY_SCRIPT_NAME_RE = re.compile(
    r"dos|slowloris|flood|brute|exploit|vuln|shellshock|backdoor|cve-?\d|ms\d\d-|rce|"
    r"overflow|fuzz")
_SCRIPT_EXPR_WORDS = {"not", "and", "or"}
# nmap's own categories keep their designed meaning (e.g. `vuln` is aggressive, not
# irreversible); the name pattern above applies only to script NAMES.
_NMAP_CATEGORIES = {"auth", "broadcast", "brute", "default", "discovery", "dos",
                    "exploit", "external", "fuzzer", "intrusive", "malware", "safe",
                    "version", "vuln"}

# Signals that widen the blast radius even against a single host.
_AGGRESSIVE_TOKENS = {"-p-", "-A", "-T4", "-T5"}
_AGGRESSIVE_SCRIPT_CATS = {"vuln", "brute", "all",
                           "exploit", "dos", "intrusive", "malware"}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/(\d{1,2})\b")
_DASH_RANGE_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\b")


@dataclass(frozen=True)
class RiskProfile:
    """Deterministic soft-risk assessment of one command."""
    reversibility: str   # "reversible" | "unknown" | "irreversible"
    blast_radius: str    # "host" | "subnet" | "wide"
    score: int           # 0..(4 + trust penalty)
    band: str            # "LOW" | "MEDIUM" | "HIGH"
    decision: str        # "ALLOW" | "ESCALATE" | "DENY"
    reason: str


def _tokens(command: str) -> list[str]:
    """Best-effort shell tokenisation. Fail-closed: unparseable -> empty list,
    which the callers treat as maximally risky (unknown + wide)."""
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _script_categories(tokens: list[str]) -> set[str]:
    """Categories named in an nmap `--script <cats>` / `--script=<cats>` arg.

    SEC-009: the value is an EXPRESSION, not a word list — `not safe`, `+exploit`,
    `(exploit or dos)`, `http-*`, a script name like `http-slowloris`, or a path to a
    custom .nse file. Anything that can select intrusive scripts without naming the
    category is reported as the categories it can reach ("intrusive" / "all"), so the
    callers below treat it as irreversible and aggressive. Named safe scripts and safe
    categories are reported as before."""
    cats: set[str] = set()
    for i, tok in enumerate(tokens):
        val = None
        if tok == "--script" and i + 1 < len(tokens):
            val = tokens[i + 1]
        elif tok.startswith("--script="):
            val = tok.split("=", 1)[1]
        if val:
            for part in re.split(r"[,\s()]+", val.lower()):
                part = part.lstrip("+")
                if not part:
                    continue
                cats.add(part)
                if part in _SCRIPT_EXPR_WORDS or "*" in part or part == "all":
                    cats.update({"intrusive", "all"})      # can select anything
                elif "/" in part or part.endswith(".nse"):
                    cats.add("intrusive")                   # custom script: arbitrary code
                elif part not in _NMAP_CATEGORIES and _RISKY_SCRIPT_NAME_RE.search(part):
                    cats.add("intrusive")
    return cats


def _strip_wrappers(tokens: list[str]) -> list[str]:
    """The command after any wrapper/assignment prefix (`timeout 9`, `sudo`, `env X=1`,
    `nice -n 5`, ...). Same deterministic prefix rule the scope gate uses."""
    from .hostmatch import _skip_prefix
    return tokens[_skip_prefix(tokens):]


def _curl_writes(tokens: list[str]) -> bool:
    """Does this curl invocation send a body or a non-safe method, in any spelling?"""
    for i, t in enumerate(tokens):
        low = t.lower()
        if low in _CURL_BODY_FLAGS or low in _CURL_WRITE_LONG or low == "--json":
            return True
        if any(low.startswith(f + "=") for f in _CURL_WRITE_LONG):
            return True
        method = None
        if low in ("-x", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1]
        elif low.startswith("--request="):
            method = t.split("=", 1)[1]
        elif t.startswith("-") and not t.startswith("--") and len(t) > 1:
            for k, ch in enumerate(t[1:], start=1):        # short-option cluster
                if ch in _CURL_SHORT_WRITE:
                    return True
                if ch == "X":
                    method = t[k + 1:] or (tokens[i + 1] if i + 1 < len(tokens) else "")
                    break
                if ch in _CURL_SHORT_VALUE:
                    break
        if method is not None and method.lower() in _HTTP_WRITE_METHODS:
            return True
    return False


def _wget_writes(tokens: list[str]) -> bool:
    for i, t in enumerate(tokens):
        low = t.lower()
        if low in _WGET_WRITE or any(low.startswith(f + "=") for f in _WGET_WRITE):
            return True
        method = None
        if low == "--method" and i + 1 < len(tokens):
            method = tokens[i + 1]
        elif low.startswith("--method="):
            method = t.split("=", 1)[1]
        if method is not None and method.lower() not in _SAFE_HTTP_METHODS:
            return True
    return False


def derive_reversibility(command: str) -> str:
    """Does this command change remote state? Read-only recon -> reversible;
    writes / active exploitation -> irreversible; anything unrecognised ->
    unknown (fail toward caution)."""
    tokens = _tokens(command)
    if not tokens:
        return "unknown"
    inner = _strip_wrappers(tokens)
    if inner is not tokens and len(inner) != len(tokens):
        # SEC-009: a wrapper must never LOWER risk. Judge the wrapped command, and keep
        # the wrapper's own "unknown" as a floor — so `timeout 9 nmap --script exploit`
        # is as irreversible as the bare command, and `sudo nmap -sV` stays unknown.
        if not inner:
            return "unknown"
        rev = derive_reversibility(" ".join(shlex.quote(t) for t in inner))
        return max(rev, "unknown", key=_REV_WEIGHT.__getitem__)
    tool = os.path.basename(tokens[0]).lower()

    if tool == "curl" and _curl_writes(tokens):
        return "irreversible"

    if tool == "wget" and _wget_writes(tokens):
        return "irreversible"

    if tool == "nmap":
        if _script_categories(tokens) & _IRREVERSIBLE_SCRIPT_CATS:
            return "irreversible"

    if tool in _ATTACK_TOOLS:
        return "irreversible"          # brute/exploit/shell -> always needs sign-off
    if tool in _READ_ONLY_TOOLS:
        return "reversible"
    return "unknown"


def derive_blast_radius(command: str) -> str:
    """How much surface does this command touch? One host -> host; a small
    range / several hosts -> subnet; a large network or aggressive breadth
    modifiers -> wide."""
    tokens = _tokens(command)
    idx = 0  # host

    if len({ip for ip in _IPV4_RE.findall(command)}) > 1:
        idx = max(idx, 1)  # several distinct hosts

    for prefix_s in _CIDR_RE.findall(command):
        prefix = int(prefix_s)
        idx = max(idx, 2 if prefix <= 24 else 1)  # <=/24 is wide, /25.. is subnet

    if _DASH_RANGE_RE.search(command):
        idx = max(idx, 1)

    # `-A` is nmap's "aggressive" (OS + scripts + traceroute). For curl/wget it is the
    # User-Agent / accept list and touches nothing more, so it is read as aggressive
    # only on nmap — it used to escalate every `curl -A <ua>` for human sign-off.
    inner = _strip_wrappers(tokens)
    is_nmap = bool(inner) and os.path.basename(inner[0]).lower() == "nmap"
    aggressive = any(t in _AGGRESSIVE_TOKENS and (t != "-A" or is_nmap) for t in tokens) \
        or bool(_script_categories(tokens) & _AGGRESSIVE_SCRIPT_CATS)
    if aggressive:
        idx = min(idx + 1, 2)  # bump one band, capped at wide

    return _BLAST[idx]


def _clamp01(x: float) -> float:
    """Clamp to [0, 1]. NaN (every comparison False) is unreadable trust -> 0.0, the
    most cautious value (SEC-010: it used to pass through and crash round())."""
    if x != x:
        return 0.0
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def assess(command: str, *, trust: float = 1.0) -> RiskProfile:
    """Deterministically assess one command and return its RiskProfile.

    `trust` in [0,1] is the milestone-6 adaptive-trust hook: at the default 1.0
    it adds nothing; lower values add a caution penalty so a distrusted agent's
    same action lands in a higher risk band. The soft layer only ever tightens.
    """
    rev = derive_reversibility(command)
    blast = derive_blast_radius(command)
    score = _REV_WEIGHT[rev] + _BLAST_WEIGHT[blast]
    score += round((1.0 - _clamp01(trust)) * _TRUST_SCALE)

    if score <= THETA_LOW:
        band, decision = "LOW", "ALLOW"
    elif score <= THETA_HIGH:
        band, decision = "MEDIUM", "ESCALATE"
    else:
        band, decision = "HIGH", "DENY"

    reason = (f"reversibility={rev}, blast={blast}, "
              f"risk_score={score} -> {band}")
    return RiskProfile(rev, blast, score, band, decision, reason)
