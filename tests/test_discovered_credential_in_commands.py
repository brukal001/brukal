"""
test_discovered_credential_in_commands.py — the leak is the COMMAND surface.

THE MEASURED PROBLEM (runs CM3, CM4, CM5)
    Three bundles are unpublishable and none of them leaked through a captured response
    body. CM4 and CM5 quantified it:

      | surface                                   | CM4 | CM5 |
      | credential-like values in captured bodies |  0  |  0  |
      | MD5-shaped strings in captured bodies     |  0  |  0  |
      | the admin hash / token in the agent's own |     |     |
      |   execution + decision records            | yes | yes |

    The agent recovered `0192023a7bbd73250516f069df18b500` from the target via SQLi and
    then typed it into `md5sum` and `hashcat` commands. `2b7e671` closed this class for
    SELF-DESCRIBING credentials only — `observe()` registers a string that actually
    DECODES as a JWT — and an MD5 hash describes nothing.

THE PROPERTY
    A value the agent RECOVERS from the target and then carries in a command it authored
    is a discovered credential, and is masked in the record with its structure preserved,
    exactly as an injected credential is.

THE ATTRIBUTION RULE, and why it is not guessing
    A scalar is a discovered credential when THE TARGET'S OWN RESPONSE LABELLED IT with a
    secret-denoting key. This is the discipline `own_identifiers` already uses for the
    other direction (`_ID_KEY_RE`: a key qualifies because the response used that name).
    The value's characters are never inspected: `0192023a…` under `"password"` registers;
    the identical string under `"id"` does not. Registration happens on TARGET OUTPUT
    only — never on agent input, or the agent's own guess payloads would be masked and
    the record of what it tried destroyed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, redact
from brukal.kali import ExecResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

# CM3/CM4/CM5's actual value.
ADMIN_HASH = "0192023a7bbd73250516f069df18b500"
ADMIN_JWT = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
             "eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIn19."
             "c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVlLWxvbmctZW5vdWdo")


class _Kali:
    """Returns whatever the test hands it, as the cage would."""

    def __init__(self, out=""):
        self.out = out
        self.seen: list[str] = []

    def run(self, command):
        self.seen.append(command)
        return ExecResult(command, 0, self.out, "")


def _executor(tmp_path, out=""):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    kali = _Kali(out)
    return Executor(Gate(scope), kali, audit, approver=lambda d: True), audit, kali


def _log(audit):
    return Path(audit.path).read_text(errors="replace")


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_cm3s_hash_recovered_then_used_is_masked_in_the_ledger(tmp_path):
    """THE DEFECT, with CM3/CM4/CM5's real value and real shape: an SQLi dump names the
    field `password`, and the agent then types the value into a cracking command."""
    dump = json.dumps({"data": [{"id": 1, "email": "admin@juice-sh.op",
                                 "password": ADMIN_HASH, "role": "admin"}]})
    ex, audit, _k = _executor(tmp_path, out=dump)

    # 1) the agent RECOVERS it from the target
    ex.run(f"curl -s http://{TARGET}:3000/api/Users?q=1", target=TARGET, agent="exploit")
    # 2) the agent then CARRIES it in a command it authored
    ex.run(f"echo -n {ADMIN_HASH} | md5sum", target=TARGET, agent="exploit")

    blob = _log(audit)
    assert ADMIN_HASH not in blob, (
        "the recovered credential is in the ledger in cleartext — on the response that "
        "disclosed it and/or the command that reused it")
    assert "[REDACTED:" in blob, "nothing was masked; the assertion above proves nothing"


def test_cm4s_token_case_likewise(tmp_path):
    """A token the target hands back under a token-named key, then reused."""
    body = json.dumps({"authentication": {"token": ADMIN_JWT, "umail": "admin@juice-sh.op"}})
    ex, audit, _k = _executor(tmp_path, out=body)
    ex.run(f"curl -s http://{TARGET}:3000/rest/user/login", target=TARGET, agent="exploit")
    ex.run(f"curl -H 'Authorization: Bearer {ADMIN_JWT}' http://{TARGET}:3000/rest/admin",
           target=TARGET, agent="exploit")

    blob = _log(audit)
    assert ADMIN_JWT not in blob, "the recovered token is in the ledger in cleartext"


def test_the_command_STRUCTURE_survives_so_the_gate_stays_auditable(tmp_path):
    """A masked record must still show WHAT was run. The gate's decision is only
    reviewable if the command's shape is intact — only the secret is replaced."""
    dump = json.dumps({"password": ADMIN_HASH})
    ex, audit, _k = _executor(tmp_path, out=dump)
    ex.run(f"curl -s http://{TARGET}:3000/api/Users", target=TARGET, agent="exploit")
    ex.run(f"hashcat -m 0 -a 0 {ADMIN_HASH} /usr/share/wordlists/rockyou.txt",
           target=TARGET, agent="exploit")

    blob = _log(audit)
    assert "hashcat -m 0 -a 0" in blob, "the command's structure was destroyed"
    assert "/usr/share/wordlists/rockyou.txt" in blob, "arguments were lost"
    assert ADMIN_HASH not in blob


def test_a_command_carrying_no_recovered_value_is_byte_identical(tmp_path):
    """Nothing recovered, nothing changed. The mechanism must be invisible otherwise."""
    ex, audit, _k = _executor(tmp_path, out='{"status":"ok","data":[]}')
    cmd = f"nmap -sV -p 3000 {TARGET}"
    ex.run(cmd, target=TARGET, agent="recon")
    blob = _log(audit)
    assert cmd in blob, "an untouched command was altered"
    assert "[REDACTED:" not in blob, "something was masked that was never a credential"


# --------------------------------------------------------------------------- #
# BOUNDARY — the identifiers the cross-account comparator needs
# --------------------------------------------------------------------------- #

def test_resource_identifiers_are_NOT_masked(tmp_path):
    """BOUNDARY, and it is load-bearing: `cross_account_resource` matches ownership BY
    VALUE against ids read out of responses and commands. Masking `6` or `28` would
    silently disable the milestone capability."""
    body = json.dumps({"status": "success",
                       "data": {"id": 6, "UserId": 28, "BasketId": 9,
                                "password": ADMIN_HASH}})
    ex, audit, _k = _executor(tmp_path, out=body)
    ex.run(f"curl -s http://{TARGET}:3000/rest/basket/6", target=TARGET, agent="exploit")
    ex.run(f"curl -s http://{TARGET}:3000/rest/basket/9", target=TARGET, agent="exploit")

    blob = _log(audit)
    assert ADMIN_HASH not in blob, "the secret beside the ids was not masked"
    assert "/rest/basket/6" in blob and "/rest/basket/9" in blob, (
        "a resource identifier was masked — the cross-account comparator depends on these")
    assert '"UserId": 28' in blob or '"UserId":28' in blob or "28" in blob


def test_the_same_string_under_an_id_key_is_not_registered(tmp_path):
    """The rule reads the TARGET'S KEY, never the value's shape. The identical 32-hex
    string under `id` is an identifier, not a secret."""
    body = json.dumps({"data": {"id": ADMIN_HASH, "name": "thing"}})
    ex, audit, _k = _executor(tmp_path, out=body)
    ex.run(f"curl -s http://{TARGET}:3000/x", target=TARGET, agent="recon")
    blob = _log(audit)
    assert ADMIN_HASH in blob, (
        "a value under an id-named key was masked — that is recognition by shape, which "
        "this design explicitly refuses")


def test_injected_credential_redaction_is_untouched(tmp_path):
    """BOUNDARY. The engagement's OWN credentials keep working exactly as before."""
    redact.register("tok-INJECTED-SECRET-VALUE")
    ex, audit, _k = _executor(tmp_path, out='{"ok":true}')
    ex.run(f"curl -H 'Authorization: Bearer tok-INJECTED-SECRET-VALUE' http://{TARGET}:3000/",
           target=TARGET, agent="recon")
    blob = _log(audit)
    assert "tok-INJECTED-SECRET-VALUE" not in blob
    assert "[REDACTED:" in blob


# --------------------------------------------------------------------------- #
# THE REAL CM3/CM4 CASE — a secret under a key that names nothing
# --------------------------------------------------------------------------- #

# Verbatim shape from runs/audit_juiceshop_cm3.jsonl and cm4: a UNION SQLi projects the
# admin password hash into the `description` column of a products listing. No key names a
# secret, so the key-name rule alone cannot see it — and this is the case that actually
# made three bundles unpublishable.
SQLI_DUMP = json.dumps({"status": "success", "data": [
    {"id": 1, "name": "admin@juice-sh.op", "description": ADMIN_HASH,
     "price": "4", "deluxePrice": "5", "image": "apple.jpg"}]})


def test_the_description_column_case_is_NOT_covered_and_that_is_recorded(tmp_path):
    """THE ACTUAL LEAK, AND THE LIMIT OF THIS DESIGN — asserted so it cannot drift.

    The key-name rule reads the key the TARGET chose. `description` names nothing, so the
    hash is not registered and the record keeps it. This is the case that made CM3's and
    CM4's bundles unpublishable, and it is NOT closed here.

    THE BEHAVIOURAL RULE WAS BUILT AND REVERTED, with the measurement that killed it.
    "A value that came out of the target and then appears in a command the agent wrote"
    attributes this hash correctly — and it also attributes every other token a response
    carries. One ordinary product listing yields 24 recovered tokens including
    `description`, `createdAt`, `item0.jpg` and `2026-09-14T05`; masking any later command
    containing those broke six unrelated suites. A control that guts the audit trail is a
    worse outcome than the leak it closes.

    Narrowing it needs a test on the VALUE — entropy, length, dictionary-ness — which is
    recognition by shape, and a 32-hex rule would mask the resource identifiers
    `cross_account_resource` matches ownership against. So it is recorded, not widened.
    """
    ex, audit, _k = _executor(tmp_path, out=SQLI_DUMP)
    ex.run(f"curl -s 'http://{TARGET}:3000/rest/products/search?q=x'",
           target=TARGET, agent="exploit")
    ex.run(f"echo -n {ADMIN_HASH} | md5sum", target=TARGET, agent="exploit")

    blob = _log(audit)
    assert ADMIN_HASH in blob, (
        "the `description`-column case is now covered. If that is deliberate, UPDATE THE "
        "ROADMAP ENTRY and this test — do not simply loosen the assertion, because the "
        "open P1 it documents would then be silently stale.")


def test_a_secret_the_agent_DERIVES_is_not_covered_either(tmp_path):
    """RECORDED. CM5 cracked the hash to `admin123` and used the plaintext. It never
    appeared in any response, so nothing in the record attributes it."""
    ex, audit, _k = _executor(tmp_path, out=SQLI_DUMP)
    ex.run("hashcat --show cracked.txt", target=TARGET, agent="exploit")
    ex.run(f"curl -d '{{\"password\":\"admin123\"}}' http://{TARGET}:3000/rest/user/login",
           target=TARGET, agent="exploit")
    assert "admin123" in _log(audit), (
        "a derived secret is now masked — see the note above before changing this")
