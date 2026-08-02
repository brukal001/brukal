"""
test_sourcemap.py — white-box input, black-box discipline.

A white-box competitor read `SECRET_KEY = 'random'` out of the repository and reported
it as a finding. Brukal may read the same file, but it may not draw the same conclusion:
source is text an attacker cannot be assumed to have, and a regex hit sitting next to
fourteen deterministically proven findings would destroy the distinction the report
rests on.

So every test here is about the boundary. Source SELECTS what to try; the dynamic proof
still decides what is true.
"""
from __future__ import annotations

from pathlib import Path

from brukal import sourcemap


def _tree(tmp_path: Path, files: dict) -> Path:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp_path


def test_dict_assigned_secret_is_found(tmp_path):
    """The real shape in Flask and Django: the name is a dict KEY, not an identifier.
    Matching only `SECRET_KEY = 'x'` missed the actual declaration in every app tried."""
    root = _tree(tmp_path, {"config.py": "app.config['SECRET_KEY'] = 'random'\n"})
    assert sourcemap.secrets_to_try(sourcemap.scan(root)) == ["random"]


def test_bare_and_json_forms_are_also_found(tmp_path):
    root = _tree(tmp_path, {"a.py": "JWT_SECRET = 'sk-bare'\n",
                            "b.json": '{"SIGNING_KEY": "sk-json"}\n'})
    assert set(sourcemap.secrets_to_try(sourcemap.scan(root))) == {"sk-bare", "sk-json"}


def test_prose_is_not_mistaken_for_a_credential(tmp_path):
    """The false positive this produced live: `'Password': 'Updated.'` is a response
    message in a handler, and was offered as a login to try."""
    root = _tree(tmp_path, {"users.py": "return {'Password': 'Updated.'}\n"})
    assert [l for l in sourcemap.scan(root) if l["kind"] == "credential"] == []


def test_everything_produced_is_a_lead_and_says_so(tmp_path):
    root = _tree(tmp_path, {"config.py": "SECRET_KEY = 'random'\n"})
    leads = sourcemap.scan(root)
    assert all({"kind", "value", "hint", "where"} <= set(l) for l in leads)
    assert "leads only" in sourcemap.summarise(leads)
    # a lead carries an instruction to PROVE, not a conclusion
    assert "try this value" in leads[0]["hint"]


def test_source_alone_produces_no_findings(tmp_path):
    """The load-bearing property. Nothing in this module can add to a FindingStore —
    it has no access to one, and returns plain data."""
    root = _tree(tmp_path, {"config.py": "SECRET_KEY = 'random'\ndebug=True\n"})
    out = sourcemap.scan(root)
    assert isinstance(out, list) and all(isinstance(l, dict) for l in out)
    assert not hasattr(sourcemap, "confirm")


def test_a_missing_or_hostile_tree_yields_nothing_rather_than_raising(tmp_path):
    assert sourcemap.scan(tmp_path / "nope") == []
    assert sourcemap.scan("/dev/null") == []
    root = _tree(tmp_path, {"weird.py": "\x00\xff binary-ish \x00 SECRET_KEY = ''\n"})
    sourcemap.scan(root)                       # must not raise


def test_dependency_trees_are_skipped(tmp_path):
    """Walking node_modules would cost minutes and produce other people's secrets."""
    root = _tree(tmp_path, {"node_modules/pkg/x.js": "const API_KEY = 'sk-vendor-key'\n",
                            "app.py": "SECRET_KEY = 'mine'\n"})
    assert sourcemap.secrets_to_try(sourcemap.scan(root)) == ["mine"]


def test_candidate_keys_reach_the_offline_prover():
    """The whole white-box benefit, expressed honestly: a key that is in the source but
    NOT in the wordlist still has to reproduce a real token's signature."""
    import hmac, hashlib, base64, json as _json
    from brukal import jwtscan

    def b64(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    secret = "a-key-no-wordlist-would-ever-contain-9f3b"
    head, payload = b64(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode()), \
        b64(_json.dumps({"sub": "x"}).encode())
    signing_input = f"{head}.{payload}".encode()
    sig = b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    token = f"{head}.{payload}.{sig}"

    assert jwtscan.crack_hmac_secret(token) is None            # unreachable black-box
    assert jwtscan.crack_hmac_secret(token, extra_secrets=(secret,)) == secret
    # and a WRONG source-derived key proves nothing, however incriminating the file
    assert jwtscan.crack_hmac_secret(token, extra_secrets=("wrong-key",)) is None
