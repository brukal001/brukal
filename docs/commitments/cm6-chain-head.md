# CM6 — audit chain head commitment

This file exists to be committed and pushed to the public repository **before the CM6
bundle is shared with anyone**. That ordering is the whole point.

Brukal's audit log is an HMAC hash chain. Verifying it requires the key, and the bundle
ships the key so a reader can actually run the check — which means the chain proves
INTERNAL CONSISTENCY and, on its own, nothing about when the log was written or whether it
was rewritten before publication. Anyone holding the key could forge a consistent chain.

A commit pushed to a public repository at a known time is the one artifact in this scheme
that cannot be edited afterwards without it being obvious. Committing the chain head here,
first, is what converts "this log is self-consistent" into "this log existed, in exactly
this form, no later than this commit". It is a timestamping substitute for the asymmetric
signing recorded as an open P1, and it is weaker in a specific way: it proves the log is no
NEWER than this commit; it does not prove who produced it.

| | |
|---|---|
| run | `CM6` — engagement `brukal-juiceshop-cm6-172.20.0.3` |
| target | OWASP Juice Shop v20.2.0, disposable container, isolated bridge, no published ports |
| audit log | `audit.jsonl` |
| entries | `719` |
| **chain head** (`entry_hash` of the final entry) | `d0b1f3e0288cdefdbbc95aec8521ca90293d9823afe8b389a03b61952b4052ec` |
| key fingerprint (`sha256` of the key file, first 16 hex) | `354309c6754710d8` |
| the key itself | **NOT here.** It ships in the bundle as `audit.key` |
| committed at (UTC) | `2026-09-15T06:43:51Z` |

## What a reader does with this

```sh
# 1. the chain verifies with the key that ships in the bundle
BRUKAL_AUDIT_KEY="$(cat audit.key)" python -m brukal.cli verify --audit audit.jsonl
#    -> audit chain intact: True

# 2. the head of that chain matches the value committed here, BEFORE publication
tail -n 1 audit.jsonl | python -c 'import json,sys; print(json.loads(sys.stdin.read())["entry_hash"])'
#    -> d0b1f3e0288cdefdbbc95aec8521ca90293d9823afe8b389a03b61952b4052ec

# 3. and the key you were given is the one this commitment names
sha256sum audit.key | cut -c1-16
#    -> 354309c6754710d8
```

If (2) does not match, the log you were given is not the log that existed when this commit
was pushed.
