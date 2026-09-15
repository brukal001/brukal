# RUNBOOK — run a Brukal engagement yourself, and audit it

Every command below is copy-pasteable into WSL from the repo root
(`/mnt/c/Users/ashis/Desktop/Brukal/brukal`). Target is OWASP Juice Shop v20.2.0, the
configuration runs CM5 and CM6 used.

Nothing here needs my involvement. Step 6 is the run; steps 7–8 are how you audit it.

---

## 0. Prerequisites — the one that bites every time

**Docker Desktop's WSL integration turns itself OFF across Windows restarts.** If `docker ps`
errors, open Docker Desktop → Settings → Resources → WSL Integration → enable your distro →
Apply & Restart.

```sh
cd /mnt/c/Users/ashis/Desktop/Brukal/brukal
docker ps                      # must succeed before anything else
.venv/bin/python -m pytest -q  # expect 1191 passed, 1 skipped
```

---

## 1. Bring up the target and the off-scope control

The control exists so "in scope reachable, out of scope blocked" is something you SEE, not
something you're told.

```sh
docker rm -f brukal-juiceshop brukal-offscope 2>/dev/null
docker run -d --name brukal-juiceshop --network docker_brukal_isolated bkimminich/juice-shop:v20.2.0
docker run -d --name brukal-offscope  --network docker_brukal_isolated nginx:alpine

# wait for the target to actually finish booting -- do not assume
until docker logs brukal-juiceshop 2>&1 | grep -q 'Server listening on port 3000'; do sleep 3; done
echo "target up"

# confirm NO published ports (the Ports column must show no host mapping)
docker ps --format '{{.Names}}\t[{{.Ports}}]' | grep -E 'juiceshop|offscope|kali'
```

## 2. Read the target's IP — do not assume it

```sh
docker network inspect docker_brukal_isolated \
  --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
# expect brukal-juiceshop 172.20.0.3 ; adjust below if it differs
```

## 3. Stamp the scope, THEN start the cage

Order matters: the cage builds its kernel egress lock from the scope at startup. Scope
first, cage second — that's what makes the lock non-widenable at runtime.

```sh
sed -i 's/brukal-juiceshop-cm[0-9]*-/brukal-juiceshop-myrun-/' scope.juiceshop.json
sed -i 's/"expires": "[0-9-]*"/"expires": "2026-12-31"/' scope.juiceshop.json
.venv/bin/python -c "import json;d=json.load(open('scope.juiceshop.json'));print(d['engagement'],d['authorized_cidrs'],d['expires'])"

docker compose -f docker/docker-compose.yml up -d --force-recreate
sleep 8
docker exec brukal-kali sh -c 'python3 -c "import json;d=json.load(open(\"/scope.json\"));print(d[\"engagement\"],d[\"authorized_cidrs\"])"'
```

## 4. Prove containment before spending anything

```sh
docker exec brukal-kali sh -c 'nft list ruleset'        # policy drop; one ip daddr accepted
docker exec brukal-kali sh -c 'curl -s -o /dev/null -w "in-scope   %{http_code}\n" --max-time 8 http://172.20.0.3:3000/'
docker exec brukal-kali sh -c 'curl -s -o /dev/null -w "off-scope  %{http_code}\n" --max-time 6 http://172.20.0.4/    || echo "off-scope  BLOCKED"'
docker exec brukal-kali sh -c 'curl -s -o /dev/null -w "internet   %{http_code}\n" --max-time 6 http://1.1.1.1/       || echo "internet   BLOCKED"'
```
Expect `200`, then two `BLOCKED`.

## 5. Audit key, and the first account

The key lives OUTSIDE the repo so it can never be committed by accident.

```sh
mkdir -p ~/.brukal && umask 077
[ -f ~/.brukal/myrun.key ] || .venv/bin/python -c "import secrets;open('$HOME/.brukal/myrun.key','w').write(secrets.token_hex(32))"
chmod 600 ~/.brukal/myrun.key && ls -l ~/.brukal/myrun.key

# principal A, created through the application's own signup
A_EMAIL="brk$(openssl rand -hex 5)@brukal.test"; A_PASS="Brk-$(openssl rand -hex 6)!"
echo "$A_EMAIL" > /tmp/a_email; echo "$A_PASS" > /tmp/a_pass
docker exec brukal-kali sh -c "curl -s -X POST http://172.20.0.3:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{\"email\":\"$A_EMAIL\",\"password\":\"$A_PASS\",\"passwordRepeat\":\"$A_PASS\",\"securityQuestion\":{\"id\":1,\"question\":\"q\"},\"securityAnswer\":\"brukal\"}'"
echo; echo "principal A = $A_EMAIL"
```
The SECOND principal is created by the harness during the run. You do not seed it.

## 6. Run it

`--full-send` auto-approves in-scope actions. **The scope wall still applies** — out of
scope is still denied. `--no-resume` starts clean; `--no-handoff` stops instead of dropping
into a menu.

```sh
export BRUKAL_AUDIT_KEY="$(cat ~/.brukal/myrun.key)"
export ANTHROPIC_API_KEY="$(grep ANTHROPIC_API_KEY runs/anthropic.env | cut -d= -f2-)"

.venv/bin/python -m brukal.cli auto 172.20.0.3 \
  --yes-authorised --scope scope.juiceshop.json --full-send --web \
  --login-url http://172.20.0.3:3000/rest/user/login --login-type json \
  --login-field-user email --login-field-pass password \
  --login-user "$(cat /tmp/a_email)" --login-pass "$(cat /tmp/a_pass)" \
  --audit runs/audit_myrun.jsonl --vault runs/vault-myrun \
  --max-steps 70 --max-cost 12.00 --no-resume --no-handoff
```

Roughly 60 minutes and **$4–6** for 70 steps. Steps bind before dollars do.

**To watch it instead of staring at it**, run it with `| tee` or in a second WSL tab:

```sh
# second tab -- the funnel, recomputed from the ledger, live
watch -n 30 '.venv/bin/python -c "
import sys;sys.path.insert(0,\".\")
from brukal import hypothesis as h
print(h.funnel_from_log(\"runs/audit_myrun.jsonl\"))"'
```

---

## 7. Audit the run — the part that matters

### 7a. Is the chain intact, and is it really keyed?

```sh
export BRUKAL_AUDIT_KEY="$(cat ~/.brukal/myrun.key)"
.venv/bin/python -m brukal.cli verify --audit runs/audit_myrun.jsonl        # -> intact: True
env -u BRUKAL_AUDIT_KEY .venv/bin/python -m brukal.cli verify --audit runs/audit_myrun.jsonl  # -> intact: False
```
The second command is the one that matters. `True` without the key would mean the chain
proves nothing.

### 7b. The funnel, from the ledger — not from the notes

```sh
.venv/bin/python -c "
import sys;sys.path.insert(0,'.')
from brukal import hypothesis as h
f=h.funnel_from_log('runs/audit_myrun.jsonl'); xa=f.pop('cross_account')
print('all          :',f)
print('cross-account:',xa)"
```

### 7c. Every cross-account claim, and whether it is checkable

```sh
.venv/bin/python -c "
import json
for l in open('runs/audit_myrun.jsonl'):
    e=json.loads(l)
    if e['kind'] in ('ownership_match','principal_ownership','authentication_mismatch'):
        print(e['kind'], json.dumps(e['data']))"
```
Read it like this:
- `principal_ownership` — who owns what, and `source`/`path` say WHICH response said so.
- `ownership_match` — `held`, `variant_as`, `owner`, `addressed`, `corroborating`.
  **`addressed: true` is what carries the claim**; `corroborating` is the body agreeing.
  An empty `corroborating` list is the weaker form — real, but say so.
- `authentication_mismatch` — should be **empty**. Any entry means a probe answered as the
  wrong principal, and every finding after it is suspect.

### 7d. Did it stay in scope?

```sh
.venv/bin/python -c "
import json,collections
v=collections.Counter(); lay=collections.Counter()
for l in open('runs/audit_myrun.jsonl'):
    d=json.loads(l).get('data',{})
    if 'verdict' in d:
        v[d['verdict']]+=1
        if d['verdict']=='DENY': lay[d.get('layer')]+=1
print(v); print(lay)"
```
`hard:web-scope` / `hard:scope` denials are the scope wall firing on a real foreign host.

### 7e. Did anything leak?

```sh
grep -c "$(cat /tmp/a_pass)" runs/audit_myrun.jsonl runs/vault-myrun -r   # expect 0
grep -roE 'eyJ[A-Za-z0-9_-]{20,}' runs/audit_myrun.jsonl | wc -l          # raw JWTs
grep -roE '\[REDACTED:[0-9a-f]{8}\]' runs/audit_myrun.jsonl | wc -l       # the control firing
```
The third number matters: if it's 0, the first two prove nothing — you searched an empty
surface.

### 7f. Read the report

```sh
less runs/vault-myrun/172.20.0.3/report.md
```

---

## 8. Tear down

```sh
docker rm -f brukal-juiceshop brukal-offscope
```

Artifacts stay in `runs/` (gitignored). To hand the run to someone else, see
`docs/commitments/cm6-chain-head.md` for the bundle pattern: commit the chain head publicly
*before* you share the bundle, ship the key with it, and write a disclosure.

---

## What to be sceptical of

- A coverage row saying "none found" is evidence **about the endpoints the crawl reached**,
  not about the application.
- A `cross_account_resource` finding with empty `corroborating` rests on the addressed id
  alone. Weaker than one with two corroborating fields.
- `as: second` is a real principal on header-reading endpoints and collapses to anonymous on
  cookie-reading ones — Juice Shop's `/rest/user/whoami` is cookie-only. Open, recorded.
- The agent's own claim sits beside every finding marked UNVERIFIED. It is the most useful
  sentence in the record and the least trustworthy.
