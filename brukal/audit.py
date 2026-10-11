"""
audit.py — the tamper-evident audit log and evidence spine.

Every decision and every execution result is appended here, never edited. The
records are chained: each entry stores the hash of the previous entry, so altering
or removing any record BEFORE the last breaks the chain and is detectable by verify(). This
turns "trust me, it scored X" into "here is the verifiable receipt for every
action" — the property the paper leans on for reproducibility.

Two chaining modes:

  * Default — an UNKEYED SHA-256 chain. This is *tamper-evident*, NOT immutable:
    anyone who can write the file can recompute the whole chain after an edit and
    still pass verify(). It detects accidental corruption and naive tampering, and
    is the right default for a local lab log.
  * Keyed (set env var BRUKAL_AUDIT_KEY) — an HMAC-SHA-256 chain. Now an edit can
    only be re-chained by someone who also holds the key, so tampering by an actor
    with mere file-write access is detectable. Use this for engagements where the
    log is evidence (e.g. bug-bounty reproducibility). verify() must run with the
    same key that wrote the log.

Truncation (SEC-006). A chain proves each record's predecessor, never how MANY records
there were: deleting the tail leaves a self-consistent prefix. So verify() also checks
the ledger still CONTAINS an anchor held outside the deleted bytes:

  1. this AuditLog's own memory of the last record it wrote or read (a live run);
  2. the `<ledger>.head` sidecar — record count + head hash, rewritten atomically on
     every append, HMAC'd in keyed mode. Records written this way carry `"v": 2`, so a
     marked ledger whose sidecar has gone missing fails verify();
  3. an operator-held external anchor: `head()` returns (count, head hash) — `brukal
     verify` prints it — and `verify(anchor=...)` checks a ledger against it.
"Contains" means the record at position `count` has hash `head`: a ledger may GROW
past an anchor (later sessions, a crash between line and sidecar), never shrink.
Residuals, by design: in UNKEYED mode a file-writer can rewrite the sidecar too (as
they can re-chain an edit); in keyed mode a file-writer who saved an OLD sidecar can
truncate back to it. Only (3), kept off the machine, closes both. Legacy ledgers
(no marker, no sidecar) verify as before.

Stored as JSONL (one JSON object per line) so it is easy to grep, load into pandas
for results tables, and diff.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path

from . import redact

_GENESIS = "0" * 64  # the hash that precedes the very first record
_FORMAT = 2          # records written with a truncation anchor carry "v": 2 (SEC-006)


def _chain(prev_hash: str, payload: str, key: str | None = None) -> str:
    """One link of the chain. Unkeyed SHA-256 by default; HMAC-SHA-256 when a key is
    supplied, so an edit can't be silently re-chained without the key."""
    msg = (prev_hash + payload).encode("utf-8")
    if key:
        return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def _head_mac(count: int, head: str, key: str | None) -> str:
    """Integrity tag for the `.head` sidecar. Keyed: HMAC, so a file-writer without
    the key cannot mint a sidecar naming a truncated prefix. Unkeyed: a plain digest
    (detects corruption, not a deliberate rewrite — the unkeyed design limit)."""
    return _chain("head", f"{count}:{head}", key)


def _contains(hashes: list, count, head) -> bool:
    """True if the ledger's `count`-th record has hash `head` (count 0 = genesis).
    Fail-closed on a malformed anchor."""
    if not isinstance(count, int) or isinstance(count, bool) or count < 0 \
            or not isinstance(head, str):
        return False
    if count == 0:
        return head == _GENESIS
    return len(hashes) >= count and hashes[count - 1] == head


# Back-compat alias for the unkeyed form (some callers/tests import _hash).
def _hash(prev_hash: str, payload: str) -> str:
    return _chain(prev_hash, payload, None)


# Ledgers this PROCESS has claimed: path -> held lock file object. Keeps the
# guard aimed at cross-process interleaving without blocking a later session
# in the same process from appending to the ledger it already owns.
_PROCESS_LEDGER_LOCKS: dict = {}


class AuditLog:
    """Append-only, hash-chained log backed by a JSONL file."""

    def __init__(self, path: str | Path, key: str | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Chain key: explicit arg wins, else BRUKAL_AUDIT_KEY, else None (unkeyed).
        # Read once at construction so append() and verify() use the same key.
        self._key = key if key is not None else os.environ.get("BRUKAL_AUDIT_KEY") or None
        self._last_hash, self._count = self._recover_tail()
        self.keyed = self._key is not None   # True = HMAC (tamper-proof), False = unkeyed
        # The hash chain is inherently sequential: read prev -> compute -> write ->
        # update must be ONE atomic step, or two concurrent agents chain onto the
        # same prev_hash and corrupt the chain. This lock is what makes the audit
        # log safe under the parallel orchestrator (invariant 5 holds concurrently).
        self._lock = threading.Lock()
        # The in-process lock cannot see ANOTHER PROCESS writing the same ledger. Two
        # runs sharing one --audit path interleave their prev_hash and the chain verifies
        # FALSE — indistinguishable from tampering, which destroys the log's evidential
        # value. A real run hit exactly this: a stopped run finished its in-flight action
        # while a relaunched run appended. Taken lazily on the first write, so a
        # verify-only open (cli `audit`, session close) never contends with a live run.
        self._wlock_fd = None
        self._wlock_taken = False
        self.head_lagging = False   # True if the last sidecar write failed (see _write_head)

    def _acquire_writer_lock(self) -> None:
        """Claim exclusive write ownership of this ledger across processes. Fail-closed:
        if another process holds it, refuse to write rather than corrupt the chain."""
        if self._wlock_taken:
            return
        try:
            import fcntl
        except ImportError:                    # non-POSIX: no advisory locks available
            self._wlock_taken = True
            return
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        key = str(self.path.resolve())
        if key in _PROCESS_LEDGER_LOCKS:
            # THIS process already owns the ledger (a later session reusing the same
            # path). That is safe and ordinary; the tail is re-read below either way.
            # Only another process interleaving is the hazard worth refusing.
            self._wlock_taken = True
            self._last_hash, self._count = self._recover_tail()
            return
        fd = open(lock_path, "w")
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fd.close()
            raise RuntimeError(
                f"audit ledger {self.path} is already being written by another run. "
                f"Appending would interleave the hash chain and make it verify FALSE. "
                f"Use a separate --audit path for this run.") from None
        fd.write(f"{os.getpid()}\n")
        fd.flush()
        _PROCESS_LEDGER_LOCKS[key] = fd     # held for the process lifetime
        self._wlock_fd = fd
        self._wlock_taken = True
        # Another process may have appended between construction and now, so re-read the
        # tail under the lock — chaining onto a stale hash is what breaks the chain.
        self._last_hash, self._count = self._recover_tail()

    def _recover_tail(self) -> tuple[str, int]:
        """On startup, read the last line so new records chain onto it, and count the
        records so the live instance holds a truncation anchor (SEC-006)."""
        if not self.path.exists():
            return _GENESIS, 0
        last, count = _GENESIS, 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
                    count += 1
        return last, count

    def _recover_last_hash(self) -> str:
        return self._recover_tail()[0]

    @property
    def head_path(self) -> Path:
        return self.path.with_name(self.path.name + ".head")

    def head(self) -> tuple[int, str]:
        """(record count, head hash) — the anchor an operator can keep off the machine
        and later pass to verify(anchor=...)."""
        return self._count, self._last_hash

    def _write_head(self) -> None:
        """Atomically rewrite the `.head` sidecar (tmp file + os.replace), so a reader
        never sees a half-written anchor."""
        doc = {"count": self._count, "head": self._last_hash,
               "mac": _head_mac(self._count, self._last_hash, self._key)}
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        for _attempt in range(2):
            try:
                tmp.write_text(json.dumps(doc, separators=(",", ":")), encoding="utf-8")
                os.replace(tmp, self.head_path)
                self.head_lagging = False
                return
            except OSError:
                # e.g. Windows refusing the replace while another program holds the
                # file open. The ledger line is already written; a sidecar that LAGS
                # (names an earlier head) is safe — verify() accepts growth past an
                # anchor, never shrinkage — so a sidecar hiccup must not abort a run.
                time.sleep(0.05)
        self.head_lagging = True

    def _read_head(self):
        """The sidecar as (count, head), None if absent, or False if present but
        unreadable / malformed / failing its MAC (fail-closed)."""
        if not self.head_path.exists():
            return None
        try:
            doc = json.loads(self.head_path.read_text(encoding="utf-8"))
            count, head, mac = doc["count"], doc["head"], doc["mac"]
        except (OSError, ValueError, TypeError, KeyError):
            return False
        if not isinstance(count, int) or not isinstance(head, str) \
                or not isinstance(mac, str):
            return False
        if not hmac.compare_digest(mac, _head_mac(count, head, self._key)):
            return False
        return count, head

    def append(self, kind: str, data) -> str:
        """Append one record. `data` may be a dataclass (e.g. Decision) or dict.

        Returns the new entry hash.
        """
        if is_dataclass(data):
            data = asdict(data)
        # Redact at the point of RECORD, never at the point of injection: the gate has
        # already judged, and the executor already ran, the REAL bytes (invariant 3) —
        # what lands in the ledger is the same command with the engagement's own
        # credential values masked. Applied here rather than at each caller so every
        # record kind (decision, execution, note) inherits it. See redact.py.
        data = redact.data(data)
        with self._lock:
            # Inside the thread lock: concurrent workers in ONE process share this
            # AuditLog and must not race to claim the cross-process lock.
            self._acquire_writer_lock()
            record = {
                "ts": time.time(),
                "kind": kind,          # "decision" | "execution" | "note"
                "data": data,
                "prev_hash": self._last_hash,
                "v": _FORMAT,
            }
            payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record["entry_hash"] = _chain(self._last_hash, payload, self._key)

            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")

            self._last_hash = record["entry_hash"]
            self._count += 1
            self._write_head()
            return self._last_hash

    def verify(self, anchor: tuple | None = None) -> bool:
        """Re-walk the file and confirm the hash chain is intact AND not truncated.

        Returns True if no record has been altered or removed: the chain links, and the
        ledger still contains every anchor available — this instance's own last record,
        the `.head` sidecar (required once any record carries the anchoring marker),
        and `anchor`, an operator-held (count, head) from `head()`. See the module
        docstring for what each anchor does and does not cover.
        """
        prev = _GENESIS
        hashes: list[str] = []
        anchored = False
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored = record.pop("entry_hash")
                if record["prev_hash"] != prev:
                    return False
                payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
                if _chain(prev, payload, self._key) != stored:
                    return False
                prev = stored
                hashes.append(stored)
                anchored = anchored or record.get("v") == _FORMAT
        # SEC-006 — the chain links; now prove nothing was cut off the end.
        if not _contains(hashes, self._count, self._last_hash):
            return False                       # shorter than what this instance saw
        side = self._read_head()
        if side is False:
            return False                       # sidecar tampered / corrupt
        if side is None:
            if anchored:
                return False                   # an anchored ledger lost its anchor
        elif not _contains(hashes, *side):
            return False                       # shorter than the sidecar says
        if anchor is not None:
            try:
                count, head = anchor
            except (TypeError, ValueError):
                return False
            if not _contains(hashes, count, head):
                return False                   # shorter than the operator's anchor
        return True
