"""
test_the_documented_scope_change_actually_changes_scope.py — GAP #25.

THE MEASURED PROBLEM (2026-09-20, first cold-target setup)
    `docker/docker-compose.yml` mounts the active scope and says:

        "The entrypoint builds the kernel egress lock from THIS file at startup.
         Changing scope => rebuild the ruleset => you MUST restart the cage
         (`docker compose ... restart kali`)."

    **`docker compose restart` does not pick up a changed bind-mount.** It restarts the
    EXISTING container with its existing configuration. Following the project's own
    documented procedure, verbatim:

        host scope file : brukal-dvwa-COLD1   172.20.0.2/32
        cage /scope.json: brukal-crapi-CR2r1  172.20.0.12/32     <- unchanged
        kernel lock     : ip daddr 172.20.0.12 accept            <- unchanged

    The harness reads the NEW scope from the host and believes it is testing the new
    target; the kernel is still enforcing the OLD one. Here that failed closed (the new
    target was unreachable), but the guarantee this project claims — "even a compromised
    agent cannot reach an unauthorised host, because the kernel drops it" — is only as
    good as the operator's belief that the lock matches the scope they are reading. A
    documented procedure that silently does not do what it says is the worst possible
    place for that belief to come from.

    `docker compose up -d --force-recreate kali` does apply it, verified in the same
    session: the lock flipped, crAPI went to HTTP 000 at the kernel and DVWA answered.

THE PROPERTY
    The documentation must not instruct an operator to change scope with a command that
    cannot change scope.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

COMPOSE = Path(__file__).resolve().parents[1] / "docker" / "docker-compose.yml"


def _scope_mount_comment() -> str:
    """The comment block immediately above the /scope.json mount."""
    text = COMPOSE.read_text()
    idx = text.find(":/scope.json")
    assert idx != -1, "the scope mount vanished from docker-compose.yml"
    return text[max(0, idx - 900):idx]


def test_the_scope_change_instruction_does_not_RECOMMEND_plain_restart():
    """`restart` reuses the existing container, mounts included.

    A mention of it is fine and in fact wanted — the comment now warns against it. What
    must not appear is an unnegated INSTRUCTION to use it, so each occurrence has to sit
    on a line that marks it as the wrong command."""
    block = _scope_mount_comment()
    for line in block.splitlines():
        if re.search(r"compose[^\n]*restart\s+kali", line):
            assert re.search(r"\bNOT\b|\bnot\b|never", line), (
                f"an unnegated instruction to change scope by restarting: {line.strip()}")


def test_it_names_a_command_that_ACTUALLY_applies_a_new_scope():
    block = _scope_mount_comment()
    assert "force-recreate" in block or "up -d" in block, (
        "the scope mount comment names no command that re-reads the mount")


def test_the_reason_is_stated_not_just_the_command():
    """A corrected command with no reason gets 'fixed' back by the next person who finds
    `restart` shorter."""
    block = _scope_mount_comment().lower()
    assert "restart" in block and ("not" in block or "cannot" in block), (
        "the comment does not warn WHY plain restart is wrong")
