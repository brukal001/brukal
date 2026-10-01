"""Provider-aware API-key resolution for the hunt wizard. The raw key is
returned separately and is NEVER stored in KeyResolution (repr-safe)."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KeyResolution:
    provider: str
    found: bool
    source: str   # "env" | "file:<path>" | "prompt" | "none"


def _env_var(provider: str) -> str:
    return f"{provider.upper()}_API_KEY"


def _read_file_key(path: Path, var: str) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(rf"^(?:export\s+)?{re.escape(var)}=(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def resolve_key(provider, *, environ=None, runs_dir="runs", prompt=input, save=True):
    environ = os.environ if environ is None else environ
    var = _env_var(provider)
    env_val = (environ.get(var) or "").strip()
    if env_val:
        return env_val, KeyResolution(provider, True, "env")

    f = Path(runs_dir) / f"{provider.lower()}.env"
    file_val = _read_file_key(f, var)
    if file_val:
        return file_val, KeyResolution(provider, True, f"file:{f}")

    try:
        typed = (prompt(f"  {var} (blank to skip): ") or "").strip()
    except (EOFError, OSError):
        typed = ""
    if not typed:
        return None, KeyResolution(provider, False, "none")

    if save:
        try:
            Path(runs_dir).mkdir(parents=True, exist_ok=True)
            os.umask(0o077)
            f.write_text(f"export {var}={typed}\n", encoding="utf-8")
        except OSError:
            pass
    return typed, KeyResolution(provider, True, "prompt")
