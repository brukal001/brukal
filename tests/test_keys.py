# tests/test_keys.py
from pathlib import Path
from brukal.keys import resolve_key, KeyResolution

def test_env_wins_over_file_and_is_stripped(tmp_path):
    (tmp_path / "openrouter.env").write_text("export OPENROUTER_API_KEY=fromfile\n")
    key, res = resolve_key("openrouter",
                           environ={"OPENROUTER_API_KEY": "  fromenv  "},
                           runs_dir=str(tmp_path))
    assert key == "fromenv"
    assert res == KeyResolution("openrouter", True, "env")

def test_file_used_when_env_absent_newline_stripped(tmp_path):
    (tmp_path / "openrouter.env").write_text("export OPENROUTER_API_KEY=sk-file-123\n")
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path))
    assert key == "sk-file-123" and res.source.startswith("file:")

def test_prompt_and_save_when_missing(tmp_path):
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path),
                           prompt=lambda _p: "sk-typed-xyz")
    assert key == "sk-typed-xyz" and res.source == "prompt"
    saved = (tmp_path / "openrouter.env").read_text()
    assert "sk-typed-xyz" in saved

def test_key_never_appears_in_resolution_repr(tmp_path):
    key, res = resolve_key("openrouter", environ={"OPENROUTER_API_KEY": "sk-secret"},
                           runs_dir=str(tmp_path))
    assert "sk-secret" not in repr(res)

def test_missing_and_declined_returns_none(tmp_path):
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path),
                           prompt=lambda _p: "")
    assert key is None and res.found is False and res.source == "none"
