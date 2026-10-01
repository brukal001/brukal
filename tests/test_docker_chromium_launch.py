"""Shape/lint test for Task 10 (Chrome-CDP + full-capture milestone).

Deterministic: reads the docker files as text, no Docker build/run involved.
Run from the repo root so the relative paths resolve:

    python -m pytest tests/test_docker_chromium_launch.py -v
"""

from pathlib import Path


def test_entrypoint_launches_proxied_chromium_as_nonproxy_uid():
    text = Path("docker/entrypoint.sh").read_text()
    assert "--remote-debugging-port=9222" in text
    assert "--proxy-server=" in text
    assert "--proxy-bypass-list=" in text  # SSRF->CDP hardening present
    assert "--ignore-certificate-errors" not in text  # cert verification stays ON
    assert "brukalop" in text  # runs as the non-proxy uid


def test_compose_publishes_cdp_on_host_loopback_only():
    text = Path("docker/docker-compose.yml").read_text()
    assert "127.0.0.1:9222:9222" in text


def test_entrypoint_bridges_cdp_to_host_with_socat():
    # Chromium 150+ ignores --remote-debugging-address and binds CDP to the
    # container's loopback only, so the published port cannot reach it without a
    # raw-TCP forwarder from the bridge interface to 127.0.0.1:9222. Live-validated
    # 2026-10-01; asserted here so a future edit can't silently drop it.
    text = Path("docker/entrypoint.sh").read_text()
    assert "socat" in text
    assert "TCP-LISTEN:9222" in text
    assert "TCP:127.0.0.1:9222" in text
