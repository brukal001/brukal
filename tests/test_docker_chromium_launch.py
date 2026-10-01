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
