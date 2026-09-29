"""
test_chrome_capture.py — ChromeCage.drain_capture() + Network.enable on navigate;
FakeCDP emits Network.* pairs (Task 4 of the Chrome-CDP + full-capture milestone).
"""
from brukal.chrome import ChromeCage, FakeCDP
from brukal.web import WebAction


def test_drain_capture_empty_without_network_transport():
    cage = ChromeCage(FakeCDP())          # bare FakeCDP has no drain_network
    assert cage.drain_capture() == []


def test_drain_capture_returns_network_pairs():
    fake = FakeCDP()
    fake.queue_network(url="http://lab/p", status=200, resp_body="<p>Solved</p>")
    cage = ChromeCage(fake)
    cage.run(WebAction(kind="navigate", url="http://lab/p"))
    pairs = cage.drain_capture()
    assert pairs and pairs[0]["url"] == "http://lab/p" and pairs[0]["resp_body"] == "<p>Solved</p>"
