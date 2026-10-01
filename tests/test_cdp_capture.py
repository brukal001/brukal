import base64
from brukal import cdp


def test_accumulator_pairs_request_and_response():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "7",
        "request": {"method": "GET", "url": "http://lab/x", "headers": {"H": "1"}}})
    nc.ingest("Network.responseReceived", {"requestId": "7",
        "response": {"status": 200, "headers": {"Content-Type": "text/html"}}})
    nc.ingest("Network.loadingFinished", {"requestId": "7"})
    pairs = nc.drain(lambda rid: ("<html>ok</html>", False))
    assert pairs[0]["url"] == "http://lab/x"
    assert pairs[0]["status"] == 200
    assert pairs[0]["resp_body"] == "<html>ok</html>"
    assert pairs[0]["resp_headers"]["Content-Type"] == "text/html"


def test_base64_body_is_decoded():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "8",
        "request": {"method": "GET", "url": "http://lab/y", "headers": {}}})
    nc.ingest("Network.responseReceived", {"requestId": "8", "response": {"status": 200, "headers": {}}})
    nc.ingest("Network.loadingFinished", {"requestId": "8"})
    b64 = base64.b64encode(b"decoded-body").decode()
    pairs = nc.drain(lambda rid: (b64, True))
    assert pairs[0]["resp_body"] == "decoded-body"


def test_unfinished_request_is_not_drained():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "9",
        "request": {"method": "GET", "url": "http://lab/z", "headers": {}}})
    # no responseReceived / loadingFinished
    assert nc.drain(lambda rid: ("", False)) == []
