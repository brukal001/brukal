"""A single-page application must present a real attack surface.

Most of the modern web ships an HTML shell and a JavaScript bundle. Brukal's first cold
run against OWASP Juice Shop mapped ONE page, zero forms, zero parameters — and produced
an empty coverage table and a single finding in eighteen requests. Three separate causes,
each of which alone was enough to hide the entire application.
"""
from __future__ import annotations

from brukal.assist import _bundle_rank
from brukal.web import HttpWebCage


def test_a_script_may_be_read_far_past_the_page_limit():
    """The cap that hid every SPA. A page is fine in twenty kilobytes; a bundle is a MAP,
    and Juice Shop's main.js is about a megabyte with its API routes spread throughout.
    Truncating at 20 000 characters yielded ZERO routes from a file containing forty."""
    cage = HttpWebCage()
    page_cap = cage._cap_for("http://t/index.html", "text/html")
    script_cap = cage._cap_for("http://t/main.js", "application/javascript")
    assert script_cap > page_cap * 10
    assert script_cap >= 1_000_000


def test_the_larger_allowance_is_only_for_scripts():
    """An accidental download of a huge asset must still not be read into memory."""
    cage = HttpWebCage()
    assert cage._cap_for("http://t/video.mp4", "video/mp4") == cage.max_body
    assert cage._cap_for("http://t/page", "text/html") == cage.max_body


def test_content_type_alone_is_enough():
    """A bundle served without a .js suffix is still a bundle."""
    cage = HttpWebCage()
    assert cage._cap_for("http://t/asset", "application/javascript") > cage.max_body


def test_the_entry_bundle_is_read_before_lazy_chunks():
    """Alphabetical order is not a priority. `chunk-5K74DZ2F.js` sorts before `main.js`,
    so the crawl spent its whole non-HTML allowance on five lazy chunks, never read the
    entry bundle, and mined eleven routes instead of forty — missing the endpoint that
    carries the application's best-known SQL injection."""
    assert _bundle_rank("/main.js") < _bundle_rank("/chunk-5K74DZ2F.js")
    assert _bundle_rank("/main.js") < _bundle_rank("/polyfills.js")
    assert _bundle_rank("/products") < _bundle_rank("/main.js")


def test_ranking_orders_a_realistic_angular_frontier():
    links = ["/chunk-DYXK4NW4.js", "/polyfills.js", "/main.js", "/styles.css", "/about"]
    ordered = sorted(links, key=lambda u: (_bundle_rank(u), u))
    assert ordered[0] == "/about"
    assert ordered.index("/main.js") < ordered.index("/chunk-DYXK4NW4.js")
    assert ordered.index("/main.js") < ordered.index("/polyfills.js")
