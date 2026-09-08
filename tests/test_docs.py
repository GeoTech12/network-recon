"""Offline guards for the documentation and static-asset invariants.

These read files from disk (no Flask client, no network). They pin the promises
Milestone 8 makes: the README matches current behaviour and leaks no real data,
the stylesheet pulls in nothing external and adds no new animation, and no
milestone/development wording survives in shipped source.
"""

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
CSS = (ROOT / "src" / "static" / "css" / "style.css").read_text(encoding="utf-8")

# Loopback, the "any" address, RFC1918, and the RFC5737 documentation ranges.
_ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
]


def test_readme_uses_only_example_addresses():
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", README):
        addr = ipaddress.ip_address(token)
        assert any(addr in net for net in _ALLOWED_NETS), (
            f"README contains a non-documentation IP address: {token}"
        )


def test_readme_has_no_real_paths_or_identifiers():
    for bad in ("/home/", "/Users/", "\\Users\\", "jeospellsgo"):
        assert bad not in README, f"README contains identifying string: {bad!r}"


def test_readme_has_no_stale_development_wording():
    for bad in (
        "Milestone",
        "still to come",
        "later milestone",
        "to be implemented",
        "TODO",
        "FIXME",
        "HACK",
    ):
        assert bad not in README, f"README contains stale wording: {bad!r}"


def test_readme_documents_current_behaviour():
    required = [
        "RECON_SUBNET",
        "RECON_RESOLVE_HOSTNAMES",
        "RECON_CHECK_PORTS",
        "127.0.0.1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "reports/",
        ".gitkeep",
        "pytest",
        "Conda",
        "VS Code Remote SSH",
    ]
    for token in required:
        assert token in README, f"README no longer documents: {token!r}"


def test_readme_lists_the_exact_seven_ports():
    for pattern in (
        r"\|\s*21\s*\|\s*FTP",
        r"\|\s*22\s*\|\s*SSH",
        r"\|\s*53\s*\|\s*DNS",
        r"\|\s*80\s*\|\s*HTTP",
        r"\|\s*443\s*\|\s*HTTPS",
        r"\|\s*445\s*\|\s*SMB",
        r"\|\s*3389\s*\|\s*RDP",
    ):
        assert re.search(pattern, README), f"README port table is missing: {pattern}"


def test_stylesheet_has_no_external_resources():
    assert "@import" not in CSS
    assert "http://" not in CSS
    assert "https://" not in CSS
    for ref in re.findall(r"url\(\s*([^)]*)\)", CSS):
        cleaned = ref.strip().strip("\"'")
        assert cleaned.startswith(("#", "data:")), f"external url() in stylesheet: {ref}"


def test_stylesheet_animation_is_limited_and_reduced_motion_safe():
    keyframes = re.findall(r"@keyframes\s+([A-Za-z0-9_-]+)", CSS)
    assert keyframes == ["state-pulse"], f"unexpected @keyframes: {keyframes}"
    assert "@media (prefers-reduced-motion: reduce)" in CSS
    assert "transition" not in CSS


def test_stylesheet_supports_dark_mode_via_media_query_only():
    assert "@media (prefers-color-scheme: dark)" in CSS


def test_shipped_source_has_no_milestone_wording():
    src = ROOT / "src"
    checked = 0
    for path in list(src.rglob("*.py")) + list(src.rglob("*.html")) + list(
        src.rglob("*.js")
    ) + list(src.rglob("*.css")):
        text = path.read_text(encoding="utf-8")
        assert "Milestone" not in text, f"{path.relative_to(ROOT)} contains 'Milestone'"
        assert "later milestone" not in text, (
            f"{path.relative_to(ROOT)} contains 'later milestone'"
        )
        checked += 1
    assert checked > 10
