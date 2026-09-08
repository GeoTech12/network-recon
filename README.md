# Network Recon

A small, browser-based tool for **authorized** reconnaissance of a home or lab
network. It discovers active devices on your local IPv4 subnet and presents what
it finds — IP address, MAC address, hostname, status, and a few common open
ports — in a clear web page instead of raw terminal output.

> **Authorized use only.** Use this tool exclusively on networks you own or have
> explicit written permission to assess.

---

## Overview and purpose

Network Recon was built for a cybersecurity penetration-testing and ethical-hacking
course. It demonstrates the **reconnaissance phase** of an assessment —
discovery and identification — while staying deliberately non-intrusive. It is
intended for:

- home networks and cybersecurity labs,
- small test networks and classroom demonstrations,
- authorized security-testing environments.

It is a discovery tool, not an exploitation tool.

## Ethical use and restrictions

The application must only be pointed at a network you **own** or are **explicitly
authorized** to assess. It is not intended to scan arbitrary Internet targets.

By design it does **not**:

- attempt authentication or log in to anything,
- exploit vulnerabilities,
- perform brute-force or password attacks,
- conduct denial-of-service testing,
- grab service banners or read any application data,
- scan UDP ports,
- use raw packet sockets, `nmap`, or any external scanner,
- request or use root / `sudo` privileges,
- modify, persist on, or install anything on remote systems.

The web page shows an authorization notice and requires you to tick a
confirmation checkbox before a scan can start.

## Features

- Auto-detects your connected private subnet, or accepts an explicit one.
- Enforces an RFC1918-only, `/24`-or-smaller target boundary.
- ICMP host discovery: one echo request per address, no retries.
- Best-effort MAC address lookup from the local ARP cache.
- Optional, opt-in reverse-DNS hostname resolution.
- Optional, opt-in checks of seven common TCP ports.
- A responsive dashboard with clear ready / scanning / completed / error states.
- Optional local HTML report generation.
- Runs entirely on `localhost`; loads no external web resources.

## Requirements

| Requirement | Notes |
| --- | --- |
| Linux (Ubuntu) | The tool reads `/proc/net/route` and `/proc/net/arp` and calls the system `ping` (iputils). It does not run on Windows or macOS. |
| Python 3.11 | Provided by the Conda environment below. |
| Conda | Used to manage the `network-recon` environment. |
| System `ping` | Part of `iputils-ping`, preinstalled on Ubuntu. Used unprivileged. |
| A private IPv4 LAN | The target must be inside `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`. |
| A modern web browser | For the dashboard. |

## Installation

The project uses an existing Conda environment named `network-recon`
(Python 3.11).

```bash
# 1. Activate the environment
conda activate network-recon

# 2. Install the Python dependencies
pip install -r requirements.txt
```

Dependencies are intentionally minimal: **Flask** for the web application and
**pytest** for the test suite.

## Running the application

```bash
conda activate network-recon
python src/main.py
```

Then open <http://127.0.0.1:5000> in a browser.

- The server binds to **`127.0.0.1` only**. It is never exposed on the LAN.
- The Werkzeug debugger is **off** unless you explicitly set `FLASK_DEBUG=1`
  (only do this locally; never on a shared host).
- This is the Flask development server — fine for local use, not a production
  deployment.

### Running over VS Code Remote SSH

If you run `python src/main.py` on a remote host over SSH, the server still binds
`127.0.0.1` **on that remote host**. Reach it from your laptop with port
forwarding:

- VS Code's Remote SSH usually forwards a detected port automatically (a
  notification appears); otherwise add it in the **Ports** panel, or
- run `ssh -L 5000:127.0.0.1:5000 <host>` and open <http://127.0.0.1:5000>
  locally.

Do **not** change the bind address to `0.0.0.0` to "make it reachable" — that
would expose a reconnaissance tool on the network and defeats the localhost-only
design. Forward the port instead.

## Usage — running a scan

1. Open <http://127.0.0.1:5000>.
2. Read the **Authorization & Ethical Use** notice.
3. Tick **"I confirm I am authorized to perform reconnaissance on this network."**
4. Click **Start Scan**.
5. Watch the status banner move through **Ready → Scanning → Completed** (or
   **Error**, with a friendly message).
6. Read the results: a summary line (network, devices found, whether port checks
   ran, scan time) and a per-host table.
7. Optionally click **Save report** to write a local HTML report.

## How it works

### Target selection and safety restrictions

When a scan starts, the application determines the target subnet:

- if the `RECON_SUBNET` environment variable is set, that value is used;
- otherwise the machine's connected private subnet is read from the Linux
  routing table. If it cannot be determined unambiguously, the scan fails with a
  clear message rather than guessing.

The subnet is then validated. It **must**:

- sit wholly inside `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`
  (checked by explicit containment — not Python's `ipaddress.is_private`, which
  also treats link-local and carrier-grade-NAT ranges as "private"), and
- contain no more than 256 addresses (a `/24` or smaller).

Public, oversized, or malformed targets are rejected **before any packet is
sent**. The same validation runs again inside the discovery layer and the
port-check layer as defense in depth.

### Host discovery

For each address in the validated subnet, the application sends **one ICMP echo
request** by invoking the system `ping` command with a fixed argument list
(`ping -n -q -c 1 -W 1 <ip>`), `shell=False`, no retries, a short per-probe
timeout, bounded concurrency (16 workers), and a 90-second overall deadline. No
raw sockets and no elevated privileges are involved. Addresses that reply are
reported as responsive hosts.

Hosts that filter ICMP (for example some firewalled or Windows machines) will
not be discovered — see [Known limitations](#known-limitations).

### MAC address enrichment

For each responsive host, the application reads the kernel's existing ARP cache
(`/proc/net/arp`), which the ping sweep populates for hosts on the same network
segment. Only complete, valid **unicast** entries are used; broadcast,
multicast, and all-zero addresses are ignored. Nothing is inferred or actively
probed, so a host that is not in the cache simply shows no MAC address. Missing
MAC information is normal and never fails the scan.

### Hostname resolution (optional, off by default)

Reverse-DNS (PTR) lookups are **disabled by default**. When disabled, the
application performs no name resolution of any kind.

Enable it by setting `RECON_RESOLVE_HOSTNAMES=1`:

```bash
RECON_RESOLVE_HOSTNAMES=1 python src/main.py
```

When enabled, each responsive host is reverse-resolved through the system
resolver, with bounded concurrency and a deadline. This **discloses the
discovered IP addresses to your configured DNS resolver**, which is why it is
opt-in. Many home devices have no PTR record, so a blank hostname is common and
never fails the scan. In the table, a missing hostname shows as *"Unknown"* when
resolution is on and *"Not resolved"* when it is off.

### Common TCP port checks (optional, off by default)

TCP port checks are **disabled by default**. When disabled, no sockets are
opened for port checking and the table shows *"Not checked"*.

Enable them by setting `RECON_CHECK_PORTS=1`:

```bash
RECON_CHECK_PORTS=1 python src/main.py
```

When enabled, each responsive host is checked against this fixed list of seven
TCP ports — and only these:

| Port | Service | Why it is checked |
| ---- | ------- | ----------------- |
| 21   | FTP     | legacy cleartext file transfer (NAS, routers, printers) |
| 22   | SSH     | remote administration (servers, single-board computers, NAS, managed switches) |
| 53   | DNS     | TCP DNS exposed by local resolvers (routers, Pi-hole / dnsmasq) |
| 80   | HTTP    | device and server web interfaces |
| 443  | HTTPS   | TLS device and server web interfaces |
| 445  | SMB     | Windows / Samba file sharing |
| 3389 | RDP     | Windows Remote Desktop |

Each port gets **one** plain TCP connect attempt: 1-second timeout, no retries,
bounded concurrency (16 workers), 60-second overall deadline. On a successful
connection the socket is closed immediately — nothing is sent and nothing is
read, so there is **no banner grabbing, no authentication, no application data,
and no UDP**. Only open ports are reported; closed, filtered, and timed-out
ports are omitted and never fail the scan. A host with no open ports from the
list shows *"None found"*. Connecting and closing may leave a harmless entry in
the target device's own logs.

### When to use `RECON_SUBNET`

Normally leave `RECON_SUBNET` unset and let the application auto-detect. Set it
when:

- auto-detection is ambiguous — the machine is multi-homed, a VM, or a
  container with several connected networks;
- your LAN is larger than a `/24` and you want to scan one `/24` slice of it;
- the machine running the server (for example a Remote SSH host) has routing
  that does not match the network you intend to assess.

The value is a CIDR string and is validated the same way as an auto-detected
subnet (private range, `/24` or smaller):

```bash
RECON_SUBNET=192.168.1.0/24 python src/main.py
```

## Local reports

After a scan completes, the **Save report** button writes a single
self-contained HTML file to the local `reports/` directory, for example
`reports/network-recon-20260908-143200.html`. A report is generated **only when
you click the button** — running a scan writes nothing to disk.

- The filename is generated by the server from a fixed timestamp pattern; the
  request cannot influence the path, and the file is always written inside
  `reports/`.
- The report is a plain HTML document with no scripts and no external
  references. Open it from your file manager — the application does not serve it
  back.
- It is never uploaded anywhere, and its contents are never logged.

**A report contains sensitive information about your network** — IP and MAC
addresses, hostnames, and open ports. Keep it local.

**Generated reports are Git-ignored.** `.gitignore` ignores everything under
`reports/` except `reports/.gitkeep`, so reports are never committed. Do not
share or commit them, and review `git status` before pushing.

## Testing

```bash
conda activate network-recon
pytest
```

The suite also passes with warnings treated as errors:

```bash
pytest -W error
```

Every test is **fully offline**. Each reconnaissance primitive is faked or
monkeypatched, and an autouse fixture in `tests/conftest.py` makes any real
`subprocess.run` or socket call fail the test. All test data uses fictional or
documentation-range addresses.

## Project structure

```
network-recon/
├── README.md
├── requirements.txt
├── pyproject.toml            # pytest configuration
├── .gitignore
├── reports/
│   └── .gitkeep              # generated reports land here (Git-ignored)
├── src/
│   ├── main.py               # dev-server entry point
│   ├── app.py                # Flask app factory, error handlers, security headers
│   ├── config.py             # settings + RECON_* environment flags
│   ├── routes.py             # /, /scan, /report, /healthz
│   ├── recon/
│   │   ├── localnet.py       # subnet detection + RFC1918 / size validation
│   │   ├── discovery.py      # ICMP host discovery
│   │   ├── enrichment.py     # MAC (ARP cache) + optional reverse-DNS hostname
│   │   ├── portscan.py       # optional common-TCP-port checks
│   │   ├── reporting.py      # local HTML report generation
│   │   └── errors.py         # reconnaissance-layer exceptions
│   ├── templates/            # base, index (dashboard), report, 404, 500
│   └── static/
│       ├── css/style.css
│       └── js/main.js
└── tests/                    # offline test suite
```

## Security and privacy design decisions

- **Localhost only.** The server binds `127.0.0.1`; the debugger is off by
  default.
- **Authorization gate.** A scan requires the confirmation checkbox, and `/scan`
  and `/report` accept only `application/json` request bodies. A cross-site form
  or `text/plain` post is rejected, and requiring JSON forces a CORS preflight
  the application does not answer — so another website cannot silently start a
  scan.
- **Strict headers.** A `Content-Security-Policy` limits the page to same-origin
  resources (`default-src 'self'; frame-ancestors 'none'; object-src 'none'`),
  plus `X-Content-Type-Options: nosniff`.
- **No external resources at all.** No fonts, scripts, stylesheets, images,
  CDNs, analytics, or trackers. System fonts only.
- **Bounded, non-intrusive scanning.** Target confined to a private `/24` (or
  smaller), enforced in three layers; one probe per host/port; no retries;
  per-probe and overall deadlines.
- **Privacy-sensitive features are opt-in.** Reverse-DNS resolution and TCP port
  checks are off by default and their privacy cost is stated in the UI.
- **No persistence, no logging of device data.** Scan results live only in the
  page. Nothing is written to disk unless you explicitly save a report, and
  report contents are never logged.
- **No browser storage.** No `localStorage`, `sessionStorage`, or cookies. The
  page inserts every dynamic value with `textContent` — never `innerHTML`.
- **Safe report generation.** Report HTML is autoescaped by Jinja and is
  self-contained; filenames are server-generated and validated; writes are
  confined to `reports/` with a path-traversal guard.
- **Safe subprocess use.** `ping` is invoked with a fixed argument list and
  `shell=False`; the target IP is validated before use.

## Known limitations

- **Linux/Ubuntu only** — depends on `/proc/net/route`, `/proc/net/arp`, and the
  iputils `ping`.
- **IPv4 only.**
- **One flat subnet, `/24` or smaller** — by design.
- **ICMP-filtered hosts are missed** — devices that drop echo requests (some
  firewalled or Windows hosts) will not appear.
- **MAC addresses are best effort** — only for hosts on the same L2 segment that
  are present in the ARP cache.
- **Hostnames depend on your resolver** — many home devices have no PTR record.
- **Port checks are a tiny, fixed, connect-only list** — this is not, and is not
  meant to be, a full port scanner.
- **The scan is synchronous** — the browser request blocks for a few seconds
  until the sweep finishes.
- **Development server** — Werkzeug's server, not for production.
- **No application authentication** — mitigated by the localhost-only bind.

## Screenshot

A sanitized screenshot of the dashboard accompanies the assignment submission.
Screenshots use demonstration data only — no real device names, IP addresses,
or MAC addresses.
