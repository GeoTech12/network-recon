# network-recon
Python-based network reconnaissance tool for authorized home-lab device discovery and reporting.

> **Authorized use only.** Use this tool exclusively on networks you own or have
> explicit permission to assess.

## Getting started (development)

The project targets **Python 3.11** and uses the Conda environment named
`network-recon`.

```bash
# 1. Activate the environment
conda activate network-recon

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the development server
python src/main.py
```

Then open <http://127.0.0.1:5000> in a browser. The server binds to localhost
only and runs with debugging disabled by default.

### Running the tests

```bash
pytest
```

The test suite never touches the network: host discovery is faked or
monkeypatched in every test.

## How discovery works (Milestone 2)

When you start a scan the application:

1. Determines the target subnet &mdash; either the value of the optional
   `RECON_SUBNET` environment variable, or the machine's own connected private
   subnet read from the Linux routing table. If the local network cannot be
   determined unambiguously it fails with a clear message rather than guessing.
2. Validates that subnet: it must sit wholly inside `10.0.0.0/8`,
   `172.16.0.0/12`, or `192.168.0.0/16`, and contain no more than 256 addresses
   (a `/24` or smaller). Public or oversized targets are refused before any
   packet is sent.
3. Sends a single ICMP echo request to each address by invoking the system
   `ping` command (fixed arguments, no shell, no retries, no elevated
   privileges). Addresses that reply are reported as responsive hosts.

No ports are scanned. Scan results are returned to your browser only &mdash;
nothing is written to disk or logged.

### Device information

Each responsive host is then enriched, best effort:

* **MAC address** &mdash; read from this machine's existing ARP cache
  (`/proc/net/arp`), which the ping sweep populates for hosts on the same
  network segment. Only complete, valid entries are used. Nothing is inferred or
  actively probed, so a host that is not in the cache simply shows no MAC.
* **Hostname** &mdash; a reverse-DNS (PTR) lookup, and **only if you opt in** by
  setting `RECON_RESOLVE_HOSTNAMES=1`. It is off by default, in which case no
  name resolution happens at all. Many home devices have no PTR record, so a
  blank hostname is common and never fails the scan.

Example fictional values used in this documentation: IPs like `192.0.2.10`,
hostnames like `desktop-lab` or `printer-demo`, MACs like `52:54:00:1a:2b:3c`.

Set an explicit subnet, or enable hostname resolution, like this:

```bash
RECON_SUBNET=192.168.1.0/24 RECON_RESOLVE_HOSTNAMES=1 python src/main.py
```

> Milestones beyond host discovery (device details, port checks, reporting, UI
> polish) are still to come. Full documentation is part of Milestone 8.
