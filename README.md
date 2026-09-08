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

No ports are scanned and no hostnames or MAC addresses are collected yet; those
columns are placeholders for later milestones. Scan results are returned to your
browser only &mdash; nothing is written to disk.

Set an explicit subnet like this if auto-detection is not suitable:

```bash
RECON_SUBNET=192.168.1.0/24 python src/main.py
```

> Milestones beyond host discovery (device details, port checks, reporting, UI
> polish) are still to come. Full documentation is part of Milestone 8.
