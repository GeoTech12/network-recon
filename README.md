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

> This is the Milestone 1 skeleton: the web interface loads and the scan button
> is a placeholder. Network discovery and reporting are added in later
> milestones. Full documentation is part of Milestone 8.
