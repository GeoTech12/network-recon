"""Entry point for running the Network Recon development server.

Usage:
    conda activate network-recon
    python src/main.py

Then open http://127.0.0.1:5000 in a browser.
"""

from app import create_app
import config

app = create_app()

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=app.config["DEBUG"])
