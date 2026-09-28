# Python Recon Tool

A simple Python reconnaissance tool for learning cybersecurity and network programming.

## Features

- DNS lookup
- IP address resolution
- HTTPS request
- HTTP status code
- Server detection
- Content-Type detection
- Security headers check
- JSON reports
- Command-line arguments

## Requirements

- Python 3.14+
- requests

## Installation

Clone the repository:

```bash
git clone <YOUR_REPOSITORY_URL>
cd pythonProject

Create a virtual environment:
python3 -m venv .venv

Activate it:
source .venv/bin/activate

install dependencies:
python -m pip install -r requirements.txt

Usage
Basic scan:
python recon.py example.com

Save results as JSON:
python recon.py example.com --json

Disclaimer
This project is intended for educational purposes and authorized security testing only.
