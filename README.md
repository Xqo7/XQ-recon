# Python Recon Tool

A modular Python reconnaissance tool built for cybersecurity education
and authorized security testing.

## Features

- DNS lookup
- HTTP metadata collection
- Security header checks
- Basic technology detection
- Domain validation
- Subdomain discovery
- Bounded concurrent DNS discovery
- TCP port discovery
- Port validation
- Common service identification
- JSON reports
- HTML port reports
- CLI interface
- Automated tests

## Project Structure

```text
pythonProject/
├── main.py
├── recon/
│   ├── config.py
│   ├── dns.py
│   ├── http.py
│   ├── security.py
│   ├── tech.py
│   ├── scanner.py
│   ├── subdomains.py
│   ├── ports.py
│   ├── validation.py
│   ├── output.py
│   └── report.py
├── tests/
├── wordlists/
│   └── common.txt
├── reports/
├── logs/
├── requirements.txt
└── README.md

Requirements
- Python 3.14+
- requests
- beautifulsoup4
- dnspython
- pytest
Installation
Create and activate a virtual environment, then install dependencies:

pip install -r requirements.txt

Usage
Full scan

python main.py scan example.com

DNS lookup

python main.py dns example.com

Security headers

python main.py headers example.com

Subdomain discovery

python main.py subdomains example.com

Subdomain discovery with workers

python main.py subdomains example.com --workers 4

Port discovery
Use only against systems you own or are explicitly authorized to test.

python main.py ports 127.0.0.1 --ports 22 80 443

JSON output

python main.py ports 127.0.0.1 --ports 22 80 443 --json

Reports are saved under:

reports/

Testing
Run the complete test suite:
python -m pytest

Version
12.0.0
Disclaimer
This project is intended for cybersecurity education,
lab environments, and authorized security testing only.
Do not scan systems without permission.
