import argparse
import json
import logging
import os
import socket

import requests

# =========================
# COLORS
# =========================

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"

from tech_detect import detect_technologies


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


# Create logs folder
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    filename="logs/recon.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def dns_lookup(domain):
    logging.info(f"Starting DNS lookup for {domain}")

    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"Resolved {domain} to {ip}")
        return ip

    except socket.gaierror:
        logging.error(f"Could not resolve {domain}")
        return None


def http_check(domain):
    url = f"https://{domain}"

    logging.info(f"Sending HTTPS request to {url}")

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        logging.info(
            f"HTTP response received: {response.status_code}"
        )

        return response

    except requests.RequestException as error:
        logging.error(f"HTTP request failed: {error}")
        return None


def security_headers_check(response):
    headers = {}

    for header in SECURITY_HEADERS:
        headers[header] = response.headers.get(header)

    return headers


def scan(domain):
    logging.info(f"Starting scan for {domain}")

    result = {
        "domain": domain,
        "ip": None,
        "url": None,
        "status_code": None,
        "server": None,
        "content_type": None,
        "security_headers": {},
        "technologies": []
    }

    # DNS lookup
    ip = dns_lookup(domain)
    result["ip"] = ip

    if not ip:
        return result

    # HTTP check
    response = http_check(domain)

    if not response:
        return result

    # Basic HTTP information
    result["url"] = response.url
    result["status_code"] = response.status_code
    result["server"] = response.headers.get("Server")
    result["content_type"] = response.headers.get("Content-Type")

    # Security headers
    result["security_headers"] = security_headers_check(response)

    # Technology detection
    result["technologies"] = detect_technologies(response)

    logging.info(f"Scan completed for {domain}")

    return result

def print_banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════╗
║        PYTHON CYBERSECURITY          ║
║             RECON TOOL               ║
╚══════════════════════════════════════╝
{RESET}""")

def print_results(result):
    print_banner()

    print(f"{BOLD}Target:{RESET} {result['domain']}")

    print(f"\n{CYAN}{BOLD}--- DNS ---{RESET}")

    if result["ip"]:
        print(f"{GREEN}[+]{RESET} IP: {result['ip']}")
    else:
        print(f"{RED}[-]{RESET} DNS lookup failed")

    print(f"\n{CYAN}{BOLD}--- HTTP ---{RESET}")

    if result["url"]:
        print(f"{GREEN}[+]{RESET} URL: {result['url']}")
        print(f"{GREEN}[+]{RESET} Status: {result['status_code']}")
        print(f"{GREEN}[+]{RESET} Server: {result['server']}")
        print(f"{GREEN}[+]{RESET} Content-Type: {result['content_type']}")
    else:
        print(f"{RED}[-]{RESET} HTTP request failed")

    print(f"\n{CYAN}{BOLD}--- Security Headers ---{RESET}")

    for header, value in result["security_headers"].items():

        if value:
            print(
                f"{GREEN}[+]{RESET} "
                f"{header}: {value}"
            )
        else:
            print(
                f"{RED}[-]{RESET} "
                f"{header}: Missing"
            )

    print(f"\n{CYAN}{BOLD}--- Technologies ---{RESET}")

    if result["technologies"]:

        for technology in result["technologies"]:
            print(
                f"{GREEN}[+]{RESET} "
                f"{technology}"
            )

    else:
        print(
            f"{YELLOW}[!]{RESET} "
            "No technologies detected"
        )

    print(f"\n{CYAN}{BOLD}=============================={RESET}")
    print(f"{GREEN}{BOLD}Scan completed successfully.{RESET}")
    print(f"{CYAN}{BOLD}=============================={RESET}\n")


def save_json(result):
    os.makedirs("reports", exist_ok=True)

    filename = f"reports/{result['domain']}.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print(f"\n[+] Report saved to: {filename}")

    logging.info(f"JSON report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Python Cybersecurity Recon Tool"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # =========================
    # SCAN COMMAND
    # =========================

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a full reconnaissance scan"
    )

    scan_parser.add_argument(
        "domain",
        help="Domain to analyze"
    )

    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON"
    )

    # =========================
    # DNS COMMAND
    # =========================

    dns_parser = subparsers.add_parser(
        "dns",
        help="Resolve a domain to an IP address"
    )

    dns_parser.add_argument(
        "domain",
        help="Domain to resolve"
    )

    # =========================
    # HEADERS COMMAND
    # =========================

    headers_parser = subparsers.add_parser(
        "headers",
        help="Check security headers"
    )

    headers_parser.add_argument(
        "domain",
        help="Domain to check"
    )

    headers_parser.add_argument(
        "--json",
        action="store_true",
        help="Save headers as JSON"
    )

    # =========================
    # PARSE ARGUMENTS
    # =========================

    args = parser.parse_args()

    # =========================
    # SCAN
    # =========================

    if args.command == "scan":

        domain = args.domain.strip()

        result = scan(domain)

        print_results(result)

        if args.json:
            save_json(result)

    # =========================
    # DNS
    # =========================

    elif args.command == "dns":

        domain = args.domain.strip()

        ip = dns_lookup(domain)

        if ip:
            print(f"\n[+] {domain} -> {ip}")
        else:
            print("[-] DNS lookup failed")

    # =========================
    # SECURITY HEADERS
    # =========================

    elif args.command == "headers":

        domain = args.domain.strip()

        response = http_check(domain)

        if not response:
            print("[-] HTTP request failed")
            return

        headers = security_headers_check(response)

        print("\n=== Security Headers ===")
        print(f"Target: {domain}\n")

        for header, value in headers.items():

            if value:
                print(f"[+] {header}: {value}")
            else:
                print(f"[-] {header}: Missing")

        if args.json:

            result = {
                "domain": domain,
                "security_headers": headers
            }

            save_json(result)


if __name__ == "__main__":
    main()
