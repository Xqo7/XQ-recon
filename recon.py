import argparse
import json
import logging
import os
import socket

import requests


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

        logging.info(f"HTTP response: {response.status_code}")

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
        "security_headers": {}
    }

    ip = dns_lookup(domain)
    result["ip"] = ip

    if not ip:
        return result

    response = http_check(domain)

    if not response:
        return result

    result["url"] = response.url
    result["status_code"] = response.status_code
    result["server"] = response.headers.get("Server")
    result["content_type"] = response.headers.get("Content-Type")
    result["security_headers"] = security_headers_check(response)

    logging.info(f"Scan completed for {domain}")

    return result


def print_results(result):
    print("\n=== Recon Tool ===")
    print(f"Target: {result['domain']}")

    print("\n--- DNS ---")
    print(f"[+] IP: {result['ip']}")

    print("\n--- HTTP ---")
    print(f"[+] URL: {result['url']}")
    print(f"[+] Status: {result['status_code']}")
    print(f"[+] Server: {result['server']}")
    print(f"[+] Content-Type: {result['content_type']}")

    print("\n--- Security Headers ---")

    for header, value in result["security_headers"].items():
        if value:
            print(f"[+] {header}: Present")
        else:
            print(f"[-] {header}: Missing")


def save_json(result):
    os.makedirs("reports", exist_ok=True)

    filename = f"reports/{result['domain']}.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print(f"\n[+] Report saved to: {filename}")

    logging.info(f"JSON report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Simple Python reconnaissance tool"
    )

    parser.add_argument(
        "domain",
        help="Domain to analyze"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON"
    )

    args = parser.parse_args()

    domain = args.domain.strip()

    result = scan(domain)

    print_results(result)

    if args.json:
        save_json(result)


if __name__ == "__main__":
    main()