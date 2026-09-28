import argparse
import socket
import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
        return ip
    except socket.gaierror:
        print("[-] Could not resolve domain.")
        return None


def http_check(domain):
    url = f"https://{domain}"

    try:
        response = requests.get(url, timeout=5)

        print(f"[+] URL: {url}")
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
        print(f"[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")

        return response

    except requests.RequestException as error:
        print(f"[-] HTTP request failed: {error}")
        return None


def security_headers_check(response):
    print("\n--- Security Headers ---")

    for header in SECURITY_HEADERS:
        value = response.headers.get(header)

        if value:
            print(f"[+] {header}: Present")
        else:
            print(f"[-] {header}: Missing")


def main():
    parser = argparse.ArgumentParser(
        description="Simple Python reconnaissance tool"
    )

    parser.add_argument(
        "domain",
        help="Domain to analyze"
    )

    args = parser.parse_args()

    domain = args.domain.strip()

    print(f"\n=== Recon Tool ===")
    print(f"Target: {domain}")

    print("\n--- DNS Lookup ---")
    ip = dns_lookup(domain)

    if not ip:
        return

    print("\n--- HTTP Check ---")
    response = http_check(domain)

    if response:
        security_headers_check(response)


if __name__ == "__main__":
    main()