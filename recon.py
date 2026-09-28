import socket
import requests


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

    except requests.RequestException as error:
        print(f"[-] HTTP request failed: {error}")


def main():
    domain = input("Enter domain: ").strip()

    print("\n--- DNS Lookup ---")
    ip = dns_lookup(domain)

    if ip:
        print("\n--- HTTP Check ---")
        http_check(domain)


if __name__ == "__main__":
    main()