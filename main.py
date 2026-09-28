import argparse

from recon.dns import dns_lookup
from recon.http import http_check
from recon.output import print_results
from recon.report import save_json
from recon.scanner import scan
from recon.security import security_headers_check

from recon.validation import validate_domain

def main():
    parser = argparse.ArgumentParser(
        description="Python Recon Tool"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a full reconnaissance scan"
    )
    scan_parser.add_argument("domain")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON"
    )

    # dns
    dns_parser = subparsers.add_parser(
        "dns",
        help="Perform DNS lookup"
    )
    dns_parser.add_argument("domain")

    # headers
    headers_parser = subparsers.add_parser(
        "headers",
        help="Check HTTP security headers"
    )
    headers_parser.add_argument("domain")
    headers_parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON"
    )

    args = parser.parse_args()
    if not validate_domain(args.domain):
        parser.error(
            f"Invalid domain: {args.domain}"
        )
    if args.command == "scan":
        result = scan(args.domain)
        print_results(result)

        if args.json:
            filename = save_json(result)
            print(f"\nJSON report saved to: {filename}")

    elif args.command == "dns":
        ip = dns_lookup(args.domain)

        if ip:
            print(f"Domain: {args.domain}")
            print(f"IP: {ip}")
        else:
            print(f"Could not resolve {args.domain}")

    elif args.command == "headers":
        response = http_check(args.domain)

        if not response:
            print(f"Could not connect to {args.domain}")
            return

        result = {
            "domain": args.domain,
            "status_code": response.status_code,
            "security_headers": security_headers_check(response),
        }

        for header, value in result["security_headers"].items():
            status = "Present" if value else "Missing"
            print(f"{header}: {status}")

        if args.json:
            filename = save_json(result)
            print(f"\nJSON report saved to: {filename}")


if __name__ == "__main__":
    main()