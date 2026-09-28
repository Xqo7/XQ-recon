RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("=" * 50)
    print("        PYTHON RECON TOOL")
    print("=" * 50)
    print(f"{RESET}")


def print_results(result):
    print_banner()

    print(f"{BOLD}Domain:{RESET} {result['domain']}")
    print(f"{BOLD}IP:{RESET} {result['ip']}")
    print(f"{BOLD}Status:{RESET} {result['status_code']}")
    print(f"{BOLD}Server:{RESET} {result['server']}")
    print(f"{BOLD}Content-Type:{RESET} {result['content_type']}")
    print(f"{BOLD}Final URL:{RESET} {result['final_url']}")
    print(f"{BOLD}Redirects:{RESET} {result['redirects']}")
    print(f"{BOLD}Response Time:{RESET} {result['response_time']}s")
    print(f"\n{YELLOW}{BOLD}Security Headers:{RESET}")

    for header, value in result["security_headers"].items():
        if value:
            print(f"{GREEN}[+] {header}: {value}{RESET}")
        else:
            print(f"{RED}[-] {header}: Missing{RESET}")

    print(f"\n{BLUE}{BOLD}Technologies:{RESET}")

    if result["technologies"]:
        for technology in result["technologies"]:
            print(f"{GREEN}[+] {technology}{RESET}")
    else:
        print(f"{YELLOW}[-] No technologies detected{RESET}")

    print(f"\n{GREEN}{BOLD}Scan completed.{RESET}")