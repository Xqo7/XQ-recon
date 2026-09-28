import json
import os
from datetime import datetime, timezone

from .config import APP_NAME, APP_VERSION


def save_json(result):
    def save_subdomain_json(domain, results):
        """Save subdomain discovery results as JSON."""
        os.makedirs("reports", exist_ok=True)

        report = {
            "tool": {
                "name": APP_NAME,
                "version": APP_VERSION,
            },
            "scan": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": domain,
                "type": "subdomain_discovery",
            },
            "data": {
                "count": len(results),
                "subdomains": results,
            },
        }

        filename = f"reports/{domain}-subdomains.json"

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        return filename
    """Save scan results as a structured JSON report."""
    os.makedirs("reports", exist_ok=True)

    report = {
        "tool": {
            "name": APP_NAME,
            "version": APP_VERSION,
        },
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": result.get("domain"),
        },
        "data": result,
    }

    filename = f"reports/{result['domain']}.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return filename
def save_subdomain_json(domain, results):
    """Save subdomain discovery results as JSON."""
    os.makedirs("reports", exist_ok=True)

    report = {
        "tool": {
            "name": APP_NAME,
            "version": APP_VERSION,
        },
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": domain,
            "type": "subdomain_discovery",
        },
        "data": {
            "count": len(results),
            "subdomains": results,
        },
    }

    filename = f"reports/{domain}-subdomains.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return filename