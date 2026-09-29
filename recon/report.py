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
def save_port_json(host, results):
    """Save port scan results as JSON."""
    os.makedirs("reports", exist_ok=True)

    report = {
        "tool": {
            "name": APP_NAME,
            "version": APP_VERSION,
        },
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": host,
            "type": "port_scan",
        },
        "data": {
            "count": len(results),
            "ports": results,
        },
    }

    filename = f"reports/{host}-ports.json"

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return filename
def save_html_report(host, results):
    """Save a simple HTML port scan report."""
    os.makedirs("reports", exist_ok=True)

    rows = ""

    for result in results:
        status = "OPEN" if result["open"] else "CLOSED"

        rows += f"""
        <tr>
            <td>{result["port"]}</td>
            <td>{result["service"]}</td>
            <td>{status}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Python Recon Tool - Port Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background: #f2f2f2;
        }}
    </style>
</head>
<body>
    <h1>Python Recon Tool</h1>

    <h2>Port Scan Report</h2>

    <p>
        <strong>Target:</strong> {host}
    </p>

    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Status</th>
        </tr>

        {rows}
    </table>
</body>
</html>
"""

    filename = f"reports/{host}-ports.html"

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)

    return filename