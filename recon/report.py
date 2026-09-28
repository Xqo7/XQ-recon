import json
import os
from datetime import datetime, timezone

from .config import APP_NAME, APP_VERSION


def save_json(result):
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