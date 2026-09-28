import logging

from .dns import dns_lookup
from .http import http_check
from .security import security_headers_check
from .tech import detect_technologies

logger = logging.getLogger(__name__)


def scan(domain):
    """Run a complete reconnaissance scan."""
    logger.info("Starting scan for %s", domain)

    ip = dns_lookup(domain)
    response = http_check(domain)

    result = {
        "final_url": None,
        "redirects": 0,
        "response_time": None,
        "domain": domain,
        "ip": ip,
        "status_code": None,
        "server": None,
        "content_type": None,
        "security_headers": {},
        "technologies": [],
    }

    if response:
        result["final_url"] = response.url
        result["redirects"] = len(response.history)
        result["response_time"] = response.response_time
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["security_headers"] = security_headers_check(response)
        result["technologies"] = detect_technologies(response)

    logger.info("Scan completed for %s", domain)

    return result