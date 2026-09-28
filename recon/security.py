import logging


logger = logging.getLogger(__name__)


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def security_headers_check(response):
    """Check common HTTP security headers."""
    results = {}

    for header in SECURITY_HEADERS:
        value = response.headers.get(header)

        if value:
            results[header] = value
            logger.info("%s: present", header)
        else:
            results[header] = None
            logger.warning("%s: missing", header)

    return results