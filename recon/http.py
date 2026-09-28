import logging
import time

import requests

logger = logging.getLogger(__name__)


def http_check(domain):
    """Send an HTTPS request and return the response."""
    url = f"https://{domain}"

    try:
        start_time = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        elapsed = time.perf_counter() - start_time
        response.response_time = round(elapsed, 3)

        logger.info(
            "HTTP check completed: %s -> %s",
            domain,
            response.status_code
        )

        return response

    except requests.RequestException as error:
        logger.error(
            "HTTP request failed for %s: %s",
            domain,
            error
        )
        return None