import logging
from concurrent.futures import ThreadPoolExecutor

from .dns import dns_lookup

logger = logging.getLogger(__name__)


def _check_subdomain(word, domain):
    word = word.strip()

    if not word:
        return None

    subdomain = f"{word}.{domain}"
    ip = dns_lookup(subdomain)

    if ip:
        return {
            "subdomain": subdomain,
            "ip": ip,
        }

    return None


def discover_subdomains(domain, wordlist, max_workers=4):
    """Discover subdomains using bounded concurrent DNS lookups."""
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(
            _check_subdomain,
            wordlist,
            [domain] * len(wordlist),
        )

        for result in results:
            if result:
                found.append(result)

    logger.info(
        "Subdomain discovery completed for %s: %d found",
        domain,
        len(found),
    )

    return found