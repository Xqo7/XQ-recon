import socket
import logging


logger = logging.getLogger(__name__)


def dns_lookup(domain):
    """Resolve a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        logger.info("Resolved %s -> %s", domain, ip)
        return ip

    except socket.gaierror:
        logger.error("Could not resolve %s", domain)
        return None