import logging
import socket

logger = logging.getLogger(__name__)


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
}


def validate_port(port):
    """Return True if a port is valid."""
    return isinstance(port, int) and 1 <= port <= 65535


def identify_service(port):
    """Return the commonly associated service for a TCP port."""
    return COMMON_SERVICES.get(port, "Unknown")


def check_port(host, port, timeout=1.0):
    """Check whether a TCP port is accepting connections."""

    if not validate_port(port):
        raise ValueError(
            f"Invalid port: {port}. "
            "Port must be between 1 and 65535."
        )

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex(
                (host, port)
            )

            return result == 0

    except OSError as error:
        logger.debug(
            "Port check failed for %s:%s - %s",
            host,
            port,
            error,
        )

        return False


def scan_ports(host, ports, timeout=1.0):
    """Scan a limited list of TCP ports."""
    results = []

    for port in ports:
        is_open = check_port(
            host,
            port,
            timeout
        )

        results.append({
            "port": port,
            "open": is_open,
            "service": identify_service(port),
        })

    logger.info(
        "Port scan completed for %s",
        host,
    )

    return results