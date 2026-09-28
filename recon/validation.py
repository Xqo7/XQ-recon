import re


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def validate_domain(domain):
    """Return True if the input is a valid domain name."""
    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    return bool(DOMAIN_PATTERN.fullmatch(domain))