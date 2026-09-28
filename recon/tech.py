import logging
import re

logger = logging.getLogger(__name__)


def detect_technologies(response):
    """Detect common technologies from HTTP headers and page content."""
    technologies = []

    headers = {
        key.lower(): value.lower()
        for key, value in response.headers.items()
    }

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    # CDN / Web servers
    if "cloudflare" in server or "cf-ray" in headers:
        technologies.append("Cloudflare")

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    # Backend
    if "php" in powered_by:
        technologies.append("PHP")

    if "asp.net" in powered_by:
        technologies.append("ASP.NET")

    # Page content
    content = getattr(response, "text", "").lower()

    if "wp-content" in content or "wordpress" in content:
        technologies.append("WordPress")

    if "react" in content:
        technologies.append("React")

    if "next.js" in content or "__next" in content:
        technologies.append("Next.js")

    # HTML generator tag
    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        content,
        re.IGNORECASE,
    )

    if generator_match:
        generator = generator_match.group(1).strip()

        if generator:
            technologies.append(f"Generator: {generator}")

    # Remove duplicates
    technologies = list(dict.fromkeys(technologies))

    logger.info("Detected technologies: %s", technologies)

    return technologies