def detect_technologies(response):
    technologies = []

    headers = {
        key.lower(): value.lower()
        for key, value in response.headers.items()
    }

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    # Server detection
    if "cloudflare" in server:
        technologies.append("Cloudflare")

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    # Backend detection
    if "php" in powered_by:
        technologies.append("PHP")

    if "asp.net" in powered_by:
        technologies.append("ASP.NET")

    # Basic HTML detection
    content = getattr(response, "text", "").lower()

    if "wp-content" in content or "wordpress" in content:
        technologies.append("WordPress")

    if "react" in content:
        technologies.append("React")

    if "next.js" in content or "__next" in content:
        technologies.append("Next.js")

    return list(dict.fromkeys(technologies))