from tech_detect import detect_technologies


def test_detect_cloudflare():
    class FakeResponse:
        headers = {
            "Server": "cloudflare"
        }

        text = ""

    result = detect_technologies(FakeResponse())

    assert "Cloudflare" in result


def test_detect_wordpress():
    class FakeResponse:
        headers = {}

        text = """
        <html>
            <link href="/wp-content/themes/test/style.css">
        </html>
        """

    result = detect_technologies(FakeResponse())

    assert "WordPress" in result