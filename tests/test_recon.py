from recon import dns_lookup, security_headers_check, scan, save_json


def test_dns_lookup(monkeypatch):
    monkeypatch.setattr(
        "recon.socket.gethostbyname",
        lambda domain: "93.184.216.34"
    )

    ip = dns_lookup("example.com")

    assert ip == "93.184.216.34"


def test_security_headers_check():
    class FakeResponse:
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY"
        }

    result = security_headers_check(FakeResponse())

    assert result["Content-Security-Policy"] == "default-src 'self'"
    assert result["X-Frame-Options"] == "DENY"


def test_scan(monkeypatch):
    class FakeResponse:
        url = "https://example.com"
        status_code = 200

        headers = {
            "Server": "TestServer",
            "Content-Type": "text/html"
        }

    monkeypatch.setattr(
        "recon.dns_lookup",
        lambda domain: "93.184.216.34"
    )

    monkeypatch.setattr(
        "recon.http_check",
        lambda domain: FakeResponse()
    )

    result = scan("example.com")

    assert result["domain"] == "example.com"
    assert result["ip"] == "93.184.216.34"
    assert result["status_code"] == 200


def test_save_json(tmp_path, monkeypatch):
    result = {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "status_code": 200
    }

    monkeypatch.chdir(tmp_path)

    save_json(result)

    report_file = tmp_path / "reports" / "example.com.json"

    assert report_file.exists()