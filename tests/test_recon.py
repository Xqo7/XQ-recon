from recon import dns_lookup, security_headers_check, scan, save_json


def test_dns_lookup(monkeypatch):
    monkeypatch.setattr(
        "recon.dns.socket.gethostbyname",
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
        text = ""
        response_time = 0.123
        history = []

    monkeypatch.setattr(
        "recon.scanner.dns_lookup",
        lambda domain: "93.184.216.34"
    )

    monkeypatch.setattr(
        "recon.scanner.http_check",
        lambda domain: FakeResponse()
    )

    result = scan("example.com")

    assert result["domain"] == "example.com"
    assert result["ip"] == "93.184.216.34"
    assert result["status_code"] == 200
    assert result["final_url"] == "https://example.com"
    assert result["redirects"] == 0
    assert result["response_time"] == 0.123


def test_save_json(tmp_path, monkeypatch):
    result = {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "status_code": 200,
    }

    monkeypatch.chdir(tmp_path)

    save_json(result)

    report_file = tmp_path / "reports" / "example.com.json"

    assert report_file.exists()


def test_save_json_structure(tmp_path, monkeypatch):
    result = {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "status_code": 200,
    }

    monkeypatch.chdir(tmp_path)

    save_json(result)

    report_file = tmp_path / "reports" / "example.com.json"

    assert report_file.exists()

    import json

    with open(report_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["tool"]["name"] == "Python Recon Tool"
    assert report["tool"]["version"] == "12.0.0"
    assert report["scan"]["target"] == "example.com"
    assert "timestamp" in report["scan"]
    assert report["data"]["status_code"] == 200