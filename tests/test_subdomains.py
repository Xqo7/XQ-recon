import json

from recon.subdomains import discover_subdomains
from recon.report import save_subdomain_json


def test_discover_subdomains(monkeypatch):
    fake_dns = {
        "www.example.com": "93.184.216.34",
        "api.example.com": "93.184.216.35",
    }

    def fake_dns_lookup(domain):
        return fake_dns.get(domain)

    monkeypatch.setattr(
        "recon.subdomains.dns_lookup",
        fake_dns_lookup
    )

    wordlist = [
        "www",
        "api",
        "missing",
    ]

    result = discover_subdomains(
        "example.com",
        wordlist
    )

    assert len(result) == 2
    assert result[0]["subdomain"] == "www.example.com"
    assert result[0]["ip"] == "93.184.216.34"
    assert result[1]["subdomain"] == "api.example.com"


def test_save_subdomain_json(tmp_path, monkeypatch):
    result = [
        {
            "subdomain": "www.example.com",
            "ip": "93.184.216.34",
        },
        {
            "subdomain": "api.example.com",
            "ip": "93.184.216.35",
        },
    ]

    monkeypatch.chdir(tmp_path)

    filename = save_subdomain_json(
        "example.com",
        result
    )

    report_file = (
        tmp_path
        / "reports"
        / "example.com-subdomains.json"
    )

    assert report_file.exists()
    assert filename == "reports/example.com-subdomains.json"

    with open(report_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["scan"]["target"] == "example.com"
    assert report["scan"]["type"] == "subdomain_discovery"
    assert report["data"]["count"] == 2
    assert len(report["data"]["subdomains"]) == 2

def test_discover_subdomains_with_workers(monkeypatch):
        fake_dns = {
            "www.example.com": "93.184.216.34",
            "api.example.com": "93.184.216.35",
            "dev.example.com": "93.184.216.36",
        }

        def fake_dns_lookup(domain):
            return fake_dns.get(domain)

        monkeypatch.setattr(
            "recon.subdomains.dns_lookup",
            fake_dns_lookup
        )

        wordlist = [
            "www",
            "api",
            "dev",
            "missing",
        ]

        result = discover_subdomains(
            "example.com",
            wordlist,
            max_workers=2
        )

        assert len(result) == 3
        assert result[0]["subdomain"] == "www.example.com"
        assert result[1]["subdomain"] == "api.example.com"
        assert result[2]["subdomain"] == "dev.example.com"