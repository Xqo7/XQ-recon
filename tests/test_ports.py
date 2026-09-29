import json
import pytest

from recon.ports import (
    check_port,
    scan_ports,
    validate_port,
)
from recon.report import save_port_json


def test_check_port_open(monkeypatch):
    monkeypatch.setattr(
        "recon.ports.socket.socket.connect_ex",
        lambda self, address: 0
    )

    assert check_port("127.0.0.1", 443) is True


def test_check_port_closed(monkeypatch):
    monkeypatch.setattr(
        "recon.ports.socket.socket.connect_ex",
        lambda self, address: 1
    )

    assert check_port("127.0.0.1", 443) is False


def test_scan_ports(monkeypatch):
    def fake_check_port(host, port, timeout=1.0):
        return port == 443

    monkeypatch.setattr(
        "recon.ports.check_port",
        fake_check_port
    )

    result = scan_ports(
        "127.0.0.1",
        [80, 443, 8080]
    )

    assert result == [
        {
            "port": 80,
            "open": False,
            "service": "HTTP",
        },
        {
            "port": 443,
            "open": True,
            "service": "HTTPS",
        },
        {
            "port": 8080,
            "open": False,
            "service": "HTTP-Proxy",
        },
    ]


def test_valid_ports():
    assert validate_port(1) is True
    assert validate_port(80) is True
    assert validate_port(443) is True
    assert validate_port(65535) is True


def test_invalid_ports():
    assert validate_port(0) is False
    assert validate_port(-1) is False
    assert validate_port(65536) is False
    assert validate_port(99999) is False


def test_invalid_port_raises_error():
    with pytest.raises(ValueError):
        check_port("127.0.0.1", 70000)


def test_save_port_json(tmp_path, monkeypatch):
    results = [
        {"port": 80, "open": True},
        {"port": 443, "open": False},
    ]

    monkeypatch.chdir(tmp_path)

    filename = save_port_json(
        "127.0.0.1",
        results
    )

    report_file = (
        tmp_path
        / "reports"
        / "127.0.0.1-ports.json"
    )

    assert report_file.exists()
    assert filename == "reports/127.0.0.1-ports.json"

    with open(
        report_file,
        "r",
        encoding="utf-8"
    ) as file:
        report = json.load(file)

    assert report["scan"]["target"] == "127.0.0.1"
    assert report["scan"]["type"] == "port_scan"
    assert report["data"]["count"] == 2
    assert report["data"]["ports"][0]["port"] == 80