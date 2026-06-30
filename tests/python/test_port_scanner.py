"""
Unit tests for security/reconnaissance/port-scanner.py

Covers the pure-logic pieces of the scanner that don't require network
access or elevated privileges: argument parsing, the ScanType enum, and
the ScanResult data structure.

Run with:
    pytest tests/python/test_port_scanner.py -v
"""
import importlib.util
import sys
from pathlib import Path

import pytest

# port-scanner.py has a hyphen in its filename, so it can't be imported
# with a normal `import` statement. Load it by file path instead.
MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "security"
    / "reconnaissance"
    / "port-scanner.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("port_scanner", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["port_scanner"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scanner():
    return _load_module()


def test_module_loads_without_side_effects(scanner):
    """Importing the module should not start a scan or block on input."""
    assert hasattr(scanner, "ScanType")
    assert hasattr(scanner, "ScanResult")
    assert hasattr(scanner, "parse_args")


def test_scan_type_enum_has_expected_members(scanner):
    names = {member.name for member in scanner.ScanType}
    assert names == {"TCP_CONNECT", "TCP_SYN", "UDP"}


def test_scan_result_defaults(scanner):
    result = scanner.ScanResult(
        port=22,
        is_open=True,
        scan_type=scanner.ScanType.TCP_CONNECT,
    )
    assert result.port == 22
    assert result.is_open is True
    assert result.response_time == 0.0
    assert result.error is None
    assert result.banner is None
    assert result.target == ""


def test_scan_result_is_immutable(scanner):
    result = scanner.ScanResult(
        port=80,
        is_open=False,
        scan_type=scanner.ScanType.TCP_SYN,
    )
    with pytest.raises(AttributeError):
        result.port = 81


@pytest.mark.parametrize(
    "argv,expected_target,expected_ports",
    [
        (["10.0.0.5", "-p", "22,80,443"], "10.0.0.5", "22,80,443"),
        (["scanme.example.com", "-p", "1-1024"], "scanme.example.com", "1-1024"),
    ],
)
def test_parse_args_target_and_ports(scanner, monkeypatch, argv, expected_target, expected_ports):
    monkeypatch.setattr(sys, "argv", ["port-scanner.py", *argv])
    args = scanner.parse_args()
    assert args.target == expected_target
    assert args.ports == expected_ports


def test_parse_args_defaults_when_no_target(scanner, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["port-scanner.py"])
    args = scanner.parse_args()
    assert args.target is None
    assert args.timeout == 1.0
    assert args.rate == 100
    assert args.randomize is False


def test_parse_args_syn_flag_sets_scan_type(scanner, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["port-scanner.py", "10.0.0.5", "-p", "80", "--syn"])
    args = scanner.parse_args()
    assert args.scan_type == scanner.ScanType.TCP_SYN


def test_parse_args_udp_flag_sets_scan_type(scanner, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["port-scanner.py", "10.0.0.5", "-p", "53", "--udp"])
    args = scanner.parse_args()
    assert args.scan_type == scanner.ScanType.UDP
