#!/usr/bin/env python3
"""
Advanced Python Port Scanner

Features:
- TCP Connect scanning
- TCP SYN scanning (requires root/admin + scapy)
- UDP scanning (requires root/admin + scapy)
- Interactive mode
- CLI mode
- Rate limiting
- Banner grabbing
- Result reporting

License: MIT
"""

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT_DIR = Path(__file__).resolve().parents[2]


SCANNER_LOCATIONS = [
    ROOT_DIR / "tools" / "security" / "reconnaissance" / "port-scanner.py",
    ROOT_DIR / "security" / "reconnaissance" / "port-scanner.py",
]


def _find_scanner():

    for path in SCANNER_LOCATIONS:

        if path.exists():
            return path

    raise FileNotFoundError(
        "Unable to locate port-scanner.py. "
        f"Checked: {SCANNER_LOCATIONS}"
    )


def _load_module():

    scanner_path = _find_scanner()

    spec = importlib.util.spec_from_file_location(
        "port_scanner",
        scanner_path,
    )

    module = importlib.util.module_from_spec(spec)

    sys.modules["port_scanner"] = module

    spec.loader.exec_module(module)

    return module


@pytest.fixture(scope="module")
def scanner():

    return _load_module()


def test_module_loads_without_side_effects(scanner):

    assert scanner is not None


def test_scan_type_enum_has_expected_members(scanner):

    assert scanner.ScanType.TCP_CONNECT
    assert scanner.ScanType.TCP_SYN
    assert scanner.ScanType.UDP


def test_scan_result_defaults(scanner):

    result = scanner.ScanResult(
        port=80,
        is_open=True,
        scan_type=scanner.ScanType.TCP_CONNECT,
    )

    assert result.port == 80
    assert result.is_open is True
    assert result.response_time == 0.0
    assert result.error is None
    assert result.banner is None
    assert result.target == ""


def test_scan_result_is_immutable(scanner):

    result = scanner.ScanResult(
        port=22,
        is_open=True,
        scan_type=scanner.ScanType.TCP_CONNECT,
    )

    with pytest.raises(AttributeError):

        result.port = 443


@pytest.mark.parametrize(
    "argv,target,ports",
    [
        (
            [
                "scanner",
                "10.0.0.5",
                "-p",
                "22,80,443",
            ],
            "10.0.0.5",
            "22,80,443",
        ),
        (
            [
                "scanner",
                "scanme.example.com",
                "-p",
                "1-1024",
            ],
            "scanme.example.com",
            "1-1024",
        ),
    ],
)
def test_parse_args_target_and_ports(
    scanner,
    monkeypatch,
    argv,
    target,
    ports,
):

    monkeypatch.setattr(
        sys,
        "argv",
        argv,
    )

    args = scanner.parse_args()

    assert args.target == target
    assert args.ports == ports


def test_parse_args_defaults_when_no_target(
    scanner,
    monkeypatch,
):

    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner"],
    )

    args = scanner.parse_args()

    assert args.target is None
    assert args.scan_type is None


def test_parse_args_syn_flag_sets_scan_type(
    scanner,
    monkeypatch,
):

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scanner",
            "10.0.0.1",
            "--syn",
        ],
    )

    args = scanner.parse_args()

    assert args.scan_type == scanner.ScanType.TCP_SYN


def test_parse_args_udp_flag_sets_scan_type(
    scanner,
    monkeypatch,
):

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scanner",
            "10.0.0.1",
            "--udp",
        ],
    )

    args = scanner.parse_args()

    assert args.scan_type == scanner.ScanType.UDP