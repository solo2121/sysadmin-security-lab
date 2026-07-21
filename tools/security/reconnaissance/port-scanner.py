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

import argparse
import asyncio
import os
import platform
import random
import socket
import time

from enum import Enum, auto
from typing import Dict, List, NamedTuple, Optional


try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP

    SCAPY_AVAILABLE = True

except ImportError:
    sr1 = None
    IP = None
    TCP = None
    UDP = None
    ICMP = None

    SCAPY_AVAILABLE = False


class ScanType(Enum):
    """Available scan techniques."""

    TCP_CONNECT = auto()
    TCP_SYN = auto()
    UDP = auto()


class ScanResult(NamedTuple):
    """Port scan result."""

    port: int
    is_open: bool
    scan_type: ScanType
    response_time: float = 0.0
    error: Optional[str] = None
    banner: Optional[str] = None
    target: str = ""


def check_privileges() -> bool:
    """Check administrator/root privileges."""

    try:
        if platform.system() == "Windows":
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0

        return hasattr(os, "getuid") and os.getuid() == 0

    except Exception:
        return False


async def tcp_connect_scan(
    target: str,
    port: int,
    timeout: float,
) -> ScanResult:

    start = time.time()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout,
        )

        banner = None

        try:
            data = await asyncio.wait_for(
                reader.read(100),
                timeout=2,
            )

            banner = data.decode(
                "utf-8",
                errors="ignore",
            ).strip()

        except asyncio.TimeoutError:
            banner = "No banner response"

        writer.close()
        await writer.wait_closed()

        return ScanResult(
            port,
            True,
            ScanType.TCP_CONNECT,
            time.time() - start,
            banner=banner,
            target=target,
        )

    except ConnectionRefusedError:

        return ScanResult(
            port,
            False,
            ScanType.TCP_CONNECT,
            target=target,
        )

    except Exception as exc:

        return ScanResult(
            port,
            False,
            ScanType.TCP_CONNECT,
            error=str(exc),
            target=target,
        )


def syn_scan(
    target: str,
    port: int,
    timeout: float,
) -> ScanResult:

    start = time.time()

    if not SCAPY_AVAILABLE:

        return ScanResult(
            port,
            False,
            ScanType.TCP_SYN,
            error="Scapy not installed",
            target=target,
        )

    if not check_privileges():

        return ScanResult(
            port,
            False,
            ScanType.TCP_SYN,
            error="Root privileges required",
            target=target,
        )

    response = sr1(
        IP(dst=target)
        / TCP(
            dport=port,
            flags="S",
        ),
        timeout=timeout,
        verbose=0,
    )

    if response is None:

        return ScanResult(
            port,
            False,
            ScanType.TCP_SYN,
            error="filtered",
            target=target,
        )

    if response.haslayer(TCP):

        flags = int(response[TCP].flags)

        if flags == 0x12:

            return ScanResult(
                port,
                True,
                ScanType.TCP_SYN,
                time.time() - start,
                target=target,
            )

    return ScanResult(
        port,
        False,
        ScanType.TCP_SYN,
        target=target,
    )


def udp_scan(
    target: str,
    port: int,
    timeout: float,
) -> ScanResult:

    if not SCAPY_AVAILABLE:

        return ScanResult(
            port,
            False,
            ScanType.UDP,
            error="Scapy not installed",
            target=target,
        )

    if not check_privileges():

        return ScanResult(
            port,
            False,
            ScanType.UDP,
            error="Root privileges required",
            target=target,
        )

    response = sr1(
        IP(dst=target)
        / UDP(dport=port),
        timeout=timeout,
        verbose=0,
    )

    if response is None:

        return ScanResult(
            port,
            True,
            ScanType.UDP,
            banner="Open|Filtered",
            target=target,
        )

    if response.haslayer(ICMP):

        return ScanResult(
            port,
            False,
            ScanType.UDP,
            target=target,
        )

    return ScanResult(
        port,
        True,
        ScanType.UDP,
        banner="Open|Filtered",
        target=target,
    )


async def scan_port(
    target: str,
    port: int,
    scan_type: ScanType,
    timeout: float,
) -> ScanResult:

    if scan_type == ScanType.TCP_CONNECT:

        return await tcp_connect_scan(
            target,
            port,
            timeout,
        )

    if scan_type == ScanType.TCP_SYN:

        return syn_scan(
            target,
            port,
            timeout,
        )

    if scan_type == ScanType.UDP:

        return udp_scan(
            target,
            port,
            timeout,
        )

    return ScanResult(
        port,
        False,
        scan_type,
        error="Unknown scan type",
        target=target,
    )


async def scan_ports(
    target: str,
    ports: List[int],
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float = 1.0,
    rate_limit: int = 100,
    randomize: bool = False,
) -> List[ScanResult]:

    ports = ports.copy()

    if randomize:
        random.shuffle(ports)

    semaphore = asyncio.Semaphore(rate_limit)

    async def worker(port):

        async with semaphore:

            return await scan_port(
                target,
                port,
                scan_type,
                timeout,
            )

    return await asyncio.gather(
        *(worker(port) for port in ports)
    )


def parse_ports(value: str) -> List[int]:

    if "-" in value:

        start, end = map(
            int,
            value.split("-"),
        )

        return list(range(start, end + 1))

    return [
        int(port)
        for port in value.split(",")
        if port.isdigit()
    ]


def parse_args():

    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner",
    )

    parser.add_argument(
        "target",
        nargs="?",
    )

    parser.add_argument(
        "-p",
        "--ports",
    )

    parser.add_argument(
        "--syn",
        action="store_const",
        const=ScanType.TCP_SYN,
        dest="scan_type",
    )

    parser.add_argument(
        "--udp",
        action="store_const",
        const=ScanType.UDP,
        dest="scan_type",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=100,
    )

    parser.add_argument(
        "--randomize",
        action="store_true",
    )

    return parser.parse_args()


def display_results(results):

    for result in results:

        status = "OPEN" if result.is_open else "CLOSED"

        print(
            f"{result.port}: {status}"
        )


async def main(args):

    if not args.target:

        print(
            "Interactive mode not implemented in this test-focused build."
        )

        return

    ports = parse_ports(args.ports or "1-1024")

    results = await scan_ports(
        args.target,
        ports,
        args.scan_type or ScanType.TCP_CONNECT,
        args.timeout,
        args.rate,
        args.randomize,
    )

    display_results(results)


if __name__ == "__main__":

    asyncio.run(
        main(
            parse_args()
        )
    )