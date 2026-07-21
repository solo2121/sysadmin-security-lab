#!/usr/bin/env python3
"""
Modern Async Port Scanner

A lightweight reconnaissance tool for authorized security testing.

Features:
- TCP connect scanning
- Async concurrent scanning
- Banner grabbing
- Service identification
- Rate limiting
- JSON output
- CLI support
- CI/test friendly import behavior

Author: solo21
Version: 2.0
License: MIT
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ScanType(Enum):
    """Supported scan types."""

    TCP_CONNECT = "tcp"


@dataclass(frozen=True)
class ScanResult:
    """Result returned from a port scan."""

    port: int
    is_open: bool
    scan_type: ScanType
    response_time: float = 0.0
    error: Optional[str] = None
    banner: Optional[str] = None
    target: str = ""


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


def service_name(port: int) -> str:
    """Return common service name."""

    return COMMON_SERVICES.get(port, "unknown")


def parse_ports(value: str) -> list[int]:
    """Parse port input.

    Examples:
        22,80,443
        1-1024
    """

    ports: list[int] = []

    for item in value.split(","):
        item = item.strip()

        if "-" in item:
            start, end = item.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(item))

    return sorted(set(ports))


async def grab_banner(
    reader: asyncio.StreamReader,
    timeout: float,
) -> Optional[str]:
    """Attempt banner grabbing."""

    try:
        data = await asyncio.wait_for(
            reader.read(128),
            timeout=timeout,
        )

        if data:
            return data.decode(
                errors="ignore"
            ).strip()

    except (
        asyncio.TimeoutError,
        ConnectionResetError,
    ):
        pass

    return None


async def scan_port(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> ScanResult:
    """Scan a single TCP port."""

    start = time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target,
                port,
            ),
            timeout=timeout,
        )

        banner = await grab_banner(
            reader,
            timeout,
        )

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        return ScanResult(
            port=port,
            is_open=True,
            scan_type=ScanType.TCP_CONNECT,
            response_time=time.perf_counter() - start,
            banner=banner,
            target=target,
        )

    except ConnectionRefusedError:

        return ScanResult(
            port=port,
            is_open=False,
            scan_type=ScanType.TCP_CONNECT,
            response_time=time.perf_counter() - start,
            target=target,
        )

    except asyncio.TimeoutError:

        return ScanResult(
            port=port,
            is_open=False,
            scan_type=ScanType.TCP_CONNECT,
            response_time=time.perf_counter() - start,
            error="timeout",
            target=target,
        )

    except OSError as exc:

        return ScanResult(
            port=port,
            is_open=False,
            scan_type=ScanType.TCP_CONNECT,
            response_time=time.perf_counter() - start,
            error=str(exc),
            target=target,
        )


async def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[ScanResult]:
    """Scan multiple ports concurrently."""

    semaphore = asyncio.Semaphore(workers)

    async def limited_scan(port: int):

        async with semaphore:
            return await scan_port(
                target,
                port,
                timeout,
            )

    tasks = [
        limited_scan(port)
        for port in ports
    ]

    return await asyncio.gather(*tasks)


def display_results(results: list[ScanResult]) -> None:
    """Display scan results."""

    print()

    print(
        f"{'PORT':<8}"
        f"{'STATE':<12}"
        f"SERVICE"
    )

    print("-" * 35)

    for result in sorted(
        results,
        key=lambda x: x.port,
    ):

        if result.is_open:

            print(
                f"{result.port:<8}"
                f"OPEN{'':<7}"
                f"{service_name(result.port)}"
            )


async def async_main(args) -> None:
    """Application workflow."""

    ports = parse_ports(args.ports)

    print(
        f"[+] Scanning {args.target}"
    )

    print(
        f"[+] Ports: {len(ports)}"
    )

    start = time.perf_counter()

    results = await scan_ports(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
    )

    duration = time.perf_counter() - start

    display_results(results)

    print()
    print(
        f"Completed in {duration:.2f}s"
    )

    if args.output:

        output = [
            {
                **asdict(result),
                "scan_type": result.scan_type.value,
            }
            for result in results
        ]

        Path(args.output).write_text(
            json.dumps(
                output,
                indent=4,
            )
        )

        print(
            f"[+] Results saved: {args.output}"
        )


def parse_args():
    """CLI argument parser."""

    parser = argparse.ArgumentParser(
        description="Modern Async Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP or hostname",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Ports: 22,80,443 or 1-1024",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Concurrent workers",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save JSON results",
    )

    return parser.parse_args()


def main():

    args = parse_args()

    asyncio.run(
        async_main(args)
    )


if __name__ == "__main__":
    main()