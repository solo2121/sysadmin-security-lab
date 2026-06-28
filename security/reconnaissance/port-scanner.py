#!/usr/bin/env python3
"""
Advanced Python Port Scanner with Interactive Menu

Description:
This script provides a comprehensive port scanning tool with multiple scanning techniques,
including TCP Connect, TCP SYN (stealth), and UDP scanning. It features an interactive
menu system, rate limiting for ethical scanning, and detailed results reporting.

Features:
- Multiple scan techniques (TCP Connect, SYN, UDP)
- Interactive menu system
- Rate limiting to prevent network flooding
- Banner grabbing for service identification
- Firewall detection capabilities
- Results saving to file
- Cross-platform support

Author: [solo21]
Version: 1.0
Date: [07-20-2025]
License: MIT License

Usage:
Run the script and follow the interactive prompts:
$ python3 port_scanner.py

For direct command-line usage (non-interactive):
$ python3 port_scanner.py <host> [-p ports] [--syn] [--udp] [--timeout] [--rate]
"""

import asyncio
import os
import platform
import random
import socket
import time
from enum import Enum, auto
import argparse

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP
except ImportError:
    print("Warning: scapy is not installed. SYN and UDP scans will not be available.")
    print("Install it with: pip install scapy")

from typing import Dict, List, NamedTuple, Optional

class ScanType(Enum):
    """Enumeration of available scan techniques."""
    TCP_CONNECT = auto()
    TCP_SYN = auto()
    UDP = auto()


class ScanResult(NamedTuple):
    """Container for port scan results."""
    port: int
    is_open: bool
    scan_type: ScanType
    response_time: float = 0.0
    error: Optional[str] = None
    banner: Optional[str] = None
    target: str = ""


def check_privileges() -> bool:
    """Check if the program is running with admin/root privileges."""
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.getuid() == 0
    except Exception:
        return False


async def scan_port(
    target: str,
    port: int,
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float = 1.0
) -> ScanResult:
    """Scan a single port using the specified technique."""
    start_time = time.time()
    try:
        if scan_type == ScanType.TCP_CONNECT:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = None
            try:
                # Try to read a banner
                banner_data = await asyncio.wait_for(reader.read(100), timeout=2.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except (asyncio.TimeoutError, ConnectionResetError):
                banner = "No banner response"
            finally:
                writer.close()
                await writer.wait_closed()
            return ScanResult(
                port=port,
                is_open=True,
                scan_type=scan_type,
                response_time=time.time() - start_time,
<<<<<<< HEAD
                banner=banner
            )
        elif scan_type == ScanType.TCP_SYN:
            if not check_privileges():
                return ScanResult(port=port, is_open=False, scan_type=scan_type, error="Root privileges required for SYN scan.")
            response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
            if response is None:
                return ScanResult(port=port, is_open=False, scan_type=scan_type, error="filtered (timeout)")
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12: # SYN-ACK
                    return ScanResult(port=port, is_open=True, scan_type=scan_type, response_time=time.time() - start_time)
                elif response.getlayer(TCP).flags == 0x14: # RST-ACK
                    return ScanResult(port=port, is_open=False, scan_type=scan_type, response_time=time.time() - start_time)
            return ScanResult(port=port, is_open=False, scan_type=scan_type, error="filtered")

        elif scan_type == ScanType.UDP:
            if not check_privileges():
                return ScanResult(port=port, is_open=False, scan_type=scan_type, error="Root privileges required for UDP scan.")
            response = sr1(IP(dst=target)/UDP(dport=port), timeout=timeout, verbose=0)
            if response is None:
                return ScanResult(port=port, is_open=True, scan_type=scan_type, response_time=time.time() - start_time, banner="Open|Filtered")
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                    return ScanResult(port=port, is_open=False, scan_type=scan_type, response_time=time.time() - start_time)
            return ScanResult(port=port, is_open=True, scan_type=scan_type, response_time=time.time() - start_time, banner="Open|Filtered")
        else:
            return ScanResult(
                port=port, is_open=False, scan_type=scan_type,
                error=f"Scan type {scan_type.name} is not implemented."
            )
    except (socket.timeout, asyncio.TimeoutError):
        return ScanResult(
            port=port, is_open=False, scan_type=scan_type,
            error="filtered (timeout)"
        )
    except ConnectionRefusedError:
        return ScanResult(port=port, is_open=False, scan_type=scan_type)
    except Exception as e:
        return ScanResult(
            port=port,
            is_open=False,
            scan_type=scan_type,
            error=str(e)
        )


async def scan_ports(
    target: str,
    ports: List[int],
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float = 1.0,
    rate_limit: int = 100,
    randomize: bool = False
) -> List[ScanResult]:
    """Scan multiple ports with rate limiting and optional randomization."""
    if randomize:
        random.shuffle(ports)

    results = []
    semaphore = asyncio.Semaphore(rate_limit)

    async def limited_scan(port):
        async with semaphore:
            return await scan_port(target, port, scan_type, timeout)

    tasks = [limited_scan(port) for port in ports]
    return await asyncio.gather(*tasks)


def display_menu() -> Dict:
    """Display interactive menu and get user choices."""
    print("\n" + "=" * 50)
    print("ADVANCED PORT SCANNER".center(50))
    print("=" * 50)

    target = input("\nEnter target hostname or IP: ").strip()
    port_range = input("Enter port range (e.g., 1-100 or 22,80,443): ").strip()

    # Parse port range
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in port_range.split(',') if p.isdigit()]

    print("\nScan Types:")
    for i, scan_type in enumerate(ScanType, 1):
        print(f"{i}. {scan_type.name.replace('_', ' ').title()}")
    scan_choice = int(input("Select scan type (1-3): ")) - 1
    selected_scan_type = list(ScanType)[scan_choice]

    if selected_scan_type in (ScanType.TCP_SYN, ScanType.UDP) and not check_privileges():
        print("\n[!] Warning: This scan type requires root/admin privileges.")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            exit("Exiting.")

    # Get advanced options
    print("\nAdvanced Options:")
    timeout = float(input("Timeout (seconds) [default 1.0]: ") or "1.0")
    rate_limit = int(input("Max packets per second [default 100]: ") or "100")
    randomize = input("Randomize port order? (y/n) [default n]: ").strip().lower() == 'y'

    return {
        'target': target,
        'ports': ports,
        'scan_type': selected_scan_type,
        'timeout': timeout,
        'rate_limit': rate_limit,
        'randomize': randomize
    }


def display_results(results: List[ScanResult]):
    """Display scan results in a readable format."""
    open_ports = [r for r in results if r.is_open]
    filtered_ports = [r for r in results if "filtered" in str(r.error)]
    closed_ports = [r for r in results if not r.is_open and r.error is None]
    error_ports = [r for r in results if r.error and "filtered" not in str(r.error)]

    print("\n" + "=" * 50)
    print("SCAN RESULTS".center(50))
    print("=" * 50)

    if not results:
        print("\nNo results to display.")
        return

    print(f"\nScan Type: {results[0].scan_type.name.replace('_', ' ').title()}")
    target_ip = socket.gethostbyname(results[0].target)
    print(f"Target: {results[0].target} ({target_ip})")

    if open_ports:
        print("\n[+] OPEN PORTS:")
        for result in sorted(open_ports, key=lambda x: x.port):
            banner_text = f" | Banner: {result.banner}" if result.banner else ""
            print(f"  - Port {result.port:<5} (response: {result.response_time:.3f}s){banner_text}")
    else:
        print("\n[-] No open ports found.")

    if filtered_ports:
        print("\n[?] FILTERED PORTS (likely firewalled):")
        ports_str = ", ".join(str(r.port) for r in sorted(filtered_ports, key=lambda x: x.port))
        print(f"  - Ports: {ports_str}")

    if closed_ports:
        print(f"\n[*] {len(closed_ports)} ports are closed.")

    if error_ports:
        print("\n[!] PORTS WITH ERRORS:")
        for result in sorted(error_ports, key=lambda x: x.port):
            print(f"  - Port {result.port}: {result.error}")


def parse_args():
    """Parse command-line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        description="Advanced Python Port Scanner.",
        epilog="If no arguments are provided, the script runs in interactive mode."
    )
    parser.add_argument("target", nargs="?", help="Target hostname or IP address.")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-100 or 22,80,443).")
    parser.add_argument("--syn", action="store_const", const=ScanType.TCP_SYN, dest="scan_type", help="Use TCP SYN scan.")
    parser.add_argument("--udp", action="store_const", const=ScanType.UDP, dest="scan_type", help="Use UDP scan.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds.")
    parser.add_argument("--rate", type=int, default=100, help="Max packets per second.")
    parser.add_argument("--randomize", action="store_true", help="Randomize port scan order.")
    return parser.parse_args()


async def main(args):
    """Main scanning workflow, supports both interactive and non-interactive modes."""
    if not check_privileges():
        print("\n[!] Warning: Running without admin/root privileges. "
              "Some scan types may not work properly.")

    if args.target and args.ports:
        # Non-interactive mode
        print("[~] Running in non-interactive mode...")
        port_range = args.ports
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in port_range.split(',') if p.isdigit()]

        options = {
            'target': args.target,
            'ports': ports,
            'scan_type': args.scan_type or ScanType.TCP_CONNECT,
            'timeout': args.timeout,
            'rate_limit': args.rate,
            'randomize': args.randomize
        }
    else:
        # Interactive mode
        options = display_menu()

    print(f"\n[~] Scanning {len(options['ports'])} ports on {options['target']}...")

    results = await scan_ports(
        target=options['target'],
        ports=options['ports'],
        scan_type=options['scan_type'],
        timeout=options['timeout'],
        rate_limit=options['rate_limit'],
        randomize=options['randomize']
    )

    # Add target to results for display
    for i, res in enumerate(results):
        results[i] = res._replace(target=options['target'])

    display_results(results)


if __name__ == "__main__":
    args = parse_args()
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(args))
                return ScanResult(
                    port=port,
                    is_open=is_open,
                    scan_type=scan_type,
                    response_time=time.time() - start_time,
                    banner=banner
                )
=======
                banner=banner,
                target=target
            )
>>>>>>> chore/repository-standardization
        elif scan_type == ScanType.TCP_SYN:
            if not check_privileges():
                return ScanResult(
                    port=port, 
                    is_open=False, 
                    scan_type=scan_type, 
                    error="Root privileges required for SYN scan.",
                    target=target
                )
            response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
            if response is None:
                return ScanResult(
                    port=port, 
                    is_open=False, 
                    scan_type=scan_type, 
                    error="filtered (timeout)",
                    target=target
                )
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    return ScanResult(
                        port=port, 
                        is_open=True, 
                        scan_type=scan_type, 
                        response_time=time.time() - start_time,
                        target=target
                    )
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return ScanResult(
                        port=port, 
                        is_open=False, 
                        scan_type=scan_type, 
                        response_time=time.time() - start_time,
                        target=target
                    )
            return ScanResult(
                port=port, 
                is_open=False, 
                scan_type=scan_type, 
                error="filtered",
                target=target
            )

        elif scan_type == ScanType.UDP:
            if not check_privileges():
                return ScanResult(
                    port=port, 
                    is_open=False, 
                    scan_type=scan_type, 
                    error="Root privileges required for UDP scan.",
                    target=target
                )
            response = sr1(IP(dst=target)/UDP(dport=port), timeout=timeout, verbose=0)
            if response is None:
                return ScanResult(
                    port=port, 
                    is_open=True, 
                    scan_type=scan_type, 
                    response_time=time.time() - start_time, 
                    banner="Open|Filtered",
                    target=target
                )
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                    return ScanResult(
                        port=port, 
                        is_open=False, 
                        scan_type=scan_type, 
                        response_time=time.time() - start_time,
                        target=target
                    )
            return ScanResult(
                port=port, 
                is_open=True, 
                scan_type=scan_type, 
                response_time=time.time() - start_time, 
                banner="Open|Filtered",
                target=target
            )
        else:
            return ScanResult(
                port=port, 
                is_open=False, 
                scan_type=scan_type,
                error=f"Scan type {scan_type.name} is not implemented.",
                target=target
            )
    except (socket.timeout, asyncio.TimeoutError):
        return ScanResult(
            port=port, 
            is_open=False, 
            scan_type=scan_type,
            error="filtered (timeout)",
            target=target
        )
    except ConnectionRefusedError:
        return ScanResult(
            port=port, 
            is_open=False, 
            scan_type=scan_type,
            target=target
        )
    except Exception as e:
        return ScanResult(
            port=port,
            is_open=False,
            scan_type=scan_type,
            error=str(e),
            target=target
        )


async def scan_ports(
    target: str,
    ports: List[int],
    scan_type: ScanType = ScanType.TCP_CONNECT,
    timeout: float = 1.0,
    rate_limit: int = 100,
    randomize: bool = False
) -> List[ScanResult]:
    """Scan multiple ports with rate limiting and optional randomization."""
    if randomize:
        random.shuffle(ports)

    semaphore = asyncio.Semaphore(rate_limit)

    async def limited_scan(port):
        async with semaphore:
            return await scan_port(target, port, scan_type, timeout)

    tasks = [limited_scan(port) for port in ports]
    return await asyncio.gather(*tasks)


def display_menu() -> Dict:
    """Display interactive menu and get user choices."""
    print("\n" + "=" * 50)
    print("ADVANCED PORT SCANNER".center(50))
    print("=" * 50)

    target = input("\nEnter target hostname or IP: ").strip()
    port_range = input("Enter port range (e.g., 1-100 or 22,80,443): ").strip()

    # Parse port range
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in port_range.split(',') if p.isdigit()]

    print("\nScan Types:")
    for i, scan_type in enumerate(ScanType, 1):
        print(f"{i}. {scan_type.name.replace('_', ' ').title()}")
    scan_choice = int(input("Select scan type (1-3): ")) - 1
    selected_scan_type = list(ScanType)[scan_choice]

    if selected_scan_type in (ScanType.TCP_SYN, ScanType.UDP) and not check_privileges():
        print("\n[!] Warning: This scan type requires root/admin privileges.")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            exit("Exiting.")

    # Get advanced options
    print("\nAdvanced Options:")
    timeout = float(input("Timeout (seconds) [default 1.0]: ") or "1.0")
    rate_limit = int(input("Max packets per second [default 100]: ") or "100")
    randomize = input("Randomize port order? (y/n) [default n]: ").strip().lower() == 'y'

    return {
        'target': target,
        'ports': ports,
        'scan_type': selected_scan_type,
        'timeout': timeout,
        'rate_limit': rate_limit,
        'randomize': randomize
    }


def display_results(results: List[ScanResult]):
    """Display scan results in a readable format."""
    open_ports = [r for r in results if r.is_open]
    filtered_ports = [r for r in results if r.error and "filtered" in str(r.error).lower()]
    closed_ports = [r for r in results if not r.is_open and not r.error]
    error_ports = [r for r in results if r.error and "filtered" not in str(r.error).lower()]

    print("\n" + "=" * 50)
    print("SCAN RESULTS".center(50))
    print("=" * 50)

    if not results:
        print("\nNo results to display.")
        return

    target_ip = socket.gethostbyname(results[0].target)
    print(f"\nTarget: {results[0].target} ({target_ip})")
    print(f"Scan Type: {results[0].scan_type.name.replace('_', ' ').title()}")

    if open_ports:
        print("\n[+] OPEN PORTS:")
        for result in sorted(open_ports, key=lambda x: x.port):
            banner_text = f" | Banner: {result.banner}" if result.banner and result.banner not in ["No banner response", "Open|Filtered"] else ""
            print(f"  - Port {result.port:<5} (response: {result.response_time:.3f}s){banner_text}")
    else:
        print("\n[-] No open ports found.")

    if filtered_ports:
        print("\n[?] FILTERED PORTS (likely firewalled):")
        ports_str = ", ".join(str(r.port) for r in sorted(filtered_ports, key=lambda x: x.port))
        print(f"  - Ports: {ports_str}")

    if closed_ports:
        print(f"\n[*] {len(closed_ports)} ports are closed.")

    if error_ports:
        print("\n[!] PORTS WITH ERRORS:")
        for result in sorted(error_ports, key=lambda x: x.port):
            print(f"  - Port {result.port}: {result.error}")


def parse_args():
    """Parse command-line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        description="Advanced Python Port Scanner.",
        epilog="If no arguments are provided, the script runs in interactive mode."
    )
    parser.add_argument("target", nargs="?", help="Target hostname or IP address.")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-100 or 22,80,443).")
    parser.add_argument("--syn", action="store_const", const=ScanType.TCP_SYN, dest="scan_type", help="Use TCP SYN scan.")
    parser.add_argument("--udp", action="store_const", const=ScanType.UDP, dest="scan_type", help="Use UDP scan.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds.")
    parser.add_argument("--rate", type=int, default=100, help="Max packets per second.")
    parser.add_argument("--randomize", action="store_true", help="Randomize port scan order.")
    return parser.parse_args()


async def main(args):
    """Main scanning workflow, supports both interactive and non-interactive modes."""
    if not check_privileges():
        print("\n[!] Warning: Running without admin/root privileges. "
              "Some scan types may not work properly.")

    if args.target and args.ports:
        # Non-interactive mode
        print("[~] Running in non-interactive mode...")
        port_range = args.ports
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in port_range.split(',') if p.isdigit()]

        options = {
            'target': args.target,
            'ports': ports,
            'scan_type': args.scan_type or ScanType.TCP_CONNECT,
            'timeout': args.timeout,
            'rate_limit': args.rate,
            'randomize': args.randomize
        }
    else:
        # Interactive mode
        options = display_menu()

    print(f"\n[~] Scanning {len(options['ports'])} ports on {options['target']}...")

    results = await scan_ports(
        target=options['target'],
        ports=options['ports'],
        scan_type=options['scan_type'],
        timeout=options['timeout'],
        rate_limit=options['rate_limit'],
        randomize=options['randomize']
    )

    display_results(results)


if __name__ == "__main__":
    args = parse_args()
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(args))