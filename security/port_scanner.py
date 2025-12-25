#!/usr/bin/env python3
import socket
import threading
import time
import platform
import ipaddress
import argparse
import json
from datetime import datetime


class PortScanner:
    def __init__(self, target, port_range, timeout=1, threads=100):
        self.target = target
        self.port_range = port_range
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.start_time = time.time()

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                try:
                    banner = self.get_banner(sock)
                except:
                    banner = "No banner"

                self.results.append({
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner,
                    "timestamp": datetime.now().isoformat()
                })

            sock.close()
        except Exception as e:
            pass

    def get_banner(self, sock):
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else "No banner"
        except:
            return "No banner"

    def scan(self):
        print(f"[*] Starting scan on {self.target}")
        print(f"[*] Target OS: {platform.system()} {platform.release()}")
        print(f"[*] Scan range: {self.port_range}")
        print(f"[*] Using {self.threads} threads")
        print("[*] Scan started at",
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        ports = self.parse_port_range()

        threads = []
        for port in ports:
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []

            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for t in threads:
            t.join()

        end_time = time.time()
        scan_duration = end_time - self.start_time

        self.results.sort(key=lambda x: x["port"])

        print(f"\n[*] Scan completed in {scan_duration:.2f} seconds")
        print(
            f"[*] Found {len([r for r in self.results if r['status'] == 'open'])} open ports")

        return self.results

    def parse_port_range(self):
        if '-' in self.port_range:
            start, end = map(int, self.port_range.split('-'))
        else:
            start = end = int(self.port_range)

        return list(range(start, end + 1))

    def generate_report(self, format='text'):
        if format == 'json':
            return self.generate_json_report()
        else:
            return self.generate_text_report()

    def generate_text_report(self):
        report = []
        report.append("=" * 60)
        report.append("PORT SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Target: {self.target}")
        report.append(
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target OS: {platform.system()} {platform.release()}")
        report.append(f"Scan Range: {self.port_range}")
        report.append(f"Total Ports Scanned: {len(self.parse_port_range())}")
        report.append(
            f"Open Ports Found: {len([r for r in self.results if r['status'] == 'open'])}")
        report.append("")

        if self.results:
            report.append("OPEN PORTS:")
            report.append("-" * 60)
            report.append(f"{'PORT':<8} {'SERVICE':<20} {'BANNER':<30}")
            report.append("-" * 60)

            for result in self.results:
                if result['status'] == 'open':
                    banner = result['banner'][:27] + \
                        "..." if len(result['banner']
                                     ) > 30 else result['banner']
                    report.append(
                        f"{result['port']:<8} {result['service']:<20} {banner:<30}")

        return "\n".join(report)

    def generate_json_report(self):
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "target_os": f"{platform.system()} {platform.release()}",
            "scan_range": self.port_range,
            "total_ports_scanned": len(self.parse_port_range()),
            "open_ports_count": len([r for r in self.results if r['status'] == 'open']),
            "open_ports": self.results
        }
        return json.dumps(report, indent=2)


def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except:
        return "127.0.0.1"


def scan_network(network, port_range, timeout=1, threads=100):
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        targets = [str(host) for host in network_obj.hosts()]

        if not targets:
            targets = [str(network_obj.network_address)]

        print(f"[*] Scanning network {network} with {len(targets)} hosts")

        all_results = []
        for target in targets:
            scanner = PortScanner(target, port_range, timeout, threads)
            results = scanner.scan()
            all_results.extend(results)

        return all_results
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Port range to scan (default: 1-1024)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds')
    parser.add_argument('--threads', type=int, default=100,
                        help='Number of threads')
    parser.add_argument(
        '--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--output', help='Save report to file')
    parser.add_argument('--network', action='store_true',
                        help='Scan entire network')

    args = parser.parse_args()

    try:
        if args.network:
            if '/' not in args.target:
                print(
                    "Error: Network scan requires CIDR notation (e.g., 192.168.1.0/24)")
                return

            results = scan_network(
                args.target, args.ports, args.timeout, args.threads)
        else:
            scanner = PortScanner(args.target, args.ports,
                                  args.timeout, args.threads)
            results = scanner.scan()

        report = scanner.generate_report(args.format)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"[*] Report saved to {args.output}")
        else:
            print(report)

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
