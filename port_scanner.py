"""A small, TCP connect port scanner for authorized hosts."""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    port: int
    is_open: bool
    service: str | None = None


def parse_ports(spec: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid port range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float) -> ScanResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = None
            return ScanResult(port, True, service)
    except (ConnectionRefusedError, TimeoutError, OSError):
        return ScanResult(port, False)


def scan(host: str, ports: list[int], timeout: float, workers: int) -> list[ScanResult]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, host, port, timeout) for port in ports]
        return sorted((future.result() for future in as_completed(futures)), key=lambda result: result.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan TCP ports on a host you are authorized to test.")
    parser.add_argument("host", help="hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="ports, e.g. 22,80,443 or 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="per-port timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=32, help="maximum concurrent connections")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        ports = parse_ports(args.ports)
        if args.timeout <= 0 or args.workers < 1 or args.workers > 256:
            raise ValueError("timeout must be positive and workers must be between 1 and 256")
        results = scan(args.host, ports, args.timeout, min(args.workers, len(ports)))
    except (ValueError, socket.gaierror) as error:
        print(f"error: {error}")
        return 2

    print(f"Scanning {args.host} ({len(ports)} TCP ports)...")
    open_ports = [result for result in results if result.is_open]
    if not open_ports:
        print("No open TCP ports found.")
    else:
        for result in open_ports:
            label = f" ({result.service})" if result.service else ""
            print(f"{result.port}/tcp open{label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
