#!/usr/bin/env python3
"""pscan.py — asyncio TCP/UDP port scanner with service banner grabbing.

    python3 pscan.py 10.0.0.5 -p top
    python3 pscan.py 10.0.0.0/24 -p 22,80,443,8000-8100 -c 512
    python3 pscan.py host.example.com -p 1-65535 -t 0.5 --json out.json
    python3 pscan.py 10.0.0.5 -p 53,123,161 --udp
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict

TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 512, 513, 514, 515, 520, 548, 554,
    587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1080, 1099, 1194, 1433,
    1434, 1521, 1701, 1723, 1755, 1812, 1813, 1883, 2049, 2082, 2083, 2181, 2222,
    2375, 2376, 2483, 2484, 3000, 3128, 3260, 3268, 3269, 3306, 3389, 3690, 4000,
    4369, 4444, 4505, 4506, 5000, 5060, 5061, 5222, 5269, 5353, 5432, 5555, 5601,
    5672, 5900, 5984, 5985, 5986, 6000, 6379, 6443, 6660, 6881, 7001, 7002, 7077,
    7199, 7474, 8000, 8006, 8008, 8080, 8081, 8086, 8088, 8090, 8123, 8181, 8200,
    8222, 8300, 8443, 8500, 8529, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9100,
    9160, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 15672, 16379, 25565, 27017,
    27018, 28017, 50000, 50070, 61616,
]

HTTP_PORTS = {80, 81, 591, 2082, 2083, 3000, 4000, 5000, 5601, 7001, 8000, 8008,
              8080, 8081, 8086, 8088, 8090, 8123, 8181, 8222, 8300, 8888, 8983,
              9000, 9001, 9090, 9200, 9999}
TLS_PORTS = {443, 2376, 5986, 6443, 8006, 8443, 9443, 10250}

# Ports that need us to speak first, otherwise they stay silent
PROBES = {
    25: b"EHLO pscan.local\r\n",
    113: b"",
    194: b"",
    587: b"EHLO pscan.local\r\n",
    2181: b"ruok\r\n",
    6379: b"PING\r\n",
    11211: b"stats\r\n",
}

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}

SERVICE_HINTS = {
    3000: "http-alt", 5000: "http-alt", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    27017: "mongodb", 6379: "redis", 11211: "memcached", 2375: "docker",
    2376: "docker-tls", 6443: "k8s-api", 10250: "kubelet", 5601: "kibana",
    15672: "rabbitmq-mgmt", 61616: "activemq", 5984: "couchdb", 2181: "zookeeper",
}


@dataclass
class Result:
    host: str
    port: int
    proto: str
    state: str
    service: str
    rtt_ms: float
    banner: str = ""
    extra: str = ""


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.lower().startswith("top"):
            ports.update(TOP_PORTS)
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError(f"invalid port range : {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    if not ports:
        raise ValueError("no ports specified")
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"port out of range: {bad[:5]}")
    return sorted(ports)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_targets(spec: str) -> list[str]:
    out: list[str] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "/" in chunk:
            net = ipaddress.ip_network(chunk, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            out.extend(str(h) for h in hosts)
        elif re.fullmatch(r"[\d.]+-[\d.]+", chunk):
            lo, hi = chunk.split("-")
            if "." not in hi:                      # 10.0.0.10-20 shorthand
                hi = lo.rsplit(".", 1)[0] + "." + hi
            a, b = int(ipaddress.ip_address(lo)), int(ipaddress.ip_address(hi))
            out.extend(str(ipaddress.ip_address(i)) for i in range(a, b + 1))
        else:
            out.append(chunk)                      # hostname / single IP
    return list(dict.fromkeys(out))                # dedupe, keep order


async def resolve_targets(spec: str) -> list[str]:
    loop = asyncio.get_running_loop()
    resolved: list[str] = []
    for target in parse_targets(spec):
        if is_ip(target):
            resolved.append(target)
            continue
        try:
            infos = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            print(f"[!] cannot resolve {target}: {exc}", file=sys.stderr)
            continue
        resolved.extend(sorted({i[4][0] for i in infos}))
    return list(dict.fromkeys(resolved))


def service_name(port: int, proto: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return SERVICE_HINTS.get(port, "unknown")


def squash(data: bytes, limit: int = 200) -> str:
    if not data:
        return ""
    text = data.decode("latin-1", "replace").replace("\x00", "")
    return " ".join(text.split())[:limit]


async def read_some(reader: asyncio.StreamReader, timeout: float, limit: int = 4096) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout)
    except (asyncio.TimeoutError, OSError):
        return b""


async def read_http_head(reader: asyncio.StreamReader, timeout: float) -> bytes:
    buf, deadline = b"", time.monotonic() + timeout
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(1024), remaining)
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
async def grab_banner(host: str, port: int, reader, writer, timeout: float):
    """Return (banner, extra_info). May reconnect for TLS ports."""
    if port in TLS_PORTS:
        writer.close()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout
        )
        try:
            w.write(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            await w.drain()
            data = await read_http_head(r, timeout)
            ssl_obj = w.get_extra_info("ssl_object")
            extra = f"{ssl_obj.version()} {ssl_obj.cipher()[0]}" if ssl_obj else ""
            return squash(data), extra
        finally:
            w.close()

    probe = PROBES.get(port)
    if probe:
        writer.write(probe)
        await writer.drain()

    if port in HTTP_PORTS:
        writer.write(b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: pscan\r\n\r\n" % host.encode())
        await writer.drain()
        return squash(await read_http_head(reader, timeout)), ""

    return squash(await read_some(reader, min(timeout, 1.5))), ""


async def tcp_scan(host: str, port: int, args) -> Result | None:
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), args.timeout
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

    rtt = (time.perf_counter() - started) * 1000
    banner, extra = "", ""
    if args.banner:
        try:
            banner, extra = await grab_banner(host, port, reader, writer, args.timeout)
        except Exception:
            pass
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    return Result(host, port, "tcp", "open", service_name(port), round(rtt, 1), banner, extra)


async def udp_scan(host: str, port: int, args) -> Result | None:
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), args.timeout)
        await loop.sock_sendall(sock, UDP_PROBES.get(port, b"\x00"))
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), args.timeout)
        return Result(host, port, "udp", "open", service_name(port, "udp"), 0.0,
                      squash(data) if args.banner else "")
    except ConnectionRefusedError:
        return None                                  # ICMP port unreachable → closed
    except asyncio.TimeoutError:
        return Result(host, port, "udp", "open|filtered", service_name(port, "udp"), 0.0)
    except OSError:
        return None
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Runner / output
# --------------------------------------------------------------------------- #
def fmt_row(r: Result) -> str:
    line = (f"{r.port:>5}/{r.proto:<3} {r.state:<14} {r.service:<14} "
            f"{r.rtt_ms:>7.1f}ms  {r.host}")
    if r.extra:
        line += f"  [{r.extra}]"
    if r.banner:
        line += f"\n{'':>10}└─ {r.banner}"
    return line


async def run(args) -> list[Result]:
    hosts = await resolve_targets(args.target)
    ports = parse_ports(args.ports)
    if not hosts:
        print("[!] no targets", file=sys.stderr)
        return []

    total = len(hosts) * len(ports)
    print(f"[*] {len(hosts)} host(s) x {len(ports)} port(s) = {total} probes  "
          f"(concurrency={args.concurrency}, timeout={args.timeout}s)", file=sys.stderr)

    scanner = udp_scan if args.udp else tcp_scan
    queue: asyncio.Queue = asyncio.Queue(maxsize=20000)
    results: list[Result] = []
    stop = asyncio.Event()

    async def producer():
        for host in hosts:
            for port in ports:
                if stop.is_set():
                    break
                await queue.put((host, port))
        for _ in range(args.concurrency):
            await queue.put(None)

    async def worker():
        while True:
            item = await queue.get()
            if item is None:
                return
            if stop.is_set():
                continue
            res = await scanner(item[0], item[1], args)
            if res:
                results.append(res)
                if not args.quiet:
                    print(fmt_row(res), flush=True)
                if args.max_results and len(results) >= args.max_results:
                    stop.set()

    await asyncio.gather(producer(), *[worker() for _ in range(args.concurrency)])
    return sorted(results, key=lambda r: (r.host, r.proto, r.port))


def write_outputs(results: list[Result], args) -> None:
    rows = [asdict(r) for r in results]
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        print(f"[*] wrote {args.json}", file=sys.stderr)
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else
                                    ["host", "port", "proto", "state", "service",
                                     "rtt_ms", "banner", "extra"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"[*] wrote {args.csv}", file=sys.stderr)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="async TCP/UDP port scanner with banner grabbing")
    p.add_argument("target", help="IP, hostname, CIDR, range (10.0.0.1-50) or comma list")
    p.add_argument("-p", "--ports", default="top", help="'top', '22,80,1-1024' (default: top)")
    p.add_argument("-c", "--concurrency", type=int, default=256)
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="per-connection timeout, s")
    p.add_argument("--udp", action="store_true", help="UDP scan instead of TCP")
    p.add_argument("--no-banner", dest="banner", action="store_false", help="skip banner grab")
    p.add_argument("--max-results", type=int, default=0, help="stop after N open ports")
    p.add_argument("--json", metavar="FILE")
    p.add_argument("--csv", metavar="FILE")
    p.add_argument("-q", "--quiet", action="store_true", help="no live output, files only")
    return p.parse_args(argv)


def main() -> int:
    args = parse_args()
    try:
        results = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130
    write_outputs(results, args)
    print(f"[*] done: {len(results)} open result(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())