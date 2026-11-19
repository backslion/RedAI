#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""port_scan.py — 并发 TCP 连接扫描 + banner 抓取（纯标准库，仅用于授权测试）。

用法:
  python3 port_scan.py --hosts <IP> <IP> --preset top100 --banner
  python3 port_scan.py --hosts file:alive.txt --ports 22,445,3389,6379 -t 1.5
输出: 每开放端口一行 JSON: {"host","port","banner","service"}；末尾 summary。
"""
import argparse
import concurrent.futures as cf
import json
import socket
import sys

PRESETS = {
    "top100": [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 500, 512, 513, 514, 548, 554, 587, 623, 636, 873, 990, 993, 995, 1080, 1099, 1194, 1433, 1521, 1604, 1723, 1883, 2049, 2181, 2375, 2376, 2379, 2638, 3000, 3128, 3260, 3306, 3389, 4444, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6379, 6443, 6666, 7001, 7002, 7077, 7100, 7547, 7777, 8000, 8008, 8009, 8010, 8020, 8025, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8098, 8161, 8180, 8200, 8443, 8500, 8649, 8686, 8786, 8800, 8848, 8849, 8888, 8983, 9000, 9001, 9002, 9042, 9043, 9080, 9090, 9091, 9092, 9100, 9200, 9300, 9418, 9443, 9527, 9800, 9876, 9999, 10000, 10001, 10050, 10051, 11211, 15672, 18080, 18083, 19000, 20880, 27017, 28015, 32400, 33060, 50000, 50070, 61616],
    "web": [80, 81, 88, 443, 444, 555, 591, 1080, 2082, 2083, 2087, 2095, 3000, 4848, 5000, 5601, 6080, 7001, 7002, 7070, 7080, 7777, 8000, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8161, 8180, 8443, 8786, 8800, 8848, 8899, 8983, 9000, 9080, 9090, 9100, 9443, 9527, 9999, 10000, 18080, 18083],
    "db": [1433, 1521, 2638, 3306, 5432, 5984, 6379, 7199, 8086, 8649, 9042, 9200, 9300, 11211, 2049, 27017, 27018, 28015, 28017, 33060, 50000, 61616],
    "win": [88, 135, 139, 389, 445, 464, 593, 636, 1099, 3268, 3269, 3389, 5985, 5986, 9389, 47001],
    "nix": [22, 111, 513, 514, 873, 1080, 2049, 6000, 7777],
}

HTTP_PORTS = {80, 81, 88, 443, 444, 591, 3000, 4848, 5000, 5601, 6080, 7001, 7002, 7070, 7080, 7777, 8000, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8161, 8180, 8443, 8786, 8800, 8848, 8899, 8983, 9000, 9080, 9090, 9100, 9443, 9527, 9999, 10000, 18080, 18083}


def load_hosts(spec):
    hosts = []
    for part in spec:
        part = part.strip()
        if not part:
            continue
        if part.startswith("file:"):
            with open(part[5:], encoding="utf-8") as f:
                hosts += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        else:
            hosts.append(part)
    return hosts


def grab_banner(sock, host, port):
    """被动读 0.8s；HTTP 端口无回显则补一个 HEAD。只读，不利用。"""
    try:
        sock.settimeout(0.8)
        data = sock.recv(256)
        if data:
            return data.decode("utf-8", "replace")
        if port in HTTP_PORTS:
            sock.settimeout(0.8)
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            sock.settimeout(1.2)
            data = sock.recv(256)
            if data:
                return data.decode("utf-8", "replace")
    except OSError:
        pass
    return ""


def scan_one(host, port, timeout, banner):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
    except OSError:
        return None
    b = grab_banner(s, host, port) if banner else ""
    try:
        s.close()
    except OSError:
        pass
    b = " ".join(b.split())[:200]
    return {"host": host, "port": port, "banner": b, "service": ""}


def main() -> int:
    ap = argparse.ArgumentParser(description="并发 TCP 端口扫描(授权测试用)")
    ap.add_argument("--hosts", required=True, nargs="+", help="主机或 file:路径")
    ap.add_argument("--ports", default="", help="显式端口(逗号分隔,与 preset 叠加)")
    ap.add_argument("--preset", default="top100", choices=list(PRESETS) + ["none"])
    ap.add_argument("-t", "--timeout", type=float, default=1.5, help="连接超时秒")
    ap.add_argument("--workers", type=int, default=400)
    ap.add_argument("--banner", action="store_true", help="抓取服务 banner")
    args = ap.parse_args()

    hosts = load_hosts(args.hosts)
    portset = set()
    if args.preset != "none":
        portset.update(PRESETS[args.preset])
    if args.ports:
        for p in args.ports.split(","):
            if p.strip().isdigit():
                portset.add(int(p))
    if not hosts or not portset:
        print(json.dumps({"error": "host/端口为空"}))
        return 1
    if len(hosts) * len(portset) > 65536:
        print(json.dumps({"error": f"组合过多({len(hosts)}x{len(portset)})，请分批"}))
        return 1

    jobs = [(h, p) for h in hosts for p in sorted(portset)]
    found = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(lambda j: scan_one(j[0], j[1], args.timeout, args.banner), jobs):
            if r:
                found += 1
                print(json.dumps(r, ensure_ascii=False))
    print(json.dumps({"summary": {"hosts": len(hosts), "ports": len(portset), "open": found}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
