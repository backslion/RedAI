#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sweep_alive.py — TCP 多端口并探测活（纯标准库）。ICMP 内网常被禁，用少量
常见端口的 TCP connect 判活；任一端口可连即视为存活。

用法:
  python3 sweep_alive.py --targets <IP> --probe-ports 22,135,445,3389,80,443 -t 1
  python3 sweep_alive.py --targets file:alive_targets.txt --workers 400
输出: 每存活主机一行 JSON: {"host": "...", "ports": [..]}
"""
import argparse
import concurrent.futures as cf
import ipaddress
import json
import socket
import sys

DEFAULT_PROBE_PORTS = [22, 135, 445, 3389, 80, 443, 445]


def expand_targets(targets, limit=65536):
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            if "-" in t and "/" not in t:
                lo, hi = (x.strip() for x in t.split("-", 1))
                lo_a, hi_a = ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
                if hi_a < lo_a:
                    lo_a, hi_a = hi_a, lo_a
                for a in range(int(lo_a), int(hi_a) + 1):
                    out.append(str(ipaddress.IPv4Address(a)))
            elif "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                for ip in (net.hosts() if net.num_addresses > 2 else net):
                    out.append(str(ip))
            else:
                out.append(str(ipaddress.ip_address(t)))
        except ValueError:
            out.append(t)  # hostname
        if len(out) > limit:
            raise SystemExit(f"目标过多(>{limit})，请分批")
    return out


def probe_host(host, ports, timeout):
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, p))
            s.close()
            open_ports.append(p)
            if len(open_ports) >= 2:  # 2 个端口可连即足以判活
                break
        except OSError:
            continue
    return {"host": host, "ports": open_ports} if open_ports else None


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP 存活探测")
    ap.add_argument("--targets", required=True,
                    help="逗号分隔的 CIDR/范围/IP，或 file:路径")
    ap.add_argument("--probe-ports", default="22,135,445,3389,80,443",
                    help="判活探测端口(逗号分隔,默认 22,135,445,3389,80,443)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="单连接超时秒(默认1)")
    ap.add_argument("--workers", type=int, default=300, help="并发数(默认300)")
    args = ap.parse_args()

    if args.targets.startswith("file:"):
        with open(args.targets[5:], encoding="utf-8") as f:
            raw = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    else:
        raw = args.targets.split(",")
    targets = expand_targets(raw)
    ports = [int(p) for p in args.probe_ports.split(",") if p.strip()]
    if not targets or not ports:
        print(json.dumps({"error": "目标或端口为空"}))
        return 1

    alive = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(probe_host, h, ports, args.timeout) for h in targets]
        for fu in cf.as_completed(futs):
            r = fu.result()
            if r:
                alive += 1
                print(json.dumps(r))
    print(json.dumps({"summary": {"targets": len(targets), "alive": alive}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
