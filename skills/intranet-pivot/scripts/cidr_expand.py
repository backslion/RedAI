#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cidr_expand.py — CIDR / IP 范围 / 单 IP 展开成 IP 列表（纯标准库）。

用法:
  python3 cidr_expand.py <IP> <IP>-<IP> <IP> [--limit 256]
输出: JSON {"count": n, "ips": [...], "truncated": bool}
"""
import argparse
import ipaddress
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="expand CIDR / ranges / IPs")
    ap.add_argument("targets", nargs="+", help="CIDR、a.b.c.d-a.b.c.d 范围或单 IP")
    ap.add_argument("--limit", type=int, default=256, help="最多输出 IP 数(默认256, 上限8192)")
    args = ap.parse_args()

    limit = max(1, min(args.limit, 8192))
    seen, ips, truncated = set(), [], False

    for t in args.targets:
        t = t.strip()
        if not t:
            continue
        try:
            if "-" in t and "/" not in t:
                lo, hi = (x.strip() for x in t.split("-", 1))
                lo_a = ipaddress.IPv4Address(lo)
                hi_a = ipaddress.IPv4Address(hi)
                if hi_a < lo_a:
                    lo_a, hi_a = hi_a, lo_a
                if int(hi_a) - int(lo_a) > 65536:
                    print(json.dumps({"error": f"范围过大: {t}"}))
                    return 1
                for a in range(int(lo_a), int(hi_a) + 1):
                    if len(ips) >= limit:
                        truncated = True
                        break
                    ip = str(ipaddress.IPv4Address(a))
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
            elif "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > 65536:
                    print(json.dumps({"error": f"网段过大: {t} (>{net.num_addresses} 地址)"}))
                    return 1
                for ip in net.hosts() if net.num_addresses > 2 else net:
                    if len(ips) >= limit:
                        truncated = True
                        break
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        ips.append(s)
            else:
                ip = str(ipaddress.ip_address(t))
                if ip not in seen and len(ips) < limit:
                    seen.add(ip)
                    ips.append(ip)
        except ValueError as e:
            print(json.dumps({"error": f"无法解析 {t!r}: {e}"}))
            return 1
        if truncated:
            break

    print(json.dumps({"count": len(ips), "ips": ips, "truncated": truncated}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
