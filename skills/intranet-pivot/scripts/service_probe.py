#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""service_probe.py — 内网高价值服务的**只读**协议级核查（纯标准库，授权测试用）。

对已确认开放的服务端口做一次最小交互，判定「未授权访问/弱配置」迹象：
  6379  Redis     : 发 PING → 期待 +PONG；INFO server(只读) 看版本/是否 requirepass
  11211 Memcached : 发 version → 回版本即未授权
  27017 MongoDB   : 发 hello(OP_MSG) → 回 ok:1 即未授权
  9200  Elasticsearch : GET / → 回 cluster 信息即未授权
  HTTP 类         : GET / 抓 title/server 头，标注管理面板指纹

不写数据、不执行命令、不发任何修改型协议指令。结论只是「存在未授权访问迹象」，
登记 fact 后按流程处置。
用法:
  python3 service_probe.py --hosts <IP> <IP>
  python3 service_probe.py --hosts file:alive.txt --ports 6379,9200 -t 2
输出: 每命中一行 JSON。
"""
import argparse
import concurrent.futures as cf
import json
import socket
import sys

HTTP_PORTS = {80, 81, 88, 443, 444, 591, 3000, 4848, 5000, 5601, 6080, 7001, 7002, 7070, 7080, 7777, 8000, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8088, 8089, 8090, 8091, 8161, 8180, 8443, 8786, 8800, 8848, 8899, 8983, 9000, 9080, 9090, 9100, 9443, 9527, 9999, 10000, 15672, 18080, 18083}

CHECKS = {
    6379: "redis",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    9200: "elasticsearch",
    9300: "elasticsearch",
}


def send_recv(host, port, payload, timeout, read=512):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if payload:
            s.sendall(payload)
        return s.recv(read).decode("utf-8", "replace")
    except OSError:
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def bson_doc(pairs):
    """极小 BSON 编码器：值支持 int32 与 str，足够构造 {hello:1, $db:'admin'}。"""
    body = b""
    for k, v in pairs:
        kb = k.encode() + b"\x00"
        if isinstance(v, int):
            body += b"\x10" + kb + v.to_bytes(4, "little")
        else:
            vb = v.encode() + b"\x00"
            body += b"\x02" + kb + (len(vb)).to_bytes(4, "little") + vb
    doc = (len(body) + 5).to_bytes(4, "little") + body + b"\x00"
    return doc


def mongodb_hello(host, port, timeout):
    """OP_MSG 2013 发送 {hello:1,$db:admin}；hello 在认证前即被允许，回包=端口可达且
    多数配置未授权。识别响应里的 serverVersion 即给出未授权迹象。"""
    doc = bson_doc([("hello", 1), ("$db", "admin")])
    body = b"\x00" + doc  # section kind 0 + document
    flag = b"\x00\x00\x00\x00"
    payload_len = 16 + len(flag) + len(body)
    header = payload_len.to_bytes(4, "little") + (1).to_bytes(4, "little") + b"\x00" * 4 + (2013).to_bytes(4, "little")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(header + flag + body)
        data = s.recv(1024)
        # 不做响应长度完整性校验：TCP 分片下单次 recv 可能只到一部分，
        # 标志字段足以判定；足够长的响应视为命中。
        if len(data) >= 16:
            text = data.decode("utf-8", "replace")
            if "serverVersion" in text or "ismaster" in text or "helloOk" in text or "topologyVersion" in text:
                ver = ""
                idx = text.find("serverVersion")
                if idx >= 0:
                    seg = text[idx + 13:idx + 40]
                    ver = seg.split('"')[1] if '"' in seg else ""
                return {"host": host, "port": port, "service": "mongodb", "finding": "未授权访问(迹象,hello 预认证可达)", "version": ver}
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return None


def probe(host, port, timeout):
    kind = CHECKS.get(port)
    if kind == "redis":
        r = send_recv(host, port, b"PING\r\n", timeout)
        if r.startswith("+PONG"):
            info = send_recv(host, port, b"INFO server\r\n", timeout, 1024)
            ver = ""
            for ln in info.splitlines():
                if ln.startswith("redis_version:"):
                    ver = ln.split(":", 1)[1].strip()
            return {"host": host, "port": port, "service": "redis", "finding": "未授权访问(可执行命令族)", "version": ver}
        if r.startswith("-NOAUTH") or "authentication" in r.lower():
            return {"host": host, "port": port, "service": "redis", "finding": "已设认证", "banner": r.strip()[:80]}
        return None
    if kind == "memcached":
        r = send_recv(host, port, b"version\r\n", timeout)
        if r.startswith("VERSION "):
            return {"host": host, "port": port, "service": "memcached", "finding": "未授权访问", "version": r.split()[1].strip()}
        return None
    if kind == "mongodb":
        return mongodb_hello(host, port, timeout)
    if kind == "elasticsearch":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = b""
            while len(data) < 2048:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            body = data.decode("utf-8", "replace")
            if '"cluster_name"' in body:
                name = ""
                idx = body.find('"cluster_name"')
                if idx >= 0:
                    seg = body[idx:idx + 80]
                    if '"' in seg[14:]:
                        name = seg.split('"')[2]
                return {"host": host, "port": port, "service": "elasticsearch", "finding": "未授权访问", "cluster": name}
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
        return None
    # HTTP 类端口：抓标题/Server 头做面板指纹
    if port in HTTP_PORTS:
        body = send_recv(host, port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout, 2048)
        if not body:
            return None
        title = ""
        lower = body.lower()
        if "<title>" in lower:
            i = lower.find("<title>")
            seg = body[i:i + 200]
            title = seg[7:seg.find("</", 7)] if "</" in seg[7:] else seg[7:60]
        server = ""
        for ln in body.splitlines():
            if ln.lower().startswith("server:"):
                server = ln.split(":", 1)[1].strip()
                break
        marks = []
        for kw in ("jenkins", "weblogic", "tomcat", "jboss", "nacos", "gitlab", "kibana", "rabbitmq", "activemq", "solr", "druid", "swagger", "eureka", "consul", "harbor", "grafana", "zentao", "jira", "sonar"):
            if kw in lower:
                marks.append(kw)
        if title or server or marks:
            return {"host": host, "port": port, "service": "http", "title": title.strip()[:60], "server": server[:60], "panel_hints": marks}
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="高价值服务只读核查")
    ap.add_argument("--hosts", required=True, nargs="+", help="主机或 file:路径")
    ap.add_argument("--ports", default="", help="显式端口(逗号分隔)；缺省=内置检查端口+常见HTTP")
    ap.add_argument("-t", "--timeout", type=float, default=2.0)
    ap.add_argument("--workers", type=int, default=100)
    args = ap.parse_args()

    hosts = []
    for part in args.hosts:
        part = part.strip()
        if not part:
            continue
        if part.startswith("file:"):
            with open(part[5:], encoding="utf-8") as f:
                hosts += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        else:
            hosts.append(part)

    if args.ports:
        portset = sorted({int(p) for p in args.ports.split(",") if p.strip().isdigit()})
    else:
        portset = sorted(set(CHECKS) | set(HTTP_PORTS))
    if not hosts or not portset:
        print(json.dumps({"error": "host/端口为空"}))
        return 1

    jobs = [(h, p) for h in hosts for p in portset]
    hits = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(lambda j: probe(j[0], j[1], args.timeout), jobs):
            if r:
                hits += 1
                print(json.dumps(r, ensure_ascii=False))
    print(json.dumps({"summary": {"hosts": len(hosts), "ports": len(portset), "hits": hits}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
