#!/usr/bin/env python3
"""
被动标记脚本 — 基于 yakit MITM 规则对 HTTP 响应做正则匹配，标记攻击面

用法:
  单目标:  python3 passive_tag.py http://example.com
  批量:    python3 passive_tag.py -l /tmp/urls.txt
  指定规则: python3 passive_tag.py -r /path/to/yakit_rules.json http://example.com

输出: [TAG] URL | 标签名 | 匹配位置(request/response/header/body) | 匹配内容片段

这个脚本不是 MITM 代理，而是主动抓取目标 HTTP 响应后用 yakit 规则做匹配。
"""
import os, sys, re, json, argparse, urllib.request, ssl

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10


def fetch(url, max_body=200000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX)
        headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.read(max_body).decode("utf-8", errors="replace")
        request_line = f"GET {url} HTTP/1.1\nHost: {urllib.request.urlparse(url).netloc}\nUser-Agent: {UA}"
        return request_line, headers_raw, body
    except Exception as e:
        return "", "", ""


def load_rules(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    rules = []
    for r in raw:
        regex = r.get("Rule", "")
        if not regex:
            continue
        tags = r.get("ExtraTag", [])
        name = r.get("VerboseName", "") or (tags[0] if tags else "unknown")
        try:
            compiled = re.compile(regex, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue
        rules.append({
            "name": name,
            "regex": compiled,
            "raw_pattern": regex[:80],
            "for_request": r.get("EnableForRequest", False),
            "for_response": r.get("EnableForResponse", False),
            "for_header": r.get("EnableForHeader", False),
            "for_body": r.get("EnableForBody", False),
        })
    return rules


def scan_url(url, rules):
    request_line, headers_raw, body = fetch(url)
    if not body and not headers_raw:
        return []

    hits = []
    seen = set()

    for rule in rules:
        name = rule["name"]
        regex = rule["regex"]

        targets = []
        if rule["for_header"]:
            targets.append(("header", headers_raw))
        if rule["for_body"]:
            targets.append(("body", body))
        if rule["for_request"]:
            targets.append(("request", request_line))
        if rule["for_response"]:
            targets.append(("response", headers_raw + "\n\n" + body))

        for location, text in targets:
            if not text:
                continue
            m = regex.search(text)
            if m:
                key = f"{name}:{location}"
                if key not in seen:
                    seen.add(key)
                    snippet = m.group(0)[:60].replace("\n", " ").strip()
                    hits.append((name, location, snippet))
                    break  # one match per rule per URL is enough

    return hits


# tag → 攻击类型映射，帮助 agent 知道下一步该做什么
TAG_TO_ACTION = {
    "疑似JSONP": "测试 JSONP 劫持 → skills/cors/",
    "登陆/密码传输": "检查是否明文传输，测试弱口令",
    "敏感信息": "提取密钥/token，尝试直接利用",
    "登陆点": "测试弱口令、万能密码、SQL注入",
    "登陆（验证码）": "测试验证码绕过 → 知识库 验证码识别与爆破.md",
    "文件上传点": "测试上传绕过 → skills/upload/",
    "文件包含参数": "测试 LFI/RFI → skills/file_inclusion/",
    "命令注入参数": "测试命令注入 → skills/injection/",
    "email泄漏": "收集邮箱，用于社工/密码喷洒",
    "手机号泄漏": "信息泄露，记录证据",
    "身份证": "严重信息泄露，记录证据",
    "RSA私钥": "严重泄露，尝试利用私钥",
    "OSS Key": "尝试接管 OSS bucket → skills/cloud_security/",
    "MySQL配置": "提取数据库凭据，尝试连接",
    "Shiro": "测试 Shiro 反序列化 → skills/middleware_exploit/",
    "SwaggerUI": "读取 API 文档，测试未授权接口",
    "JWT 测试点": "测试 JWT 伪造 → skills/jwt_attack/",
    "SQL注入测试点": "测试 SQL 注入 → skills/injection/",
    "SSRF测试参数": "测试 SSRF → skills/ssrf/",
    "XXE测试点": "测试 XXE → skills/xxe/",
    "XPath注入测试点": "测试 XPath 注入 → skills/xpath_injection/",
    "Struts2测试点": "测试 Struts2 RCE → skills/middleware_exploit/",
    "Java反序列化测试点": "测试 Java 反序列化 → skills/deserialization/",
    "Url重定向参数": "测试开放重定向 → skills/open_redirect/",
    "Source Map": "下载 source map，还原前端源码审计",
    "JDBC Connection": "提取 JDBC 连接串，测试数据库访问",
    "HTTP XSS测试点": "测试反射 XSS → skills/xss/",
    "XML请求": "测试 XXE → skills/xxe/",
    "SOAP请求": "测试 SOAP 注入",
    "后台登陆": "测试弱口令、默认口令",
    "云主机密钥": "尝试接管云主机 → skills/cloud_security/",
    "Amazon AK": "尝试 AWS 接管 → skills/cloud_security/",
    "URL作为参数": "测试 SSRF → skills/ssrf/",
    "Session/Token测试点": "测试 session 固定/token 伪造",
}


def main():
    parser = argparse.ArgumentParser(description="Passive tagging with yakit MITM rules")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-l", "--list", help="File with URLs, one per line")
    parser.add_argument("-r", "--rules", help="Path to yakit_rules.json",
                        default=os.path.join(os.path.dirname(__file__), "..", "data", "yakit_rules.json"))
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    rules_path = args.rules
    if not os.path.exists(rules_path):
        # 优先从 CLAUDE_SKILL_DIR 环境变量推断 data 目录
        skill_dir = os.environ.get("CLAUDE_SKILL_DIR", "")
        alts = []
        if skill_dir:
            alts.append(os.path.join(skill_dir, "data", "yakit_rules.json"))
        if not alts:
            print(f"[!] Rules file not found: {rules_path}", file=sys.stderr)
            print(f"    Set CLAUDE_SKILL_DIR env or use -r to specify path", file=sys.stderr)
            sys.exit(1)
        for alt in alts:
            if os.path.exists(alt):
                rules_path = alt
                break
        else:
            print(f"[!] Rules file not found in any fallback location", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Loading rules from {rules_path}", file=sys.stderr)
    rules = load_rules(rules_path)
    print(f"[*] Loaded {len(rules)} rules", file=sys.stderr)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        urls.extend(line.strip() for line in open(args.list) if line.strip())

    all_tags = {}
    for url in urls:
        print(f"[*] Scanning {url}", file=sys.stderr)
        hits = scan_url(url, rules)
        if hits:
            all_tags[url] = hits
            for name, location, snippet in hits:
                action = TAG_TO_ACTION.get(name, "")
                action_str = f" → {action}" if action else ""
                print(f"[TAG] {url} | {name} | {location} | {snippet}{action_str}")

    if all_tags:
        all_tag_names = set()
        for hits in all_tags.values():
            for name, _, _ in hits:
                all_tag_names.add(name)
        print(f"\n--- 共标记 {sum(len(v) for v in all_tags.values())} 个发现，覆盖 {len(all_tags)} 个URL ---", file=sys.stderr)
        print(f"[!] 发现的攻击面类型: {', '.join(sorted(all_tag_names))}", file=sys.stderr)


if __name__ == "__main__":
    main()
