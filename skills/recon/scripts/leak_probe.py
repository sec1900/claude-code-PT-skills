#!/usr/bin/env python3
"""
信息泄露探测脚本 — 含 SPA 假阳性过滤 + body 关键字校验

用法: python3 leak_probe.py /tmp/urls_p1.txt
输出: 每行一条确认的泄露，格式 [LEAK] 状态码 URL (大小) | 描述
"""
import os, sys, urllib.request, ssl, hashlib

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 路径 → (body 关键字列表, 描述)
# body 不包含任何关键字 → 假阳性
LEAK_RULES = {
    "/.git/HEAD":           (["ref: refs/", "ref:refs/"], ".git HEAD"),
    "/.git/config":         (["[core]", "repositoryformatversion", "[remote"], ".git config"),
    "/.env":                (["=", "DB_", "APP_", "SECRET", "KEY", "PASSWORD"], ".env file"),
    "/phpinfo.php":         (["PHP Version", "phpinfo()", "PHP Credits"], "phpinfo"),
    "/actuator":            (["_links", "self", "href"], "Spring Actuator"),
    "/actuator/env":        (["propertySources", "activeProfiles", "systemProperties"], "Actuator Env"),
    "/actuator/health":     (["status", "UP", "DOWN", "components"], "Actuator Health"),
    "/actuator/heapdump":   ([], "Actuator Heapdump"),
    "/druid/index.html":    (["Druid Stat", "druid", "DataSource"], "Druid Console"),
    "/swagger-ui.html":     (["swagger", "Swagger UI", "api-docs"], "Swagger UI"),
    "/api-docs":            (["swagger", "openapi", "paths", "info"], "API Docs"),
    "/nacos/":              (["nacos", "Nacos", "console-ui"], "Nacos Console"),
    "/console":             (["console", "h2-console", "login"], "Console"),
    "/server-status":       (["Apache Server Status", "Total Accesses", "Scoreboard"], "Apache Status"),
    "/server-info":         (["Apache Server Information", "Module Name"], "Apache Info"),
    "/debug":               (["SERVER_NAME", "DOCUMENT_ROOT", "REQUEST_URI", "debug"], "Debug Page"),
    "/debug/config":        (["config", "database", "app_name"], "Debug Config"),
    "/.DS_Store":           (["\x00\x00\x00\x01Bud1"], ".DS_Store"),
    "/wp-json/wp/v2/users": (["id", "name", "slug", "link"], "WP Users API"),
    "/trace":               (["timestamp", "info", "method"], "Trace Endpoint"),
}

url_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/urls_p1.txt"
urls = [u.strip() for u in open(url_file) if u.strip()]

# Step 1: 获取每个 URL 首页的 body hash，用于 SPA 假阳性检测
homepage_hashes = {}
for url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=8, context=ctx)
        body = resp.read(5000)
        homepage_hashes[url] = hashlib.md5(body).hexdigest()
    except:
        homepage_hashes[url] = ""

# Step 2: 逐路径探测 + 校验
for url in urls:
    for path, (keywords, desc) in LEAK_RULES.items():
        probe_url = url.rstrip("/") + path
        try:
            req = urllib.request.Request(probe_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=8, context=ctx)
            body = resp.read(10000)
            body_text = body.decode("utf-8", errors="replace")
            body_hash = hashlib.md5(body[:5000]).hexdigest()
            code = resp.getcode()
            ctype = resp.headers.get("Content-Type", "")
            size = len(body)

            if code != 200:
                continue
            if size < 10:
                continue
            # SPA 检测: body hash 与首页相同 → 假阳性
            if body_hash == homepage_hashes.get(url, ""):
                continue
            # 关键字校验 (heapdump 除外)
            if keywords:
                if not any(kw in body_text for kw in keywords):
                    continue
            elif path == "/actuator/heapdump":
                if "application/octet-stream" not in ctype:
                    continue

            print("[LEAK] %d %s (%db) | %s" % (code, probe_url, size, desc))
        except urllib.error.HTTPError as e:
            if e.code == 403 and path in ["/.git/HEAD", "/.git/config"]:
                print("[INFO] 403 %s | %s (exists but forbidden)" % (probe_url, desc))
        except:
            pass
