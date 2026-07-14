#!/usr/bin/env python3
"""
API 端点批量探测 — 同时测 GET/POST，输出状态码+响应摘要

用法:
  python3 api_probe.py <base_url> <endpoints_file>
  python3 api_probe.py https://target.com /tmp/endpoints.txt
  python3 api_probe.py https://target.com --dict common    (使用内置路径字典)
  python3 api_probe.py https://target.com --dict sensitive (敏感路径)
  python3 api_probe.py https://target.com --dict all       (全量 212K 路径, 慎用)

endpoints_file 每行一个路径，如:
  /api/user/info
  /api/login
  /user_center/api/account/info

输出: 表格形式，每个端点的 GET/POST 状态码 + 响应前 120 字符
"""
import sys, os, ssl, json
from urllib import request, error, parse

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*",
}

# Built-in dictionaries
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data")

# Common API/biz paths (high-value subset from 212K merged dict)
COMMON_PATHS = [
    "/api/v1/users", "/api/v1/login", "/api/v1/health", "/api/v1/info",
    "/api/user/info", "/api/user/login", "/api/user/register",
    "/api/login", "/api/health", "/api/info", "/api/admin",
    "/api/docs", "/api/swagger.json", "/api/v2/api-docs", "/api/v3/api-docs",
    "/swagger-ui.html", "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
    "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/mappings",
    "/admin/login", "/admin/index", "/admin/api",
    "/login", "/register", "/logout", "/forgot-password", "/reset-password",
    "/user/login", "/user/register", "/user/info", "/user/profile",
    "/graphql", "/graphiql", "/playground",
    "/.env", "/wp-json/", "/sitemap.xml", "/robots.txt",
    "/health", "/status", "/ping", "/version", "/info",
    "/druid/index.html", "/druid/login.html",
    "/console/login/LoginForm.jsp", "/j_spring_security_check",
    "/jmx-console/", "/jolokia/", "/actuator/jolokia",
    "/.git/config", "/.svn/entries", "/.DS_Store",
]

SENSITIVE_PATHS = [
    "/.git/config", "/.git/index", "/.git/HEAD", "/.svn/entries",
    "/.env", "/.env.backup", "/.env.production", "/.env.local",
    "/config/database.yml", "/database.yml", "/db.conf", "/db.ini",
    "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
    "/conf/server.xml", "/conf/tomcat-users.xml",
    "/phpinfo.php", "/info.php", "/apc.php",
    "/phpmyadmin/index.php", "/pma/index.php",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/swagger-ui.html", "/swagger-resources", "/v2/api-docs",
    "/druid/index.html", "/jmx-console/",
    "/.ssh/id_rsa", "/id_rsa", "/.ssh/known_hosts",
    "/.bash_history", "/.mysql_history", "/nohup.out",
    "/server-status", "/status",
    "/core", "/debug/pprof/heap?debug=1",
    "/metrics", "/prometheus/metrics",
    "/admin/login", "/manager/html",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/backup.zip", "/backup.tar.gz", "/db.zip", "/web.zip",
]

def load_dict(name):
    """Load path dictionary by name."""
    if name == "all":
        dict_path = os.path.join(DATA_DIR, "dict_merged_paths.json")
        if os.path.exists(dict_path):
            with open(dict_path, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("paths", [])
        return []
    elif name == "common":
        return COMMON_PATHS
    elif name == "sensitive":
        return SENSITIVE_PATHS
    elif os.path.isfile(name):
        return [line.strip() for line in open(name) if line.strip() and not line.startswith("#")]
    return []

def do_request(url, method="GET", body=None, extra_headers=None):
    headers = dict(HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    if method == "POST" and body is None:
        body = b"{}"
        headers["Content-Type"] = "application/json"
    elif isinstance(body, str):
        body = body.encode()
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = request.urlopen(req, timeout=10, context=ctx)
        data = resp.read(2000).decode("utf-8", errors="replace")
        return resp.getcode(), data
    except error.HTTPError as e:
        data = ""
        try:
            data = e.read(2000).decode("utf-8", errors="replace")
        except:
            pass
        return e.code, data
    except Exception as e:
        return 0, str(e)[:120]

def summarize(body, maxlen=120):
    s = body.strip().replace("\n", " ").replace("\r", "")
    if len(s) > maxlen:
        s = s[:maxlen] + "..."
    return s

def main():
    if len(sys.argv) < 2:
        print("用法: python3 api_probe.py <base_url> <endpoints_file>")
        print("      python3 api_probe.py <base_url> --dict common")
        print("      python3 api_probe.py <base_url> --dict sensitive")
        print("      python3 api_probe.py <base_url> --dict all")
        print("      python3 api_probe.py <base_url> -e '/path1,/path2,/path3'")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    endpoints = []
    if sys.argv[2] == "--dict":
        dict_name = sys.argv[3] if len(sys.argv) > 3 else "common"
        endpoints = load_dict(dict_name)
        print(f"[*] Loaded {len(endpoints)} paths from dict '{dict_name}'")
    elif sys.argv[2] == "-e":
        endpoints = [p.strip() for p in sys.argv[3].split(",") if p.strip()]
    else:
        with open(sys.argv[2]) as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # 可选: 认证头
    auth_header = {}
    for i, arg in enumerate(sys.argv):
        if arg == "--token" and i + 1 < len(sys.argv):
            auth_header["Authorization"] = sys.argv[i + 1]
        if arg == "--cookie" and i + 1 < len(sys.argv):
            auth_header["Cookie"] = sys.argv[i + 1]

    print("%-45s | %-12s | %-12s | %s" % ("Endpoint", "GET", "POST", "Response Summary"))
    print("-" * 120)

    for ep in endpoints:
        url = base_url + ("" if ep.startswith("/") else "/") + ep

        get_code, get_body = do_request(url, "GET", extra_headers=auth_header)
        post_code, post_body = do_request(url, "POST", extra_headers=auth_header)

        # 选择有内容的响应做摘要
        if post_code == 200 and post_body.strip():
            summary = summarize(post_body)
        elif get_code == 200 and get_body.strip():
            summary = summarize(get_body)
        elif post_body.strip():
            summary = summarize(post_body)
        elif get_body.strip():
            summary = summarize(get_body)
        else:
            summary = ""

        get_str = str(get_code) if get_code else "ERR"
        post_str = str(post_code) if post_code else "ERR"

        # 高亮有趣的结果
        flag = ""
        if get_code == 200 or post_code == 200:
            flag = " ←"
        elif get_code == 401 or post_code == 401:
            flag = " [AUTH]"
        elif get_code == 403 or post_code == 403:
            flag = " [FORBIDDEN]"

        print("%-45s | %-12s | %-12s | %s%s" % (ep, get_str, post_str, summary, flag))

    print("-" * 120)
    print("Done. %d endpoints tested." % len(endpoints))

if __name__ == "__main__":
    main()
