#!/usr/bin/env python3
"""
CORS 批量检测 — 含 OPTIONS 预检 + SameSite 属性检查

用法:
  python3 cors_check.py <urls_file>
  python3 cors_check.py /tmp/httpx_alive.txt

urls_file 每行一个完整 URL，如:
  https://target.com/api/endpoint1
  https://target.com/api/endpoint2

输出: 每个 URL 的 CORS 配置 + 浏览器可利用性判定
"""
import sys, os, ssl
from urllib import request, error

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

EVIL_ORIGIN = "https://evil.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def fetch_headers(url, method="GET", extra_headers=None, body=None):
    headers = {"User-Agent": UA}
    if extra_headers:
        headers.update(extra_headers)
    if isinstance(body, str):
        body = body.encode()
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = request.urlopen(req, timeout=10, context=ctx)
        return resp.getcode(), dict(resp.headers)
    except error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception:
        return 0, {}

def check_cors(url):
    result = {
        "url": url,
        "reflects_origin": False,
        "allows_credentials": False,
        "preflight_pass": False,
        "samesite": "unknown",
        "browser_exploitable": False,
        "severity": "none",
    }

    # 1. 基础 CORS 检测 (GET + Origin)
    code, hdrs = fetch_headers(url, "GET", {"Origin": EVIL_ORIGIN})
    acao = hdrs.get("Access-Control-Allow-Origin", hdrs.get("access-control-allow-origin", ""))
    acac = hdrs.get("Access-Control-Allow-Credentials", hdrs.get("access-control-allow-credentials", ""))

    if EVIL_ORIGIN in acao or acao == "*":
        result["reflects_origin"] = True
    if "true" in acac.lower():
        result["allows_credentials"] = True

    if not result["reflects_origin"]:
        result["severity"] = "none"
        return result

    # 2. POST CORS 检测
    code2, hdrs2 = fetch_headers(url, "POST", {
        "Origin": EVIL_ORIGIN,
        "Content-Type": "application/json",
    }, body="{}")
    acao2 = hdrs2.get("Access-Control-Allow-Origin", hdrs2.get("access-control-allow-origin", ""))
    if EVIL_ORIGIN not in acao2 and acao2 != "*":
        pass  # GET 反射但 POST 不反射

    # 3. OPTIONS 预检检测
    code3, hdrs3 = fetch_headers(url, "OPTIONS", {
        "Origin": EVIL_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type",
    })
    acah = hdrs3.get("Access-Control-Allow-Headers", hdrs3.get("access-control-allow-headers", ""))
    acam = hdrs3.get("Access-Control-Allow-Methods", hdrs3.get("access-control-allow-methods", ""))
    acao3 = hdrs3.get("Access-Control-Allow-Origin", hdrs3.get("access-control-allow-origin", ""))

    if code3 in (200, 204) and (EVIL_ORIGIN in acao3 or acao3 == "*"):
        if "content-type" in acah.lower() or "*" in acah:
            result["preflight_pass"] = True

    # 4. SameSite 检测 (从响应中提取 Set-Cookie)
    for key, val in hdrs.items():
        if key.lower() == "set-cookie":
            val_lower = val.lower()
            if "samesite=none" in val_lower:
                result["samesite"] = "None"
            elif "samesite=strict" in val_lower:
                result["samesite"] = "Strict"
            elif "samesite=lax" in val_lower:
                result["samesite"] = "Lax"
            else:
                result["samesite"] = "not-set (default Lax)"

    # 5. 综合判定
    if result["reflects_origin"] and result["allows_credentials"]:
        if result["preflight_pass"] and result["samesite"] in ("None",):
            result["browser_exploitable"] = True
            result["severity"] = "high"
        elif result["preflight_pass"]:
            result["severity"] = "medium"
            result["note"] = "preflight OK but SameSite may block cookies"
        else:
            result["severity"] = "low"
            result["note"] = "curl exploitable only, preflight blocked"
    elif result["reflects_origin"]:
        result["severity"] = "info"
        result["note"] = "reflects origin but no credentials"

    return result

def main():
    if len(sys.argv) < 2:
        print("用法: python3 cors_check.py <urls_file>")
        print("      python3 cors_check.py -u <single_url>")
        sys.exit(1)

    if sys.argv[1] == "-u":
        urls = [sys.argv[2]]
    else:
        with open(sys.argv[1]) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print("=" * 100)
    print("CORS Batch Check — %d URLs" % len(urls))
    print("=" * 100)

    stats = {"high": 0, "medium": 0, "low": 0, "info": 0, "none": 0}

    for url in urls:
        r = check_cors(url)
        stats[r["severity"]] += 1

        if r["severity"] == "none":
            continue

        tag = r["severity"].upper()
        print("\n[%s] %s" % (tag, r["url"]))
        print("  ACAO reflects origin: %s" % r["reflects_origin"])
        print("  Allow-Credentials:    %s" % r["allows_credentials"])
        print("  OPTIONS preflight:    %s" % ("PASS" if r["preflight_pass"] else "FAIL"))
        print("  SameSite:             %s" % r["samesite"])
        print("  Browser exploitable:  %s" % r["browser_exploitable"])
        if "note" in r:
            print("  Note: %s" % r["note"])

    print("\n" + "=" * 100)
    print("Summary: HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d  CLEAN=%d  TOTAL=%d" % (
        stats["high"], stats["medium"], stats["low"], stats["info"], stats["none"], len(urls)))

if __name__ == "__main__":
    main()
