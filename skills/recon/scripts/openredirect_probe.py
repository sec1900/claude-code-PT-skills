#!/usr/bin/env python3
"""
Open Redirect 批量探测 — 参数级反射检测

用法:
  python3 openredirect_probe.py -u https://target.com/login?redirect=/home -p redirect,next,return
  python3 openredirect_probe.py -f /tmp/urls_with_params.txt
  python3 openredirect_probe.py -f /tmp/urls.txt --callback https://evil.com

输入:
  -u 单 URL + -p 参数名列表（逗号分隔）
  -f 文件，每行一个带参数的 URL（自动提取所有参数值）
  --callback 自定义回调域名（默认 https://evil.com）
  --follow-redirects 跟随重定向（默认不跟随，直接检查 30x）

输出: 每个参数的重定向反射类型 + 危险程度
"""

import sys, os, ssl, re, urllib.parse
from urllib import request, error

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 回调域名（可被替换）
EVIL_DOMAIN = "https://evil.com"

# 常见 redirect 参数名
COMMON_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirect_to",
    "url", "next", "return", "return_to", "return_url",
    "continue", "goto", "target", "dest", "destination",
    "ref", "referer", "referrer", "callback", "cb",
    "origin", "back", "back_url", "to", "forward",
    "jump", "jump_url", "link", "out", "r", "u",
    "redir", "service", "returnUrl", "redirectUrl",
    "success_url", "error_url", "cancel_url",
]

# JS redirect patterns to check in response body
JS_REDIRECT_PATTERNS = [
    r'window\.location\s*=\s*["\']?EVIL',
    r'window\.location\.href\s*=\s*["\']?EVIL',
    r'window\.location\.replace\s*\(\s*["\']?EVIL',
    r'document\.location\s*=\s*["\']?EVIL',
    r'document\.location\.href\s*=\s*["\']?EVIL',
    r'location\.href\s*=\s*["\']?EVIL',
    r'location\.replace\s*\(\s*["\']?EVIL',
    r'window\.open\s*\(\s*["\']?EVIL',
    r'self\.location\s*=\s*["\']?EVIL',
    r'top\.location\s*=\s*["\']?EVIL',
    r'<meta\s+http-equiv\s*=\s*["\']refresh["\']\s+content\s*=\s*["\'].*?EVIL',
]


def do_request(url, method="GET", follow=False, timeout=8):
    headers = {"User-Agent": UA}
    req = request.Request(url, headers=headers, method=method)

    if follow:
        from urllib.request import HTTPRedirectHandler
        opener = request.build_opener(HTTPRedirectHandler())
    else:
        # 自定义 handler 不跟随重定向
        class NoRedirectHandler(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = request.build_opener(NoRedirectHandler())

    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.getcode(), dict(resp.headers), body
    except error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except:
            pass
        return e.code, dict(e.headers), body
    except Exception as ex:
        return 0, {}, str(ex)


def check_open_redirect(url, param, callback_domain, follow=False):
    """对单个参数注入 callback 并检测重定向"""
    result = {
        "param": param,
        "http_redirect": False,
        "js_redirect": False,
        "meta_redirect": False,
        "redirect_type": "none",
        "severity": "none",
        "details": "",
    }

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [callback_domain]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    injected_url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )

    code, headers, body = do_request(injected_url, follow=follow)

    # 1. HTTP 30x 重定向
    if code in (301, 302, 303, 307, 308):
        location = headers.get("Location", headers.get("location", ""))
        if location:
            loc_parsed = urllib.parse.urlparse(location)
            evil_parsed = urllib.parse.urlparse(callback_domain)
            if evil_parsed.netloc.lower() in loc_parsed.netloc.lower():
                result["http_redirect"] = True
                result["redirect_type"] = "http_30x"
                result["details"] = "Location: %s" % location[:120]
            else:
                # 重定向到其他域但不是我们的 callback（可能是相对路径/同域）
                # 检查是否部分反射
                if evil_parsed.netloc.lower() in location.lower():
                    result["http_redirect"] = True
                    result["redirect_type"] = "http_30x_partial"
                    result["details"] = "Location: %s" % location[:120]

    # 2. JS 重定向
    for pattern in JS_REDIRECT_PATTERNS:
        pat = pattern.replace("EVIL", re.escape(callback_domain))
        matches = re.findall(pat, body, re.IGNORECASE)
        if matches:
            if "<meta" in pattern:
                result["meta_redirect"] = True
                result["redirect_type"] = "meta_refresh"
            else:
                result["js_redirect"] = True
                result["redirect_type"] = "js_location"
            result["details"] = "body contains: %s" % matches[0][:120] if isinstance(matches[0], str) else str(matches)[:120]
            break

    # 3. 检查 body 中是否直接出现了 callback URL（link/iframe/script src）
    if not result["http_redirect"] and not result["js_redirect"]:
        evil_host = urllib.parse.urlparse(callback_domain).netloc.lower()
        if evil_host in body.lower() and "href=\"%s" % callback_domain.lower() in body.lower():
            result["redirect_type"] = "html_reflection"
            result["details"] = "callback URL appears in HTML body"
        elif evil_host in body.lower():
            result["redirect_type"] = "partial_reflection"
            result["details"] = "callback host appears in body"

    # 4. 定级
    if result["redirect_type"] in ("http_30x",):
        result["severity"] = "high"
    elif result["redirect_type"] in ("http_30x_partial", "js_location", "meta_refresh"):
        result["severity"] = "medium"
    elif result["redirect_type"] in ("html_reflection",):
        result["severity"] = "low"
    elif result["redirect_type"] in ("partial_reflection",):
        result["severity"] = "info"
    else:
        result["severity"] = "none"

    return result


def main():
    callback_domain = EVIL_DOMAIN
    url_file = None
    single_url = None
    params = []
    follow = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--callback" and i + 1 < len(args):
            callback_domain = args[i + 1]
            if "://" not in callback_domain:
                callback_domain = "https://" + callback_domain
            i += 2
        elif args[i] == "-u" and i + 1 < len(args):
            single_url = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            params = [p.strip() for p in args[i + 1].split(",") if p.strip()]
            i += 2
        elif args[i] == "-f" and i + 1 < len(args):
            url_file = args[i + 1]
            i += 2
        elif args[i] == "--follow-redirects":
            follow = True
            i += 1
        else:
            i += 1

    # 构建待测列表
    targets = []

    if single_url:
        if not params:
            # 自动提取 URL 参数名，优先匹配常见 redirect 参数
            parsed = urllib.parse.urlparse(single_url)
            all_params = list(urllib.parse.parse_qs(parsed.query).keys())
            # 常见 redirect 参数排前面
            params = [p for p in COMMON_REDIRECT_PARAMS if p in all_params]
            remaining = [p for p in all_params if p not in params]
            params += remaining
        for p in params:
            targets.append((single_url, p))
    elif url_file:
        with open(url_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = urllib.parse.urlparse(line)
                qs = urllib.parse.parse_qs(parsed.query)
                if not qs:
                    continue
                redirect_params = [p for p in COMMON_REDIRECT_PARAMS if p in qs]
                all_params = redirect_params + [p for p in qs if p not in redirect_params]
                for p in all_params[:8]:  # 最多测 8 个参数
                    targets.append((line, p))
    else:
        print("用法: python3 openredirect_probe.py -u <url> -p <params> [--callback URL]")
        print("      python3 openredirect_probe.py -f <urls_file> [--callback URL]")
        sys.exit(1)

    if not targets:
        print("没有待测目标。")
        sys.exit(1)

    print("=" * 90)
    print("Open Redirect Probe — %d targets | callback: %s" % (len(targets), callback_domain))
    print("=" * 90)
    print("%-45s | %-12s | %-18s | %s" % ("URL (param)", "Code", "Result", "Details"))
    print("-" * 90)

    stats = {"high": 0, "medium": 0, "low": 0, "info": 0, "none": 0}

    seen = set()
    for url, param in targets:
        key = (url, param)
        if key in seen:
            continue
        seen.add(key)

        r = check_open_redirect(url, param, callback_domain, follow=follow)
        stats[r["severity"]] += 1

        if r["severity"] == "none":
            continue

        tag_map = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
        tag = tag_map.get(r["severity"], r["severity"].upper())

        short_url = url if len(url) <= 38 else url[:35] + "..."
        print("[%s] %-38s | %-12s | %-18s | %s" % (
            tag,
            "%s?%s=CALLBACK" % (short_url, param),
            "30x redirect" if r["http_redirect"] else "200",
            r["redirect_type"],
            r["details"][:60],
        ))

    print("-" * 90)
    print("Summary: HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d  NONE=%d  TOTAL=%d" % (
        stats["high"], stats["medium"], stats["low"], stats["info"], stats["none"], len(seen)))


if __name__ == "__main__":
    main()
