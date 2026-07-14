#!/usr/bin/env python
"""
Playwright 爬虫 — JS 渲染 + 请求拦截 + 攻击面提取

适用于 SPA 站点（Vue/React/Angular）和需要 JS 渲染的页面。
自带请求拦截，不需要外部代理。

用法:
  单目标:  python playwright_crawler.py http://example.com
  批量:    python playwright_crawler.py -l urls.txt
  输出:    python playwright_crawler.py http://example.com -o results.json

输出内容:
  - 所有网络请求（含 XHR/fetch）
  - 页面链接
  - 表单及字段
  - JS 中发现的 API 端点
  - 带参数的 URL（注入测试候选）
"""
import sys, os, re, json, argparse
from urllib.parse import urlparse, urljoin

# 清理代理环境变量，避免干扰
for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)


def crawl_url(url, headless=True, timeout=30000):
    from playwright.sync_api import sync_playwright

    result = {
        "url": url,
        "requests": [],
        "responses": [],
        "links": [],
        "forms": [],
        "js_apis": [],
        "parameterized_urls": [],
        "errors": [],
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()

            # 请求拦截
            def on_request(req):
                entry = {
                    "url": req.url,
                    "method": req.method,
                }
                if req.post_data:
                    entry["post_data"] = req.post_data[:500]
                result["requests"].append(entry)

            def on_response(resp):
                result["responses"].append({
                    "url": resp.url,
                    "status": resp.status,
                    "content_type": resp.headers.get("content-type", ""),
                })

            page.on("request", on_request)
            page.on("response", on_response)

            # 访问页面
            page.goto(url, wait_until="networkidle", timeout=timeout)

            # 等额外的异步请求
            page.wait_for_timeout(2000)

            # 提取链接
            try:
                links = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href).filter(h => h && !h.startsWith('javascript:'))"
                )
                result["links"] = list(set(links))
            except:
                pass

            # 提取表单
            try:
                forms = page.eval_on_selector_all("form", """els => els.map(e => ({
                    action: e.action || '',
                    method: (e.method || 'GET').toUpperCase(),
                    enctype: e.enctype || '',
                    inputs: [...e.querySelectorAll('input,select,textarea')].map(i => ({
                        name: i.name || '',
                        type: i.type || 'text',
                        value: i.value || '',
                        placeholder: i.placeholder || ''
                    })).filter(i => i.name)
                }))""")
                result["forms"] = forms
            except:
                pass

            # 提取页面 HTML 中的 JS API 端点
            try:
                content = page.content()

                # 各种 API 调用模式
                patterns = [
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
                    r'\$\.(get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
                    r'["\'](/api/[^"\'\\s]{3,})["\']',
                    r'["\'](/v[12]/[^"\'\\s]{3,})["\']',
                    r'url\s*[:=]\s*["\']([^"\']+/api/[^"\']*)["\']',
                    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
                    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
                ]

                apis = set()
                for pattern in patterns:
                    for m in re.finditer(pattern, content):
                        found = m.group(m.lastindex)
                        if found and len(found) > 3 and not found.endswith(('.js', '.css', '.png', '.jpg')):
                            apis.add(found)

                result["js_apis"] = sorted(apis)
            except:
                pass

            # 从所有请求中提取带参数的 URL
            param_urls = set()
            for req in result["requests"]:
                req_url = req["url"]
                parsed = urlparse(req_url)
                # 排除静态资源
                if parsed.path.split('.')[-1] in ('js', 'css', 'png', 'jpg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf'):
                    continue
                if parsed.query or req.get("post_data"):
                    param_urls.add(req_url)

            result["parameterized_urls"] = sorted(param_urls)

            browser.close()

    except Exception as e:
        result["errors"].append(str(e))

    return result


def main():
    parser = argparse.ArgumentParser(description="Playwright crawler with request interception")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-l", "--list", help="File with URLs, one per line")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("--no-headless", action="store_true", help="Show browser window")
    parser.add_argument("--timeout", type=int, default=30000, help="Page load timeout in ms")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        urls.extend(line.strip() for line in open(args.list) if line.strip())

    all_results = []
    for url in urls:
        print(f"[*] Crawling {url}", file=sys.stderr)
        result = crawl_url(url, headless=not args.no_headless, timeout=args.timeout)

        # 打印摘要
        print(f"    Requests: {len(result['requests'])}", file=sys.stderr)
        print(f"    Links: {len(result['links'])}", file=sys.stderr)
        print(f"    Forms: {len(result['forms'])}", file=sys.stderr)
        print(f"    JS APIs: {len(result['js_apis'])}", file=sys.stderr)
        print(f"    Parameterized URLs: {len(result['parameterized_urls'])}", file=sys.stderr)

        # 输出关键发现到 stdout
        if result["forms"]:
            for form in result["forms"]:
                enctype = f" [enctype={form['enctype']}]" if "multipart" in form.get("enctype", "") else ""
                print(f"[FORM] {form['method']} {form['action']}{enctype} | fields: {', '.join(i['name'] for i in form['inputs'])}")

        if result["js_apis"]:
            for api in result["js_apis"]:
                print(f"[API] {api}")

        if result["parameterized_urls"]:
            for purl in result["parameterized_urls"][:30]:
                print(f"[PARAM] {purl}")

        if result["errors"]:
            for err in result["errors"]:
                print(f"[ERROR] {err}", file=sys.stderr)

        all_results.append(result)

    # 输出 JSON
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"\n[*] Results saved to {args.output}", file=sys.stderr)
    elif not args.url:
        # 批量模式无 -o 时输出到 stdout
        print(json.dumps(all_results, ensure_ascii=False, indent=2))

    # 汇总
    total_forms = sum(len(r["forms"]) for r in all_results)
    total_apis = sum(len(r["js_apis"]) for r in all_results)
    total_params = sum(len(r["parameterized_urls"]) for r in all_results)
    print(f"\n--- 汇总: {len(urls)} URL | {total_forms} 表单 | {total_apis} JS API | {total_params} 带参URL ---", file=sys.stderr)


if __name__ == "__main__":
    main()
