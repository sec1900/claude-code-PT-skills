#!/usr/bin/env python3
"""
Webpack 源码提取器 — 本地化复现 Webpack_extract 核心能力。

从目标 URL 下载 JS 文件，检测 Webpack 打包，提取:
  1. 模块注册表 → 拆分为独立源文件
  2. Source Map → 还原完整原始源码
  3. API 端点 / 路径 / 敏感信息

用法:
  python webpack_extract.py -u https://target.com
  python webpack_extract.py -u https://target.com -o ./output --depth 3
  python webpack_extract.py -j https://target.com/js/app.js  # 直接分析单个 JS

对比 Webpack_extract Chrome 扩展:
  - 扩展: 从浏览器内存 (window.__webpack_require__) 直接读 → 100% 准确
  - 本脚本: 从下载的 JS 文本中正则提取 → 覆盖主流 Webpack 4/5 格式
"""

import re
import json
import base64
import argparse
import sys
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse
from collections import defaultdict

try:
    import requests
except ImportError:
    print("[!] 需要 requests 库: pip install requests")
    sys.exit(1)

# ============================================================
# 一、Webpack 检测与识别
# ============================================================

RE_WEBPACK_SIGNATURE = re.compile(
    r'__webpack_require__|webpackJsonp|webpackChunk|webpackBootstrap|'
    r'webpack-dev-server|webpack:\/\/|__webpack_public_path__|'
    r'installedModules|moduleId|chunkId',
    re.IGNORECASE
)

RE_WEBPACK4 = re.compile(r'\/\*! webpack [34]\.')
RE_WEBPACK5 = re.compile(r'\/\*! webpack [56]\.|self\.webpackChunk')

RE_SOURCEMAP_URL = re.compile(r'//# sourceMappingURL=(.+?)(?:\n|$)', re.MULTILINE)
RE_SOURCEMAP_DATA = re.compile(r'//# sourceMappingURL=data:application/json(?:;charset=utf-8)?;base64,(.+?)(?:\n|$)', re.MULTILINE)


def detect_webpack(js_content):
    if not RE_WEBPACK_SIGNATURE.search(js_content):
        return False, None
    if RE_WEBPACK5.search(js_content):
        return True, 5
    if RE_WEBPACK4.search(js_content):
        return True, 4
    return True, "unknown"


# ============================================================
# 二、Source Map 提取
# ============================================================

def extract_sourcemap(js_content, base_url="", session=None):
    data_match = RE_SOURCEMAP_DATA.search(js_content)
    if data_match:
        try:
            b64 = data_match.group(1)
            raw = base64.b64decode(b64).decode('utf-8')
            return json.loads(raw)
        except Exception as e:
            print(f"  [!] 内联 source map 解码失败: {e}")

    url_match = RE_SOURCEMAP_URL.search(js_content)
    if url_match:
        url = url_match.group(1).strip()
        if url.startswith('data:'):
            return None
        full_url = urljoin(base_url, url)
        if session:
            try:
                resp = session.get(full_url, timeout=15)
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if text.startswith(')]}\''):
                        text = text[4:]
                    return json.loads(text)
                else:
                    print(f"  [!] Source map 下载失败: HTTP {resp.status_code} ({full_url})")
            except Exception as e:
                print(f"  [!] Source map 下载异常: {e} ({full_url})")
        else:
            print(f"  [*] 发现外部 source map: {full_url}")

    return None


# ============================================================
# 三、Webpack 模块注册表提取
# ============================================================

def extract_module_registry(js_content):
    modules = {}

    iife_end = _find_iife_module_object(js_content)
    if iife_end:
        parsed = _parse_module_object(iife_end)
        modules.update(parsed)

    chunk_push = re.findall(
        r'(?:webpackJsonp|webpackChunk\w*|self\.webpackChunk\w*)\s*\.\s*push\s*\(\s*\[',
        js_content
    )
    for match in chunk_push:
        start = js_content.find(match)
        if start == -1:
            continue
        module_obj = _extract_chunk_modules(js_content, start + len(match) - 1)
        if module_obj:
            parsed = _parse_module_object(module_obj)
            modules.update(parsed)

    return modules if modules else None


def _find_iife_module_object(js):
    require_call = re.search(
        r'__webpack_require__\s*\(\s*__webpack_require__\s*\.\s*s\s*=\s*',
        js
    )
    if not require_call:
        require_call = re.search(
            r'__webpack_require__\s*\(\s*["\']\.\/',
            js
        )
    if not require_call:
        require_call = re.search(
            r'return\s+__webpack_require__\s*\(\s*["\']([^"\']+)["\']',
            js
        )

    if not require_call:
        return None

    pos = require_call.start()
    search_start = max(0, pos - 2000)
    snippet = js[search_start:pos]

    iife_match = re.search(r'\}\s*\)\s*\(\s*(\{)', snippet)
    if not iife_match:
        iife_match = re.search(r'\]\s*\)\s*\(\s*(\{)', snippet)

    if not iife_match:
        all_iife = list(re.finditer(r'\}\s*\)\s*\(\s*\{', js))
        if not all_iife:
            return None
        iife_start = all_iife[-1].end() - 1
    else:
        iife_start = search_start + iife_match.start(1)

    return _extract_balanced_braces(js, iife_start)


def _extract_balanced_braces(js, start):
    if start >= len(js) or js[start] != '{':
        return None
    depth = 0
    i = start
    while i < len(js):
        ch = js[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return js[start:i+1]
        elif ch in ('"', "'", '`'):
            quote = ch
            i += 1
            while i < len(js) and js[i] != quote:
                if js[i] == '\\':
                    i += 1
                i += 1
        i += 1
    return None


def _extract_chunk_modules(js, start):
    brace_pos = js.find('{', start)
    if brace_pos == -1:
        return None
    return _extract_balanced_braces(js, brace_pos)


def _parse_module_object(obj_str):
    modules = {}
    if not obj_str:
        return modules

    obj_str = obj_str.strip()
    if obj_str.startswith('{'):
        obj_str = obj_str[1:]
    if obj_str.endswith('}'):
        obj_str = obj_str[:-1]
    if obj_str.endswith('};'):
        obj_str = obj_str[:-2]

    pattern = re.compile(
        r'(?:(["\'])((?:[^"\\]|\\.)*)\1|(\w+))\s*:\s*'
        r'('
        r'function\s*\([^)]*\)\s*\{[^}]*\}|'
        r'function\s*\([^)]*\)\s*\{.*?\n\}|'
        r'\(\s*function\s*\([^)]*\)\s*\{.*?\}\s*\)|'
        r'\([^)]*\)\s*=>\s*\{.*?\}|'
        r'\(\s*function\s*\(.*?\}\s*\)'
        r')',
        re.DOTALL
    )

    for m in pattern.finditer(obj_str):
        key = m.group(2) or m.group(3)
        value = m.group(4)
        if key and value:
            modules[key] = value.strip()

    return modules


# ============================================================
# 四、JS 文件发现（从 HTML 页面）
# ============================================================

RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
RE_SCRIPT_INLINE = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
RE_LINK_JS = re.compile(r'<link[^>]+href=["\']([^"\']+\.js)["\']', re.IGNORECASE)


def discover_js_files(html, base_url):
    js_urls = set()

    for m in RE_SCRIPT_SRC.finditer(html):
        url = urljoin(base_url, m.group(1))
        if url not in js_urls:
            js_urls.add(url)

    for m in RE_LINK_JS.finditer(html):
        url = urljoin(base_url, m.group(1))
        if url not in js_urls:
            js_urls.add(url)

    for m in RE_SCRIPT_INLINE.finditer(html):
        inline = m.group(1)
        for imp in re.finditer(r'import\s*\(\s*["\']([^"\']+)["\']', inline):
            js_urls.add(urljoin(base_url, imp.group(1)))
        for src in re.finditer(r'["\']src["\']\s*:\s*["\']([^"\']+\.js)["\']', inline):
            js_urls.add(urljoin(base_url, src.group(1)))
        for chunk in re.finditer(r'["\'](?:chunk|bundle)[^"\']*\.js["\']', inline, re.IGNORECASE):
            js_urls.add(urljoin(base_url, chunk.group(0).strip('"\'"')))

    return sorted(js_urls)


# ============================================================
# 五、API 端点 & 路径提取
# ============================================================

RE_PATH_FROM_JS = re.compile(
    r"""["']((?:/[a-zA-Z0-9_\-./]+/?|(?:https?://)?[a-zA-Z0-9_\-]+"""
    r"""\.[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-./?=&%#]*)?))["']""",
    re.IGNORECASE
)
RE_API_PATH = re.compile(r'["\']((?:/api|/v\d|/rest|/graphql|/ws|/sock)/[^"\'\s]*)["\']')
RE_INTERNAL_PATH = re.compile(r'["\']((?:/admin|/manage|/dashboard|/internal|/debug|/test)/[^"\'\s]*)["\']')
RE_WEBSOCKET = re.compile(r'["\']((?:ws|wss)://[^"\']+)["\']')


def extract_urls_from_js(js_content, base_url=""):
    results = {
        "api_endpoints": set(),
        "internal_paths": set(),
        "websockets": set(),
        "all_urls": set(),
    }

    for m in RE_API_PATH.finditer(js_content):
        results["api_endpoints"].add(m.group(1))
    for m in RE_INTERNAL_PATH.finditer(js_content):
        results["internal_paths"].add(m.group(1))
    for m in RE_WEBSOCKET.finditer(js_content):
        results["websockets"].add(m.group(1))
    for m in RE_PATH_FROM_JS.finditer(js_content):
        path = m.group(1)
        if path.startswith('/') or path.startswith('http'):
            results["all_urls"].add(path)

    return {k: sorted(v) for k, v in results.items() if v}


# ============================================================
# 六、敏感信息检测
# ============================================================

SENSITIVE_RULES = [
    ("aws_access_key", r'(?i)(?:AWS|aws)[_\s]*(?:access|secret)[_\s]*key[_\s]*(?:id)?[=:]\s*["\']?([A-Z0-9+/=]{16,})["\']?', "critical"),
    ("aws_secret", r'(?i)(?:AWS|aws)[_\s]*secret[_\s]*(?:key)?[=:]\s*["\']?([A-Za-z0-9/+=]{40,})["\']?', "critical"),
    ("google_api_key", r'(?i)AIza[0-9A-Za-z\-_]{35}', "high"),
    ("github_token", r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "critical"),
    ("jwt_token", r'(?i)eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*', "medium"),
    ("private_key", r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "critical"),
    ("password_in_js", r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\'\s]{4,50}["\']', "high"),
    ("api_key_in_js", r'(?i)(?:api[_\s]?key|apikey|api[_\s]?secret|secret[_\s]?key)\s*[=:]\s*["\'][^"\'\s]{10,}["\']', "high"),
    ("connection_string", r'(?i)(?:mongodb|mysql|postgres|postgresql|redis|sqlserver|oracle)://[^"\'<>\s]{10,}', "critical"),
    ("db_credentials", r'(?i)(?:host|port|database|user|username)\s*[=:]\s*["\'][^"\'\s]{2,}["\']', "low"),
    ("internal_ip", r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', "medium"),
    ("internal_domain", r'(?i)\.(?:internal|local|corp|intranet|dev|staging|test)\.', "low"),
    ("private_registry", r'(?i)(?:npm\.internal|nexus\.internal|artifactory\.internal|docker\.internal)', "medium"),
    ("email", r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "low"),
    ("phone_cn", r'1[3-9]\d{9}', "low"),
    ("id_card", r'\b\d{17}[\dXx]\b', "medium"),
    ("open_cors", r'(?i)access-control-allow-origin\s*:\s*\*', "medium"),
    ("exposed_debug", r'(?i)(?:debug|verbose|trace)\s*[=:]\s*(?:true|1|enabled)', "low"),
    ("hardcoded_url", r'(?i)(?:base[_\s]?url|endpoint|api[_\s]?url)\s*[=:]\s*["\']https?://[^"\']{5,}["\']', "low"),
    ("wechat_appid", r'(?i)wx[0-9a-f]{16}', "medium"),
    ("alipay_appid", r'(?i)(?:alipay|支付宝)[_\s]*app[_\s]*id[=:]\s*["\']?\d{16,}["\']?', "medium"),
    ("aliyun_ak", r'(?i)(?:LTAI|STS\.)[A-Za-z0-9]{16,}', "critical"),
    ("azure_storage_key", r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+', "critical"),
    ("tencent_secret_id", r'(?i)AKID[A-Za-z0-9]{32,}', "high"),
]


def scan_sensitive(js_content, file_name=""):
    hits = []
    for rule_name, pattern, severity in SENSITIVE_RULES:
        for m in re.finditer(pattern, js_content):
            start = max(0, m.start() - 40)
            end = min(len(js_content), m.end() + 40)
            context = js_content[start:end].replace('\n', ' ').strip()
            hits.append({
                "file": file_name,
                "rule": rule_name,
                "severity": severity,
                "match": m.group(0),
                "context": f"...{context}...",
            })
    return hits


# ============================================================
# 七、主流程
# ============================================================

def build_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Accept": "text/html,application/javascript,application/x-javascript,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
    })
    return s


def fetch_js(url, session):
    try:
        resp = session.get(url, timeout=20)
        resp.raise_for_status()
        return resp.text, resp.url
    except Exception as e:
        print(f"  [!] 下载失败: {url} — {e}")
        return None, url


def process_single_js(js_content, url, session, output_dir):
    results = {
        "url": url,
        "is_webpack": False,
        "webpack_version": None,
        "sourcemap": None,
        "modules": None,
        "urls": None,
        "sensitive": [],
    }

    is_wp, version = detect_webpack(js_content)
    results["is_webpack"] = is_wp
    results["webpack_version"] = version

    if not is_wp:
        return results

    print(f"  [Webpack v{version}] {url}")

    # 1. Source Map 提取
    sm = extract_sourcemap(js_content, url, session)
    if sm:
        n_sources = len(sm.get("sourcesContent", []))
        n_empty = sum(1 for s in sm.get("sourcesContent", []) if not s)
        print(f"    [SourceMap] {len(sm.get('sources', []))} 个源文件, "
              f"{n_sources} 个有源码内容")
        results["sourcemap"] = {
            "file": sm.get("file", ""),
            "sourceRoot": sm.get("sourceRoot", ""),
            "source_count": len(sm.get("sources", [])),
            "with_content": n_sources,
            "without_content": n_empty,
        }

        if output_dir and n_sources > 0:
            sm_dir = Path(output_dir) / "sourcemap" / _safe_filename(url)
            sm_dir.mkdir(parents=True, exist_ok=True)
            for i, src in enumerate(sm.get("sources", [])):
                content = sm.get("sourcesContent", [None])[i] if i < len(sm.get("sourcesContent", [])) else None
                if content:
                    fp = sm_dir / src.lstrip("./\\")
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(content, encoding='utf-8')
            print(f"    [保存] {n_sources} 个文件 → {sm_dir}")

    # 2. 模块注册表提取
    modules = extract_module_registry(js_content)
    if modules and len(modules) > 5:
        print(f"    [模块] 提取到 {len(modules)} 个模块")
        results["modules"] = {"count": len(modules), "sample": list(modules.keys())[:10]}

        if output_dir:
            mod_dir = Path(output_dir) / "modules" / _safe_filename(url)
            mod_dir.mkdir(parents=True, exist_ok=True)
            for mod_id, mod_code in modules.items():
                fp = mod_dir / _safe_filename(str(mod_id))
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(mod_code, encoding='utf-8')
            print(f"    [保存] {len(modules)} 个模块 → {mod_dir}")

    # 3. URL/API 提取
    urls = extract_urls_from_js(js_content)
    if any(urls.values()):
        results["urls"] = {k: v[:20] for k, v in urls.items()}
        print(f"    [URL] API端点:{len(urls.get('api_endpoints',[]))} "
              f"内部路径:{len(urls.get('internal_paths',[]))} "
              f"WebSocket:{len(urls.get('websockets',[]))}")

    # 4. 敏感信息扫描
    hits = scan_sensitive(js_content, url)
    if hits:
        results["sensitive"] = hits
        for h in hits[:5]:
            print(f"    [!] [{h['severity'].upper()}] {h['rule']}: {h['match'][:80]}")

    return results


def process_url(target_url, output_dir=None, depth=1, session=None):
    if session is None:
        session = build_session()

    print(f"\n{'='*60}")
    print(f"[*] 目标: {target_url}")
    print(f"{'='*60}")

    try:
        resp = session.get(target_url, timeout=20)
        resp.raise_for_status()
        html = resp.text
        print(f"[+] 页面: HTTP {resp.status_code}, {len(html)} bytes")
    except Exception as e:
        print(f"[!] 页面加载失败: {e}")
        return []

    js_urls = discover_js_files(html, target_url)
    print(f"[+] 发现 {len(js_urls)} 个 JS 文件")

    all_results = []

    for i, js_url in enumerate(js_urls):
        print(f"\n[{i+1}/{len(js_urls)}] {js_url}")
        js_content, final_url = fetch_js(js_url, session)
        if not js_content:
            continue

        result = process_single_js(js_content, final_url, session, output_dir)
        all_results.append(result)

    webpack_count = sum(1 for r in all_results if r["is_webpack"])
    sm_count = sum(1 for r in all_results if r["sourcemap"])
    hits_count = sum(len(r["sensitive"]) for r in all_results)

    print(f"\n{'='*60}")
    print(f"[*] 汇总: {len(all_results)} JS, {webpack_count} Webpack, "
          f"{sm_count} SourceMap, {hits_count} 敏感命中")
    print(f"{'='*60}")

    return all_results


def _safe_filename(url_str):
    parsed = urlparse(url_str)
    path = parsed.path.strip('/')
    if not path:
        return parsed.netloc.replace(':', '_')
    return path.replace('/', '_').replace('\\', '_').replace(':', '_')


# ============================================================
# 八、CLI 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Webpack 源码提取器 — 本地化复现 Webpack_extract 核心能力",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python webpack_extract.py -u https://target.com
  python webpack_extract.py -u https://target.com -o ./output --depth 2
  python webpack_extract.py -j https://target.com/js/app.js -o ./js_dump
  python webpack_extract.py -j ./local_bundle.js
        """
    )
    parser.add_argument("-u", "--url", help="目标 URL（会先下载 HTML 再提取所有 JS）")
    parser.add_argument("-j", "--js", help="直接分析单个 JS 文件 URL 或本地路径")
    parser.add_argument("-o", "--output", default="./webpack_output",
                        help="输出目录 (默认: ./webpack_output)")
    parser.add_argument("--depth", type=int, default=1,
                        help="递归深度（预留，当前版本不支持递归爬虫）")
    parser.add_argument("--no-download", action="store_true",
                        help="不保存文件，只输出分析结果")
    parser.add_argument("--proxy", help="HTTP 代理 (如 http://127.0.0.1:8080)")

    args = parser.parse_args()

    if not args.url and not args.js:
        parser.print_help()
        sys.exit(1)

    session = build_session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    output_dir = None if args.no_download else args.output

    if args.js:
        if args.js.startswith("http"):
            print(f"[*] 下载 JS: {args.js}")
            js_content, url = fetch_js(args.js, session)
            if not js_content:
                sys.exit(1)
        else:
            url = args.js
            js_content = Path(args.js).read_text(encoding='utf-8')
            print(f"[*] 本地文件: {args.js} ({len(js_content)} bytes)")

        result = process_single_js(js_content, url, session, output_dir)

        if result["sensitive"]:
            print(f"\n[!] 敏感信息详情 ({len(result['sensitive'])} 条):")
            for h in result["sensitive"]:
                print(f"  [{h['severity'].upper()}] {h['rule']}: {h['match']}")
                print(f"    {h['context'][:120]}")

        if result.get("urls"):
            print(f"\n[API 端点]:")
            for ep in result["urls"].get("api_endpoints", [])[:30]:
                print(f"  {ep}")
            print(f"\n[内部路径]:")
            for p in result["urls"].get("internal_paths", [])[:20]:
                print(f"  {p}")

    else:
        results = process_url(args.url, output_dir, args.depth, session)

        all_hits = []
        for r in results:
            all_hits.extend(r["sensitive"])

        if all_hits:
            print(f"\n[!] 所有敏感信息 ({len(all_hits)} 条):")
            for h in all_hits:
                print(f"  [{h['severity'].upper()}] {h['rule']}: {h['match']} ({h['file']})")


if __name__ == "__main__":
    main()
