#!/usr/bin/env python3
"""
敏感信息统一扫描器 — 基于 sensitive_rules.json (48条规则, 6大类)

每条规则的描述和风险分析专为 AI 研判设计:
  - description: 规则匹配什么
  - risk_analysis: 攻击者能利用这个做什么
  - fp_note: 常见误报场景, AI 用来判断真假

用法:
  # 扫描 URL 的 JS 文件
  python sensitive_scanner.py -u https://target.com/app.js

  # 扫描本地文件
  python sensitive_scanner.py -f bundle.js

  # 扫描 URL 响应 (含 header + body)
  python sensitive_scanner.py -r https://target.com/api/data --header "Authorization: Bearer xxx"

  # 扫描多个 URL
  python sensitive_scanner.py -l urls.txt

  # 输出 JSON 给 AI 分析
  python sensitive_scanner.py -u https://target.com/app.js --format json

  # 按严重级别过滤
  python sensitive_scanner.py -f bundle.js --min-severity high

  # 按类别过滤
  python sensitive_scanner.py -f bundle.js --category 凭据泄露 信息泄露

  # 管道输入
  cat bundle.js | python sensitive_scanner.py --stdin --source-name bundle.js
"""
import argparse
import json
import re
import os
import sys
import base64
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

# Windows GBK 编码问题修复
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data")
RULES_FILE = os.path.join(DATA_DIR, "sensitive_rules.json")

SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def load_rules(path=None):
    if path is None:
        path = RULES_FILE
    if not os.path.exists(path):
        print(f"[!] 规则文件不存在: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    for r in rules:
        try:
            r["_compiled"] = re.compile(r["regex"], re.IGNORECASE | re.DOTALL)
        except re.error as e:
            print(f"[!] 正则编译失败 [{r['id']}]: {e}", file=sys.stderr)
            r["_compiled"] = None
    return rules


def fetch_url(url, extra_headers=None):
    """通过 requests 获取 URL 内容，没有则用 urllib。"""
    try:
        import requests
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if extra_headers:
            for h in extra_headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
        resp = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
        return {
            "url": resp.url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "header_text": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
        }
    except ImportError:
        pass

    try:
        from urllib.request import urlopen, Request
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urlopen(req, timeout=15)
        body = resp.read().decode("utf-8", errors="replace")
        headers = dict(resp.headers)
        return {
            "url": resp.geturl(),
            "status": resp.status,
            "headers": headers,
            "body": body,
            "header_text": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        }
    except Exception as e:
        print(f"[!] URL 请求失败: {url} — {e}", file=sys.stderr)
        return None


def scan_text(rules, text, source_name="", scan_scope=None):
    """对一段文本执行所有规则扫描。返回命中列表。

    每条命中:
      { "rule_id", "category", "name_zh", "severity", "match", "context",
        "risk_summary", "fp_hint", "source" }
    """
    hits = []
    if not text:
        return hits
    for rule in rules:
        regex = rule.get("_compiled")
        if regex is None:
            continue
        if scan_scope and not any(s in rule.get("scan_scope", []) for s in scan_scope):
            continue
        for m in regex.finditer(text):
            match_text = m.group(0)
            if not match_text or len(match_text.strip()) < 2:
                continue
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            ctx = text[start:end].replace("\n", " ").replace("\r", " ").strip()
            hits.append({
                "rule_id": rule["id"],
                "category": rule["category"],
                "name_zh": rule["name_zh"],
                "description": rule.get("description", ""),
                "severity": rule["severity"],
                "risk_summary": rule.get("risk_analysis", ""),
                "fp_hint": rule.get("fp_note", ""),
                "match": match_text[:200],
                "match_len": len(match_text),
                "context": ctx,
                "source": source_name,
            })
    return hits


def dedup_hits(hits):
    """按 (source + rule_id + md5(match)) 去重。"""
    seen = set()
    unique = []
    for h in hits:
        import hashlib
        key = (h["source"], h["rule_id"], hashlib.md5(h["match"].encode()).hexdigest()[:8])
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique


def format_table(hits):
    """人类可读的表格输出。"""
    if not hits:
        print("[OK] 未发现敏感信息。")
        return

    lines = []
    lines.append(f"\n{'='*80}")
    lines.append(f"  敏感信息扫描结果 — {len(hits)} 条命中 (去重)")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"{'='*80}")

    # 按严重度排序
    sorted_hits = sorted(hits, key=lambda h: -SEVERITY_WEIGHT.get(h["severity"], 0))

    # 统计
    by_sev = defaultdict(list)
    for h in sorted_hits:
        by_sev[h["severity"]].append(h)

    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev not in by_sev:
            continue
        lines.append(f"\n--- {severity_label(sev)} ---")
        for h in by_sev[sev]:
            lines.append(f"\n  [{h['rule_id']}] {h['name_zh']}")
            lines.append(f"  来源 : {h['source']}")
            lines.append(f"  匹配 : {h['match'][:120]}")
            if h.get("context") and h["context"] != h["match"]:
                # 高亮匹配部分
                ctx_highlighted = h["context"].replace(h["match"][:100], f"»»{h['match'][:100]}««")
                lines.append(f"  上下文: ...{ctx_highlighted[:200]}...")
            lines.append(f"  风险 : {h['risk_summary'][:150]}")
            lines.append(f"  误报 : {h['fp_hint'][:120]}")

    lines.append(f"\n{'─'*80}")
    lines.append("  统计:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            lines.append(f"    {severity_label(sev)}: {len(by_sev[sev])} 条")
    lines.append(f"{'─'*80}")
    return "\n".join(lines)


def format_json(hits):
    """JSON 格式输出 — 专为 AI 分析设计。"""
    result = {
        "scan_time": datetime.now().isoformat(),
        "total_hits": len(hits),
        "hits": [],
    }
    for h in sorted(hits, key=lambda x: -SEVERITY_WEIGHT.get(x["severity"], 0)):
        result["hits"].append({
            "rule_id": h["rule_id"],
            "rule_name": h["name_zh"],
            "category": h["category"],
            "severity": h["severity"],
            "source": h["source"],
            "match": h["match"],
            "context": h["context"],
            "ai_hints": {
                "what_it_means": h["description"],
                "attacker_perspective": h["risk_summary"],
                "false_positive_check": h["fp_hint"],
            },
        })
    return json.dumps(result, ensure_ascii=False, indent=2)


def format_text(hits):
    """简要的逐行输出，适合管道处理。"""
    if not hits:
        return "[OK] 未发现敏感信息。"
    lines = []
    for h in sorted(hits, key=lambda x: -SEVERITY_WEIGHT.get(x["severity"], 0)):
        lines.append(f"[{h['severity'].upper()}][{h['rule_id']}] {h['name_zh']} "
                     f"| {h['source']} | {h['match'][:80].replace(chr(10), ' ')}")
    return "\n".join(lines)


def severity_label(sev):
    labels = {
        "critical": "【致命】",
        "high":     "【高危】",
        "medium":   "【中危】",
        "low":      "【低危】",
        "info":     "【提示】",
    }
    return labels.get(sev, sev)


def resolve_js_sources(html_url, body):
    """从 HTML 页面提取 <script src=...> 列表。"""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
    base = html_url
    resolved = []
    for s in srcs:
        if s.startswith("http"):
            resolved.append(s)
        elif s.startswith("//"):
            parsed = urlparse(base)
            resolved.append(f"{parsed.scheme}:{s}")
        elif s.startswith("/"):
            parsed = urlparse(base)
            resolved.append(f"{parsed.scheme}://{parsed.netloc}{s}")
        else:
            resolved.append(base.rsplit("/", 1)[0] + "/" + s)
    return resolved


def main():
    parser = argparse.ArgumentParser(
        description="敏感信息统一扫描器 — 加载 48 条规则扫描文本/URL, 输出专为 AI 研判设计的结果"
    )
    parser.add_argument("-u", "--url", help="扫描单个 JS 文件 URL")
    parser.add_argument("-r", "--response-url", help="扫描 URL 的完整响应(header+body)")
    parser.add_argument("-f", "--file", help="扫描本地文件")
    parser.add_argument("-l", "--list", help="批量扫描 URL 列表文件")
    parser.add_argument("--stdin", action="store_true", help="从标准输入读取")
    parser.add_argument("--source-name", default="stdin", help="配合 --stdin 标识来源")
    parser.add_argument("--header", action="append", help="自定义请求头 (--header 'Key: Value')")
    parser.add_argument("--format", choices=["table", "json", "text"], default="table",
                       help="输出格式 (table=人类可读, json=AI分析, text=管道)")
    parser.add_argument("--min-severity", choices=["critical","high","medium","low","info"],
                       default="info", help="最低严重度过滤")
    parser.add_argument("--category", nargs="+", help="只扫描指定类别 (如: 凭据泄露 信息泄露)")
    parser.add_argument("--follow-js", action="store_true",
                       help="从 HTML 页面提取所有 <script src> 并逐个扫描")
    parser.add_argument("--rules", help="自定义规则文件路径 (默认: sensitive_rules.json)")
    parser.add_argument("--output", "-o", help="输出到文件")
    parser.add_argument("--quiet", "-q", action="store_true", help="只输出结果, 不输出进度")

    args = parser.parse_args()

    rules = load_rules(args.rules)
    min_weight = SEVERITY_WEIGHT[args.min_severity]

    # 过滤规则
    scan_rules = rules
    if args.category:
        scan_rules = [r for r in rules if r["category"] in args.category]
        if not args.quiet:
            cats = set(r["category"] for r in scan_rules)
            print(f"[*] 已过滤类别: {', '.join(cats)} ({len(scan_rules)} 条规则)", file=sys.stderr)

    all_hits = []
    targets = []

    # 收集扫描目标
    if args.url:
        targets.append(("js_url", args.url))
    if args.response_url:
        targets.append(("response", args.response_url))
    if args.file:
        targets.append(("file", args.file))
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#"):
                    targets.append(("js_url", u))
    if args.stdin:
        content = sys.stdin.read()
        hits = scan_text(scan_rules, content, args.source_name, scan_scope=["request","response","header","body"])
        all_hits.extend(hits)
        if not args.quiet:
            print(f"[*] stdin 扫描完成, {len(hits)} 条命中", file=sys.stderr)

    # 逐个扫描
    for target_type, target in targets:
        if target_type in ("js_url", "response"):
            resp = fetch_url(target, args.header)
            if not resp:
                continue
            url = resp["url"]
            if not args.quiet:
                print(f"[*] 扫描: {url} (status={resp['status']}, body={len(resp['body'])} bytes)", file=sys.stderr)

            if target_type == "response":
                # 完整响应: header + body
                text = resp["header_text"] + "\n\n" + resp["body"]
                hits = scan_text(scan_rules, text, url, scan_scope=["request","response","header","body"])
            else:
                # JS 文件: body 为主, headers 为辅
                hits = scan_text(scan_rules, resp["body"], url, scan_scope=["request","body"])
                # 检查响应头中的敏感信息
                header_hits = scan_text(scan_rules, resp["header_text"], url + " [headers]", scan_scope=["header"])
                hits.extend(header_hits)

            all_hits.extend(hits)

            # 跟随 JS 引用
            if args.follow_js and "text/html" in resp["headers"].get("content-type", ""):
                js_urls = resolve_js_sources(url, resp["body"])
                if not args.quiet:
                    print(f"[*] 发现 {len(js_urls)} 个 JS 引用", file=sys.stderr)
                for js_url in js_urls[:50]:  # 限制最多 50 个
                    js_resp = fetch_url(js_url, args.header)
                    if js_resp:
                        jh = scan_text(scan_rules, js_resp["body"], js_url, scan_scope=["request","body"])
                        all_hits.extend(jh)

        elif target_type == "file":
            if not os.path.exists(target):
                print(f"[!] 文件不存在: {target}", file=sys.stderr)
                continue
            with open(target, encoding="utf-8", errors="replace") as f:
                content = f.read()
            hits = scan_text(scan_rules, content, target, scan_scope=["request","response","header","body"])
            all_hits.extend(hits)
            if not args.quiet:
                print(f"[*] 扫描: {target} ({len(content)} bytes) -> {len(hits)} 条命中", file=sys.stderr)

    # 去重
    all_hits = dedup_hits(all_hits)

    # 按严重度过滤
    all_hits = [h for h in all_hits if SEVERITY_WEIGHT.get(h["severity"], 0) >= min_weight]

    # 输出
    if args.format == "json":
        output = format_json(all_hits)
    elif args.format == "text":
        output = format_text(all_hits)
    else:
        output = format_table(all_hits)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(str(output) + "\n")
        if not args.quiet:
            print(f"[*] 结果已写入: {args.output}", file=sys.stderr)
    else:
        print(output)

    # 返回给 shell
    return 1 if any(h["severity"] in ("critical", "high") for h in all_hits) else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
