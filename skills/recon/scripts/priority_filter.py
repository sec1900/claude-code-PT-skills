#!/usr/bin/env python3
"""
智能筛选 — 从 httpx 批量探活结果中分级 P1-P4。SRC/红队共享

用法:
  python3 priority_filter.py /tmp/httpx_alive.jsonl
  python3 priority_filter.py /tmp/httpx_alive.jsonl -o /tmp/priority.json

输入: httpx -json 输出的 JSONL 文件
输出: priority.json，按 P1/P2/P3/P4 分组的 URL 列表 + 分级依据
"""

import sys, os, json


def parse_httpx_line(line):
    try:
        return json.loads(line.strip())
    except:
        return None


def extract_host(url):
    """从 URL 提取 hostname 部分"""
    if not url:
        return ""
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split(":")[0]


def extract_port(url):
    """从 URL 提取端口"""
    if not url:
        return "443"
    url = url.replace("https://", "").replace("http://", "")
    parts = url.split("/")[0].split(":")
    return parts[1] if len(parts) > 1 else ("443" if "https://" in url else "80")


def is_standard_port(port, scheme):
    if scheme == "https" and port == "443":
        return True
    if scheme == "http" and port == "80":
        return True
    return False


def has_cdn(entry):
    """检测是否经过 CDN"""
    cdn_keywords = [
        "cloudflare", "akamai", "fastly", "cdn", "cdn77", "keycdn",
        "stackpath", "cdnjs", "jsdelivr", "azureedge", "aws cloudfront",
        "incapsula", "imperva", "sucuri", "chinacache", "wangsu",
        "dnion", "qiniu", "aliyuncs", "tencent cdn", "baidu cdn",
        "kxcdn", "ccgslb",
    ]

    cdn_field = (entry.get("cdn_name") or "").lower()
    if cdn_field:
        for kw in cdn_keywords:
            if kw in cdn_field:
                return True

    # 检查响应头中的 CDN 特征
    for key in list(entry.keys()):
        val = str(entry[key]).lower()
        if "cdn" in val or "cloudflare" in val:
            return True

    return False


def is_old_framework(entry):
    """检测旧框架"""
    tech = entry.get("tech", [])
    if isinstance(tech, str):
        tech = [tech]
    tech_str = " ".join(tech).lower()

    old_patterns = [
        "thinkphp 5", "thinkphp 3", "struts2", "struts 1",
        "spring boot 1", "spring mvc 3", "tomcat 6", "tomcat 7",
        "jquery 1.", "jquery 2.", "php 5.", "asp.net 2",
        "iis 6", "iis 7", "apache 2.2", "nginx 0.",
        "drupal 7", "joomla 2", "wordpress 3",
    ]
    return any(p in tech_str for p in old_patterns)


def is_login_page(entry):
    """检测是否纯登录页"""
    title = (entry.get("title") or "").lower()
    login_keywords = [
        "login", "sign in", "log in", "登录", "登入",
        "auth", "authentication", "认证",
        "admin panel", "管理后台", "后台管理",
    ]
    return any(kw in title for kw in login_keywords)


def is_api_gateway(entry):
    """检测 API gateway"""
    title = (entry.get("title") or "").lower()
    url = (entry.get("url") or entry.get("input") or "").lower()
    host = extract_host(url)

    api_signals = [
        "swagger", "api-doc", "api doc", "openapi",
        "graphql", "graphiql", "playground",
        "kibana", "konga", "apisix",
    ]
    if any(s in title for s in api_signals) or any(s in url for s in api_signals):
        return True

    api_host_prefixes = ["api.", "api-", "open.", "openapi.", "gateway."]
    return any(host.startswith(p) for p in api_host_prefixes)


def is_third_party_saas(entry):
    """检测第三方 SaaS / 停泊页"""
    title = (entry.get("title") or "").lower()
    url = (entry.get("url") or entry.get("input") or "").lower()
    host = extract_host(url)
    cname = (entry.get("cname") or "").lower()
    tech = entry.get("tech", [])
    if isinstance(tech, str):
        tech = [tech]
    tech_str = " ".join(tech).lower()

    saas_domains = [
        "my.salesforce.com", "zendesk.com", "atlassian.net",
        "sharepoint.com", "azurewebsites.net", "firebaseapp.com",
        "amplifyapp.com", "netlify.app", "vercel.app",
        "herokuapp.com", "onrender.com", "fly.dev",
        "readthedocs.io", "gitbook.io", "notion.site",
    ]
    if any(d in host for d in saas_domains) or any(d in cname for d in saas_domains):
        return True

    parking_keywords = [
        "domain has expired", "parked", "parking", "domain name",
        "this domain", "buy this domain", "is for sale",
        "under construction", "coming soon", "site not found",
        "website is under construction", "403 forbidden",
        "域名已过期", "域名出售", "网站建设中",
    ]
    return any(kw in title for kw in parking_keywords)


def is_admin_portal(entry):
    """检测管理后台"""
    url = (entry.get("url") or entry.get("input") or "").lower()
    host = extract_host(url)
    title = (entry.get("title") or "").lower()

    admin_hosts = ["admin.", "manage.", "dashboard.", "console.", "control.", "portal."]
    has_admin_host = any(host.startswith(p) for p in admin_hosts)

    admin_titles = ["admin", "dashboard", "console", "management", "control panel",
                    "管理", "后台", "控制台", "运维"]
    has_admin_title = any(kw in title for kw in admin_titles)

    return has_admin_host or has_admin_title


def classify(entry):
    """对单个条目分级，返回 (priority, reason)"""
    url = entry.get("url") or entry.get("input") or ""
    host = extract_host(url)
    scheme = url.split("://")[0] if "://" in url else "https"
    port = extract_port(url)
    status = entry.get("status_code", 0)
    title = entry.get("title") or ""

    reasons = []

    # --- P4 跳过 ---
    if is_third_party_saas(entry):
        return "P4", "third-party SaaS / parking page"

    if status in (404, 0):
        return "P4", "dead (status %s)" % status

    # --- P1 高价值 ---
    p1_score = 0
    p1_reasons = []

    # dev/test/staging/uat host
    dev_patterns = ["test.", "dev.", "staging.", "uat.", "qa.", "demo.", "beta.", "pre.", "sandbox.", "debug."]
    if any(host.startswith(p) for p in dev_patterns):
        p1_score += 2
        p1_reasons.append("dev/test env")

    if is_admin_portal(entry):
        p1_score += 1
        p1_reasons.append("admin portal")

    if is_api_gateway(entry):
        p1_score += 1
        p1_reasons.append("API gateway")

    if is_old_framework(entry):
        p1_score += 1
        p1_reasons.append("old framework")

    if status == 403 and not has_cdn(entry):
        p1_score += 1
        p1_reasons.append("non-CDN 403 (hidden resource)")

    if status in (500, 503) and not has_cdn(entry):
        p1_score += 0.5
        p1_reasons.append("internal error (leak potential)")

    if p1_score >= 2:
        return "P1", " | ".join(p1_reasons)

    # --- P2 关注 ---
    p2_score = 0
    p2_reasons = []

    if not has_cdn(entry):
        p2_score += 1
        p2_reasons.append("non-CDN")
    if not is_standard_port(port, scheme):
        p2_score += 1
        p2_reasons.append("non-standard port %s" % port)
    if is_login_page(entry):
        p2_score += 1
        p2_reasons.append("login page")

    if p2_score >= 2:
        return "P2", " | ".join(p2_reasons)

    # P1 with only one signal (not enough for P1 alone)
    if p1_score >= 1:
        return "P2", "single high-value signal: %s" % " | ".join(p1_reasons)

    # --- P3 普通 ---
    return "P3", "standard"


def main():
    if len(sys.argv) < 2:
        print("用法: python3 priority_filter.py <httpx.jsonl> [-o <output.json>]")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = None
    if "-o" in sys.argv:
        outfile = sys.argv[sys.argv.index("-o") + 1]

    entries = []
    with open(infile, "r", encoding="utf-8") as f:
        for line in f:
            e = parse_httpx_line(line)
            if e:
                entries.append(e)

    if not entries:
        print("ERROR: 没有有效的 httpx JSON 条目")
        sys.exit(1)

    results = {"P1": [], "P2": [], "P3": [], "P4": []}

    for e in entries:
        url = e.get("url") or e.get("input") or ""
        level, reason = classify(e)
        results[level].append({
            "url": url,
            "host": extract_host(url),
            "status": e.get("status_code", 0),
            "title": e.get("title", ""),
            "tech": e.get("tech", []),
            "reason": reason,
        })

    # 输出
    print("=" * 100)
    print("Priority Filter — %d URLs → P1=%d P2=%d P3=%d P4=%d" % (
        len(entries), len(results["P1"]), len(results["P2"]),
        len(results["P3"]), len(results["P4"])))
    print("=" * 100)

    for level in ["P1", "P2", "P3", "P4"]:
        items = results[level]
        if not items:
            continue
        print("\n--- %s (%d URLs) ---" % (level, len(items)))
        for item in items:
            print("  [%s] %s | %s" % (item["status"], item["url"], item["reason"]))

    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print("\nOutput: %s" % outfile)

    # 写入 stats 供后续引用
    print("\n" + "=" * 100)
    print("作业建议:")
    print("  P1 (%d): 优先做信息泄露探测 + 指纹匹配 + CORS 检测" % len(results["P1"]))
    print("  P2 (%d): 做目录爆破(top30) + API 端点探测" % len(results["P2"]))
    print("  P3 (%d): 仅跑 nuclei 信息收集模板" % len(results["P3"]))
    print("  P4 (%d): 跳过" % len(results["P4"]))


if __name__ == "__main__":
    main()
