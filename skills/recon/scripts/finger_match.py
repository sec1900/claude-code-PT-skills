#!/usr/bin/env python3
"""
指纹匹配脚本 — 基于 fingerprints_merged_v5.json (33,107条, 5源合并) 进行 CMS/产品识别

用法:
  单目标:  python3 finger_match.py http://example.com
  批量:    python3 finger_match.py -l /tmp/urls.txt
  指定库:  python3 finger_match.py -f /path/to/custom.json http://example.com
  最小级别: python3 finger_match.py --min-level L1 http://example.com
  按类别:  python3 finger_match.py --category OA,Security http://example.com

输出: [FINGER] URL | 产品名 | 匹配方法 | 级别 | 分类
匹配后自动检查 POC 库是否有对应厂商目录。
"""
import os, sys, json, hashlib, struct, argparse, urllib.request, ssl

for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
    os.environ.pop(k, None)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10
POC_DIR = os.environ.get("POC_DIR", "")  # 需显式设置，如 /mnt/share/poc

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
DEFAULT_FP = os.path.join(DATA_DIR, "fingerprints_merged_v5.json")


def mmh3_hash32(data):
    """murmurhash3 32-bit, same as shodan/fofa favicon hash"""
    import base64
    b64 = base64.encodebytes(data).decode()
    try:
        import mmh3
        return str(mmh3.hash(b64))
    except ImportError:
        pass
    h = 0
    encoded = b64.encode("utf-8")
    length = len(encoded)
    nblocks = length // 4
    c1, c2 = 0xcc9e2d51, 0x1b873593
    for i in range(nblocks):
        k = struct.unpack_from("<I", encoded, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail_idx = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= encoded[tail_idx + 2] << 16
    if tail_size >= 2:
        k1 ^= encoded[tail_idx + 1] << 8
    if tail_size >= 1:
        k1 ^= encoded[tail_idx]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    if h >= 0x80000000:
        h -= 0x100000000
    return str(h)


def fetch(url, max_size=200000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(max_size).decode("utf-8", errors="replace")
        return headers, body
    except Exception:
        return {}, ""


def fetch_favicon_hash(base_url):
    for path in ["/favicon.ico", "/static/favicon.ico"]:
        try:
            req = urllib.request.Request(base_url.rstrip("/") + path, headers={"User-Agent": UA})
            resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX)
            data = resp.read(500000)
            if len(data) > 0:
                return mmh3_hash32(data)
        except Exception:
            continue
    return None


def extract_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""


def match_fingerprints(url, fingerprints):
    """Match fingerprints against a URL. Supports body/header/title/faviconhash/url methods."""
    import re
    headers, body = fetch(url)
    if not body and not headers:
        return []

    title = extract_title(body)
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    fav_hash = None
    url_path = urllib.parse.urlparse(url).path

    matches = []
    seen = set()

    for fp in fingerprints:
        name = fp.get("name", "")
        method = fp.get("method", "body")
        keywords = fp.get("keyword", [])
        level = fp.get("level", "L2")
        category = fp.get("category", "")

        if not keywords or not name:
            continue

        if method == "body":
            target = body + title  # title is part of body, but also match separately
            if all(kw in target for kw in keywords):
                key = f"{name}|{method}"
                if key not in seen:
                    matches.append((name, method, level, category))
                    seen.add(key)

        elif method == "header":
            if all(kw in header_str for kw in keywords):
                key = f"{name}|{method}"
                if key not in seen:
                    matches.append((name, method, level, category))
                    seen.add(key)

        elif method == "faviconhash":
            if fav_hash is None:
                fav_hash = fetch_favicon_hash(url)
            if fav_hash and any(kw == fav_hash for kw in keywords):
                key = f"{name}|{method}"
                if key not in seen:
                    matches.append((name, method, level, category))
                    seen.add(key)

        elif method == "url":
            if any(kw in url_path for kw in keywords):
                key = f"{name}|{method}"
                if key not in seen:
                    matches.append((name, method, level, category))
                    seen.add(key)

    return matches


def check_poc_dir(cms_name):
    if not os.path.isdir(POC_DIR):
        return None
    cms_lower = cms_name.lower()
    for d in os.listdir(POC_DIR):
        if d.lower() in cms_lower or cms_lower in d.lower():
            poc_path = os.path.join(POC_DIR, d)
            count = len([f for f in os.listdir(poc_path) if f.endswith(".yaml")])
            return (d, count)
    return None


def main():
    parser = argparse.ArgumentParser(description="Fingerprint matching with 33K merged rules")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-l", "--list", help="File with URLs, one per line")
    parser.add_argument("-f", "--fingerdb", help="Path to fingerprint JSON", default=DEFAULT_FP)
    parser.add_argument("--min-level", choices=["L1", "L2"], help="Minimum fingerprint level (L1=stronger)")
    parser.add_argument("--category", help="Filter by category (comma separated, e.g. OA,Security)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    fp_path = args.fingerdb
    if not os.path.exists(fp_path):
        print(f"[ERROR] Fingerprint DB not found: {fp_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading fingerprints from {fp_path}", file=sys.stderr)
    with open(fp_path, encoding="utf-8") as f:
        data = json.load(f)
    fingerprints = data.get("fingerprint", data if isinstance(data, list) else [])

    # Apply filters
    if args.min_level:
        fingerprints = [fp for fp in fingerprints if fp.get("level", "L2") == args.min_level]
    if args.category:
        cats = set(c.strip() for c in args.category.split(","))
        fingerprints = [fp for fp in fingerprints if fp.get("category", "") in cats]

    print(f"[*] Loaded {len(fingerprints)} rules (filtered from {data.get('total_rules', '?')} total)", file=sys.stderr)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        with open(args.list) as f:
            urls.extend(line.strip() for line in f if line.strip())

    all_matches = {}
    for url in urls:
        print(f"[*] Scanning {url}", file=sys.stderr)
        matches = match_fingerprints(url, fingerprints)
        if matches:
            all_matches[url] = matches
            for name, method, level, category in matches:
                poc = check_poc_dir(name)
                poc_info = f" → POC: {poc[0]} ({poc[1]} yamls)" if poc else ""
                line = f"[FINGER] {url} | {name} | {method}:{level} | {category}{poc_info}"
                print(line)
        else:
            print(f"[FINGER] {url} | 未识别匹配", file=sys.stderr)

    # Summary
    if all_matches:
        total_hits = sum(len(v) for v in all_matches.values())
        unique_cms = set()
        for matches in all_matches.values():
            for name, _, _, _ in matches:
                unique_cms.add(name)
        print(f"\n--- {total_hits} 次命中, {len(unique_cms)} 个产品, 覆盖 {len(all_matches)} 个URL ---", file=sys.stderr)

        cms_with_poc = set()
        for matches in all_matches.values():
            for name, _, _, _ in matches:
                poc = check_poc_dir(name)
                if poc:
                    cms_with_poc.add(name)
        if cms_with_poc:
            print(f"[!] POC 库覆盖: {', '.join(sorted(cms_with_poc))}", file=sys.stderr)


if __name__ == "__main__":
    main()
