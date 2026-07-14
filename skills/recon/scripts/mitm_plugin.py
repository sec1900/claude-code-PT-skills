"""
mitmproxy 被动扫描插件 — 集成 yakit 规则 + 指纹匹配

启动方式:
  mitmdump -p 8888 -s mitm_plugin.py --set flow_detail=0

功能:
  1. 每个 HTTP 响应经过时，自动用 yakit 规则（60条正则）扫描
  2. 对响应做指纹匹配（fingerprints_merged_v5.json 33000+ 产品）
  3. 命中规则时写入 mitm_tags.jsonl
  4. 所有流量记录到 mitm_flows.jsonl（精简版，非完整 HAR）

输出文件（写入当前工作目录）:
  mitm_tags.jsonl   — 每行一条标记（被动发现）
  mitm_fingers.jsonl — 每行一条指纹匹配
  mitm_flows.jsonl  — 每行一条请求/响应摘要
"""
import os, re, json, hashlib, time
from datetime import datetime, timezone
from mitmproxy import http

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data")

TAG_LOG = os.environ.get("MITM_TAG_LOG", "mitm_tags.jsonl")
FINGER_LOG = os.environ.get("MITM_FINGER_LOG", "mitm_fingers.jsonl")
FLOW_LOG = os.environ.get("MITM_FLOW_LOG", "mitm_flows.jsonl")

# tag → 下一步行动建议
TAG_ACTIONS = {
    "疑似JSONP": "测试 JSONP 劫持",
    "登陆/密码传输": "检查明文传输，测试弱口令",
    "敏感信息": "提取密钥/token，尝试利用",
    "登陆点": "测试弱口令、SQL注入",
    "登陆（验证码）": "测试验证码绕过",
    "文件上传点": "测试上传绕过",
    "文件包含参数": "测试 LFI/RFI",
    "命令注入参数": "测试命令注入",
    "email泄漏": "信息泄露记录",
    "手机号泄漏": "信息泄露记录",
    "身份证": "严重信息泄露",
    "RSA私钥": "尝试利用私钥",
    "OSS Key": "尝试接管 OSS bucket",
    "MySQL配置": "提取数据库凭据",
    "Shiro": "测试 Shiro 反序列化",
    "SwaggerUI": "读取 API 文档，测试未授权",
    "JWT 测试点": "测试 JWT 伪造",
    "SQL注入测试点": "测试 SQL 注入",
    "SSRF测试参数": "测试 SSRF",
    "XXE测试点": "测试 XXE",
    "XPath注入测试点": "测试 XPath 注入",
    "Struts2测试点": "测试 Struts2 RCE",
    "Java反序列化测试点": "测试 Java 反序列化",
    "Url重定向参数": "测试开放重定向",
    "Source Map": "下载 source map 还原源码",
    "HTTP XSS测试点": "测试反射 XSS",
    "XML请求": "测试 XXE",
    "后台登陆": "测试弱口令/默认口令",
    "云主机密钥": "尝试接管云主机",
    "URL作为参数": "测试 SSRF",
}


def load_yakit_rules(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    rules = []
    for r in raw:
        regex_str = r.get("Rule", "")
        if not regex_str:
            continue
        tags = r.get("ExtraTag", [])
        name = r.get("VerboseName", "") or (tags[0] if tags else "")
        if not name:
            continue
        try:
            compiled = re.compile(regex_str, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue
        rules.append({
            "name": name,
            "regex": compiled,
            "for_request": r.get("EnableForRequest", False),
            "for_response": r.get("EnableForResponse", False),
            "for_header": r.get("EnableForHeader", False),
            "for_body": r.get("EnableForBody", False),
        })
    return rules


def load_fingerprints(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    fps = data.get("fingerprint", [])
    # Normalize merged format (name/method) to legacy format (cms/location)
    normalized = []
    for fp in fps:
        normalized.append({
            "cms": fp.get("cms", fp.get("name", "")),
            "method": fp.get("method", "keyword"),
            "location": fp.get("location", fp.get("method", "body")),
            "keyword": fp.get("keyword", []),
        })
    return normalized


def extract_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""


class PassiveScanner:
    def __init__(self):
        yakit_path = os.path.join(DATA_DIR, "yakit_rules.json")
        finger_path = os.path.join(DATA_DIR, "fingerprints_merged_v5.json")

        self.rules = load_yakit_rules(yakit_path)
        self.fingerprints = load_fingerprints(finger_path)
        self.seen_tags = set()
        self.seen_fingers = set()

        self.tag_file = open(TAG_LOG, "a", encoding="utf-8")
        self.finger_file = open(FINGER_LOG, "a", encoding="utf-8")
        self.flow_file = open(FLOW_LOG, "a", encoding="utf-8")

        print(f"[mitm_plugin] Loaded {len(self.rules)} yakit rules, {len(self.fingerprints)} fingerprints")
        print(f"[mitm_plugin] Logs: {TAG_LOG}, {FINGER_LOG}, {FLOW_LOG}")

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        now = datetime.now(timezone.utc).isoformat()

        # 提取文本
        req_headers = str(flow.request.headers)
        req_body = flow.request.get_text() or ""
        resp_headers = str(flow.response.headers)
        resp_body = flow.response.get_text() or ""
        resp_title = extract_title(resp_body)

        # --- 记录流量摘要 ---
        flow_entry = {
            "time": now,
            "method": flow.request.method,
            "url": url,
            "status": flow.response.status_code,
            "content_type": flow.response.headers.get("content-type", ""),
            "content_length": len(resp_body),
            "title": resp_title[:100],
        }
        self.flow_file.write(json.dumps(flow_entry, ensure_ascii=False) + "\n")
        self.flow_file.flush()

        # --- yakit 规则扫描 ---
        for rule in self.rules:
            name = rule["name"]
            regex = rule["regex"]

            targets = []
            if rule["for_request"]:
                targets.append(("request", req_headers + "\n" + req_body))
            if rule["for_response"]:
                targets.append(("response", resp_headers + "\n" + resp_body))
            if rule["for_header"]:
                targets.append(("header", resp_headers))
            if rule["for_body"]:
                targets.append(("body", resp_body))

            for location, text in targets:
                if not text:
                    continue
                m = regex.search(text)
                if m:
                    key = f"{url}:{name}"
                    if key not in self.seen_tags:
                        self.seen_tags.add(key)
                        snippet = m.group(0)[:80].replace("\n", " ").strip()
                        action = TAG_ACTIONS.get(name, "")
                        entry = {
                            "time": now,
                            "url": url,
                            "tag": name,
                            "location": location,
                            "match": snippet,
                            "action": action,
                        }
                        self.tag_file.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        self.tag_file.flush()
                        print(f"  [TAG] {name} | {url} | {snippet[:40]}")
                    break

        # --- 指纹匹配 ---
        for fp in self.fingerprints:
            cms = fp.get("cms", "")
            keywords = fp.get("keyword", [])
            location = fp.get("location", "body")
            method = fp.get("method", "keyword")

            if not cms or not keywords or method != "keyword":
                continue

            if location == "body":
                target_str = resp_body
            elif location == "header":
                target_str = resp_headers
            elif location == "title":
                target_str = resp_title
            else:
                continue

            if all(kw in target_str for kw in keywords):
                key = f"{url}:{cms}"
                if key not in self.seen_fingers:
                    self.seen_fingers.add(key)
                    entry = {
                        "time": now,
                        "url": url,
                        "cms": cms,
                        "method": method,
                        "location": location,
                    }
                    self.finger_file.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    self.finger_file.flush()
                    print(f"  [FINGER] {cms} | {url}")


addons = [PassiveScanner()]
