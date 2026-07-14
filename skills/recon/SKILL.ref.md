---
description: 对目标进行信息收集。支持 SRC（宽度优先，大规模资产发现+批量漏扫）和 RedTeam（深度优先，全端口+多端口差异分析）双模式。自动识别目标类型和规模，执行子域名枚举、httpx批量探测、智能筛选、nuclei批量扫描（SRC）或全端口扫描+多端口差异对比（RedTeam）。覆盖 APP/小程序资产发现(ICP备案→应用宝包名→APK域名提取)。可作为独立 skill 调用，也可被其他 skill 引用。
---

# 信息收集 — SRC + RedTeam 双模式

## ⚠ 硬规则（无论何时必须遵守）

```
1. 不污染目标 — 禁止注册账号、提交表单、写入数据。用户枚举用只读差异检测（无效email/password触发"已存在"提示）。
2. 被动先行 — R1(SSL/DNS/JS/响应头) → R2(JS深入/泄露/登录机制) → R3(指纹/nuclei/ffuf) → R4(端口扫描)。不跳级。
3. 端口扫描低速率 — --min-rate 500 -T3，不是 5000。全端口扫描是可选的最后一步，不是第一步。
4. VPN内网绕过代理 — tun0 存在时，10.0.0.0/8 等私有 IP 必须 --noproxy，ffuf 需设 no_proxy 环境变量。
5. CTF/靶场跟引导走 — 题目给了命令/字典就用那个，不要自己发明。离线题(base64/MD5)直接本地解。
6. 敏感路径探测必须校验 body — SPA 站点会把所有未知路径 fallback 到 index.html 返回 200。仅凭 HTTP 状态码 200 不能判定文件存在。必须校验: (1) body hash 与首页不同 (2) Content-Length > 0 且含该文件类型的特征内容（如 .git/HEAD 应含 "ref: refs/"，.env 应含 "="）。两项都不满足视为假阳性。
7. 字典/词表路径优先级 — Kali 在线用 `/usr/share/seclists/`；Kali 不在线用共享文件夹 `/mnt/share/SecLists/`（Kali）或 `\\<NAS_IP>\share\SecLists\`（Windows）。Payload 大全用 `/mnt/share/PayloadsAllTheThings/`（Kali）或 `\\<NAS_IP>\share\PayloadsAllTheThings\`（Windows）。
8. 操作前查 timeline — 耗时操作（nmap/nuclei/ffuf/爆破/大量curl）执行前先 grep timeline.jsonl，已 done 的跳过直接读已有结果。宁可多 grep 一次也不重做一次 nmap。
9. 工具容错 — 工具失败不卡住，自动降级: nmap SYN被拦 → `nmap -sT -Pn`；nuclei 超时 → 分端口逐个扫 `-timeout 15`；ffuf 被 ban → 切副端口降低 `-t`；sqlmap 连接重置 → `--delay 2`；SSH 断开 → 长任务用 `nohup &`，重连后读结果文件。
10. 先 1 后 N — 任何批量操作（n 并发子域名枚举、n 并发 nuclei、n 并发 ffuf、n 个目标的批量扫描），必须先跑 1 个样例验证通过（工具正常、输出正确、路径正确），确认无误后再并行启动其余 n-1 个。禁止 0 验证直接全量铺开。日志教训：6 并发 OneForAll 全失败（Python 3.14 fire 库不兼容），先跑 1 个就不会浪费 6 倍时间。
11. 失败先诊断，不盲重试 — 工具命令报错时，禁止立即用同样参数重试。先花 10 秒诊断：读 --help 确认参数名、file $(which xxx) 确认是不是正确的二进制、检查版本号。日志教训：httpx -l 报错了 5 次才去看 --help；Kali 上 /usr/bin/httpx 是 Python HTTP 库不是 Go 版，被"发现"了 3 次。
12. 同一方向 3 次未果 → 强制切换 — 对同一个端点/漏洞点的同类尝试超过 3 次都不成功，立即标记搁置，切换到资产列表中的下一个目标。禁止沉迷单一方向。日志教训：JS 反爬破解写了 1300 行日志后发现切香港代理根本不需要绕过；WMS 登录页反复测格式但 SRC 不该盯着登录打。
```

## 模式流程速查

```
SRC 模式:  步骤 1→2→3→4→4.5 → 快速得分通道 → 5→6→7 → 跳到「侦察结果汇总」→ 步骤 9
RedTeam:   步骤 1→2→3→4→4.5 → 快速得分通道 → 5→6→8R→10R→12R→12R-api→12R-c→6R→7R→11R→9R → 侦察结果汇总 → 步骤 9
          (步骤 8「SRC→RedTeam 升级」仅 SRC 模式触发，纯 RedTeam 直接进入 8R)
```

==SRC 模式不执行 6R-12R（全端口/C段/深度差异对比），这些是 RedTeam 专属。==

## 行为指令

**你是自动化扫描引擎，不是参考手册。** 但在执行任何扫描之前，应先完成场景判断。

==执行位置分工（强制）==
- **Kali (SSH)**：所有网络请求（curl/nuclei/ffuf/whatweb/nmap/subfinder/httpx/sqlmap/hydra）— 不走 Windows 本地
- **Windows 本地**：Python 脚本、文件读写、结果解析、报告生成
- 禁止在 Windows Git Bash 跑 curl 测目标（代理不同步、grep -P 不支持、编码乱码）
- 禁止在 Kali 和 Windows 之间混跑同一批目标探测

---

## 步骤 1：场景判断（优先，在扫描之前执行）

==拿到目标后第一步不是开打，而是判断"我该怎么打"。不同场景的规则、边界、手法完全不同。==

### 1a. 场景识别

```
对于无法自动匹配的目标（中小企业/IP/不认识的域名）：

  1. 搜索引擎查 "{目标名/域名} SRC" 或 "{目标名} 安全应急响应中心"
     找到专属SRC → 提示用户SRC链接和规则，确认后再开始
     
  2. 搜索补天(butian.net) / 漏洞盒子 厂商库，看目标是否是注册厂商
     是公益SRC厂商 → 告知用户，进入公益SRC模式（合规轻量测试）
     
  3. 什么都找不到 → 询问用户:
     a) 这是授权红队渗透？→ 确认授权范围后，全力打（/recon）
     b) 这是公益SRC厂商？→ 轻量测试，遵守平台通用规则
     c) 这是CTF/靶场？→ 无限制
     d) 其他？→ 先搞清楚再动手
```

### 1b. 不同场景的扫描边界

```
| 维度         | 红队授权渗透      | 企业专属SRC(BSRC等) | 公益SRC(补天等)    |
|-------------|----------------|-------------------|-----------------|
| 全端口扫描   | ✓              | ✗ 大多禁止          | ✗ 不建议         |
| C段扫描      | ✓              | ✗ 禁止             | ✗ 禁止          |
| 高频爆破     | ✓              | ✗ 禁止             | ✗ 不建议         |
| 数据获取     | 按需            | 严格限制(如≤10条)   | 仅验证不拖数据    |
| 内网渗透     | ✓              | 看规则(BSRC禁止)    | ✗ 禁止          |
| 自动化扫描器 | nuclei/sqlmap  | 低频手工为主         | 低频为主         |
| 目标范围     | 合同授权范围     | SRC明确收录范围      | 仅该厂商资产      |
| 证明方式     | 完整利用链       | hostname/id等      | 截图+数据包       |
```

### 1c. 输出场景判断结果

```
=== 场景判断 ===
目标: xxx
场景: 红队授权渗透 / 企业SRC(xx平台) / 公益SRC(补天) / CTF
规则: [规则链接或"无特殊规则"]
扫描边界: [简述允许和禁止的操作]
→ 进入对应模式
```

==场景判断完成后，才能进入步骤 2。==

> 侦察中识别到云资产(CDN/CVM/OSS/IMDS) → @cloud-attack.md | 域环境(Kerberos/LDAP/SMB/AD) → @ad-attack.md

---

## 步骤 2：模式选择

### 2a. 显式指定

用户传入 `mode=src` 或 `mode=redteam` 则直接使用。

### 2b. 自动判断

```
if 目标是公司名（无点号、无IP格式）      → SRC（宽度优先）
elif 目标是根域名（如 example.com）       → SRC（宽度优先）
elif 目标是具体子域名（如 api.example.com）→ RedTeam（深度优先）
elif 目标是 IP 或 CIDR                     → RedTeam（深度优先）
```

确认后输出：`[MODE] SRC/RedTeam | 目标: xxx | 原因: xxx`

将 mode 写入 `meta.json`。

---

## 步骤 3：目标类型判断与被动信息收集（共享）

### 3a. 判断目标类型

```bash
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
  TYPE="ip"
elif [[ "$TARGET" =~ \.[a-zA-Z]{2,}$ ]]; then
  TYPE="domain"
else
  TYPE="company"
fi
echo "目标类型: $TYPE | 目标: $TARGET"
```

### 3b. 链式被动信息收集

==每一步的输出追加到下一步的输入。不是独立执行，是链式扩展。==

```
数据池（持续积累，每步都往里追加）:
  - 公司名列表
  - ICP 备案号列表
  - 主域名列表
  - 子域名列表
  - IP 列表
```

**根据输入类型启动对应的链：**

```
输入是公司名:
  公司名 → enscan/天眼查/爱企查 → 提取主域名（追加到主域名池）
  公司名 → ICP 备案查询 → 提取备案号（追加到 ICP 池）
  公司名 → 测绘引擎搜索（FOFA: "公司名"）→ 提取域名和 IP

输入是主域名:
  主域名 → subfinder → 子域名（追加到子域名池）
  主域名 → crt.sh → 子域名（追加到子域名池）
  主域名 → ICP 备案查询 → 备案号（追加到 ICP 池）
  主域名 → DNS 解析 → IP（追加到 IP 池）

输入是 ICP 备案号:
  备案号 → ICP 反查域名 → 主域名（追加到主域名池，触发上面的链）

输入是 IP:
  IP → 反向 DNS → 域名（追加到主域名池）
  IP → IP 归属查询（nali）→ 地理/ASN 信息
  IP → 测绘引擎搜索（FOFA: "ip=x.x.x.x"）→ 开放端口和服务
```

**链式扩展的关键：新发现的数据要回流到数据池，触发下一轮扩展。**

```
示例：
  输入「某某科技有限公司」
  → enscan 查到主域名 example.com + example.cn
  → ICP 查到备案号 京ICP备12345号
  → 备案号反查发现 example-api.com（新主域名！追加到池）
  → subfinder 跑 3 个主域名，发现 200 个子域名
  → DNS 解析子域名，得到 30 个 IP
  → 测绘引擎搜 IP，发现其中 5 个 IP 还有其他端口/服务

  最终数据池: 3 个主域名, 200 个子域名, 30 个 IP, 1 个 ICP
  比只搜一个域名的覆盖面大几倍
```

### 3c. 测绘引擎搜索（被动，零风险）

可用的搜索项（拿数据池里的每种数据去搜）：
```
FOFA/Hunter/Quake/Shodan/ZoomEye/Censys/DayDayMap

搜索维度:
  - IP: "ip=x.x.x.x"
  - 主域名: "domain=example.com"
  - ICP 备案号: "icp=京ICP备12345号"
  - 企业名称: "org=某某科技"
  - 证书: "cert=example.com"
```

### 3d. 其他被动收集

```
Github 源码泄露:
  搜索: "$COMPANY_NAME" password|secret|token|key|jdbc
  搜索: "$COMPANY_NAME" filename:.env
  搜索: "$DOMAIN" filename:config.json

云存储桶检测:
  检测: https://{company}-{env}.s3.amazonaws.com
  检测: https://{company}.oss-cn-{region}.aliyuncs.com
  检测: https://{company}.cos.ap-{region}.myqcloud.com
  发现后检查: 目录列出/未授权读取

邮箱密码泄露:
  Have I Been Pwned / 社工库查询

Wayback Machine:
  历史快照中可能有已删除的页面、旧 API、旧配置

Google Dorks:
  site:example.com filetype:pdf|doc|xls
  site:example.com inurl:admin|login|upload
```

### 3d-app: APP/小程序资产发现（被动，零风险）

==企业移动端资产（APP/小程序）往往比 Web 资产防御更弱，但常被遗漏。一条公司名就能自动化挖出全部 APP。==

**核心链路：** 公司名 → ICP 备案 → APP 列表 → 应用宝包名校验 → 下载地址

#### 第一层：ICP 备案信息抓取

```
数据来源: ICP 备案接口（工信部公开数据）
输入: 公司名称
输出: 
  - 备案 APP 名称列表
  - 微信小程序名称列表
  - 备案域名（可能发现新主域名，回流到步骤 3b 域名池）

关键点:
  - 接口支持分页批量查询 → 大公司可能几十个 APP
  - 很多 APP 名称与备案名称不完全一致 → 需要后续清洗
  - 微信小程序也算移动端资产,同样有 API 可测试
```

```bash
# 1. ICP 备案查询（通过测绘引擎/备案查询API）
# FOFA: app="{公司名}" 
# 或使用专用 ICP 查询接口

# 2. 从备案信息提取 APP 名称
# 记录到 target.json 的 mobile_assets 字段:
# {
#   "app_names": ["APP1", "APP2", ...],
#   "miniprograms": ["小程序1", "小程序2", ...],
#   "icp_domains": ["新发现的备案域名"]
# }
```

#### 第二层：应用宝包名校验（防山寨）

==名称相似的 APP 很多，山寨/修改版泛滥。应用宝的 pkgName 是权威"身份证"。==

```
校验流程:
1. 拿 ICP 备案的 APP 名称 → 腾讯应用宝搜索
2. 获取返回的 pkgName（如 com.company.appname）
3. pkgName 记录为"权威包名"，用于后续匹配
4. 应用宝搜不到的 → 标记为"待确认"，后续用其他市场交叉验证

为什么用应用宝:
  - 腾讯官方市场，包名可信度高
  - 返回结构规范，便于自动化
  - 防止下载到假 APP/广告壳/同名不同包
```

#### 第三层：软件市场双重匹配下载

==下载跳转规则相对固定，可解析 302 获取真实链接，市场详情页 HTML 也能直接抓包名。==

**常用市场及特点：**

| 市场 | 用途 | 特点 |
|------|------|------|
| 腾讯应用宝 | 包名校验（权威来源） | pkgName 准确,返回结构规范 |
| 历趣 | 严格模式下载 | 页面结构清晰,详情页直接含包名 |
| 豌豆荚 | 兜底下载 | 历史版本齐全,老 APP 也能找到 |
| 酷安 | 兜底下载 | 国内开发版/修改版多,注意校验 |
| 360 手机助手 | 兜底下载 | 覆盖面广 |

```
策略 1: 严格模式（有包名时）
  条件: 已获取应用宝 pkgName
  操作: 到历趣/豌豆荚搜索 → 进入详情页 → 校验页面中的包名 → 必须匹配
  效果: 完全防伪，不会下错

策略 2: 智能兜底模式（无包名时）
  操作: 清洗名称 → 过滤广告关键词 → 选标题含核心词的第一个结果
  适用: 应用宝搜不到 / 海外 APP / 小众 APP / 未上架主流市场
```

**页面结构抓包名（防止下错）：**
```bash
# 市场详情页 HTML 中通常直接包含包名
# 例: 历趣页面中有 <span id="pkgName">com.company.app</span>
# 或者 <meta data-pkg="com.company.app">
curl -sk "https://www.liqucn.com/app/xxxxx" | \
  grep -oP '(packageName|pkgName|pkg_name|data-pkg)["\x27][:=]["\x27]?\s*([a-zA-Z][a-zA-Z0-9_]*\.)+[a-zA-Z][a-zA-Z0-9_]*' | \
  head -5

# 如果页面中的包名 != 应用宝的 pkgName → 山寨/修改版,跳过
```

#### 名称清洗策略

==市场搜索结果混杂，不洗名字命中率很低。==

```
清洗规则（依次应用）:
  1. 去掉括号内容: "某某APP(官方版)" → "某某APP"
  2. 去掉后缀词: 官方版、APP、安卓版、客户端、手机版、HD版
  3. 去掉版本号: v2.3.1、2.0.1
  4. 统一大小写

黑名单关键词过滤（搜索结果去噪）:
  攻略、壁纸、破解、修改、多开、辅助、刷分、外挂
  → 包含这些词的搜索结果直接跳过，防止下载污染
```

#### 多线程加速

```python
# 并发跑多个 APP，速度提升 4-6 倍
from concurrent.futures import ThreadPoolExecutor

def process_app(app_name):
    pkg = query_yingyongbao(app_name)      # 应用宝取包名
    url = search_market(pkg or app_name)    # 市场搜索下载
    return {"name": app_name, "pkg": pkg, "url": url}

with ThreadPoolExecutor(max_workers=6) as executor:
    results = list(executor.map(process_app, app_names))
```

#### 302 跳转解析真实下载地址

```bash
# 市场下载链接通常是中转页 → 302 到真实 CDN 地址
# 不要 follow redirect，直接拿 Location 头
curl -sI "https://market.example.com/download/appid/12345" \
  -H "User-Agent: Mozilla/5.0" \
  | grep -i "^location:"
# Location: https://cdn.example.com/apk/com.company.app/v2.3.1.apk
```

#### 小程序资产特殊处理

```
微信小程序:
  - 无法下载 APK，但可以通过微信开发者工具抓包
  - 小程序也有后端 API → 抓包获取 API 域名 → 回流到子域名池
  - 小程序的 API 通常和 APP 共用后端，防御往往更弱
  - 注意: 小程序域名通常在 weixin.qq.com 白名单内

支付宝/百度小程序:
  - 同理，抓包获取后端 API 地址
  - 多端共用一套后端是常态
```

#### 输出与回流

==发现的 APP/小程序资产必须回流到数据池，触发后续攻击面分析。==

```
输出到 target.json:
  mobile_assets:
    apps:
      - name: "某某APP"
        pkg_name: "com.company.app"
        download_url: "https://cdn.example.com/app.apk"
        verified: true
    miniprograms:
      - name: "某某小程序"
        platform: "weixin"
        api_domains: []  # 抓包后填充

回流触发:
  1. APP 下载成功 → 触发 步骤 8R-app（APK 浅层域名提取）
  2. 发现新域名 → 回流到步骤 3b 域名池 → 触发子域名枚举
  3. 小程序 API 域名 → 加入 web-exploit 攻击面
```

### 3e. 优先排序原则

```
1. 源码泄露的敏感信息（密钥/密码/配置）→ 直接尝试登录
2. 云存储桶未授权 → 下载分析
3. staging/test/dev 环境 → 通常防御最弱
4. 非标准端口的 HTTP 服务 → 可能是管理后台
5. 主站 → 最后打，防御通常最强
```

---

## 步骤 4：子域名枚举（共享，深度按模式）

Tier 1（两种模式）: subfinder + crt.sh + DNS 爆破常用前缀
Tier 2（SRC 额外）: amass + FOFA API + Hunter API + SecLists DNS top-5000
最后: 通配符 DNS 检测 + 合并去重

```bash
# 通配符 DNS 检测 — 构造随机子域名，解析即说明存在通配符
WILDCARD_TEST="nocare-$(head -c 8 /dev/urandom | xxd -p).$DOMAIN"
WILDCARD_IP=$(dig +short "$WILDCARD_TEST" A 2>/dev/null | head -1)

if [ -n "$WILDCARD_IP" ]; then
  echo "[!] 通配符 DNS 已启用 → 所有未注册子域名解析到 $WILDCARD_IP"
  echo "    过滤: 从结果中排除 $WILDCARD_IP"
  grep -v "$WILDCARD_IP" "$OUTDIR/recon/subdomains_resolved.txt" \
    > "$OUTDIR/recon/subdomains_filtered.txt"
else
  echo "[OK] 无通配符 DNS"
  cp "$OUTDIR/recon/subdomains_resolved.txt" "$OUTDIR/recon/subdomains_filtered.txt"
fi
```

→ 详细命令见 `reference/commands.md`「子域名枚举命令」

---

## 步骤 4.5：子域名接管检测（共享）

==子域名枚举完成后，先对所有子域名做 CNAME 查询。发现指向已失效云服务（OSS/S3/Azure/GitHub Pages/CloudFront 等）时，该子域名可被接管。==

```bash
# 对每个子域名查 CNAME
while read sub; do
  cname=$(dig +short "$sub" CNAME 2>/dev/null | tail -1)
  if [ -n "$cname" ]; then
    echo "$sub → $cname"
  fi
done < "$OUTDIR/recon/subdomains.txt" > "$OUTDIR/recon/cname_records.txt"

# 匹配已知接管指纹
cat "$OUTDIR/recon/cname_records.txt" | while read line; do
  echo "$line" | grep -iE "cloudfront\.net|amazonaws\.com|azurewebsites\.net|azurefd\.net|trafficmanager\.net|cloudapp\.net|github\.io|gitbook\.io|herokuapp\.com|surge\.sh|netlify\.app|firebaseapp\.com|web\.app|storage\.googleapis\.com|aliyuncs\.com|aliyundrive\.com|myqcloud\.com" \
    && echo "  [!] POTENTIAL TAKEOVER"
done
```

接管指纹（CNAME 匹配）:

| 服务 | CNAME 特征 | 接管方式 |
|------|-----------|---------|
| AWS S3 | `s3.amazonaws.com` / `s3-*.amazonaws.com` | 创建同名 bucket |
| AWS CloudFront | `cloudfront.net` | 创建同名 CloudFront distribution |
| Azure Web App | `azurewebsites.net` | 创建同名 Web App |
| Azure CDN | `azurefd.net` / `trafficmanager.net` | 创建同名 CDN/traffic manager |
| Azure VM | `cloudapp.net` | 创建同名 VM |
| GitHub Pages | `github.io` | 创建同名 repo→Pages |
| GitBook | `gitbook.io` | 注册同名团队 |
| Heroku | `herokuapp.com` | 创建同名 app |
| Netlify | `netlify.app` | 创建同名 site |
| Firebase | `firebaseapp.com` / `web.app` | 创建同名 project |
| Google Cloud Storage | `storage.googleapis.com` | 创建同名 bucket |
| 阿里云 OSS | `aliyuncs.com` | 创建同名 bucket |
| 腾讯云 COS | `myqcloud.com` | 创建同名 bucket |

==命中 → 立即写 timeline + 预警（可接管的子域名列在 targets/{id}.json 的 subdomain_takeover 字段）==
**注意**：CNAME 指纹匹配 ≠ 确认可接管。需手动尝试验证——注册同名资源后看是否生效。

---

## 快速得分通道（被动完成→主动探测前，2 分钟高回报检查）

==被动信息收完，在 IP 暴露给目标大批量主动扫描前，先花 2 分钟直接测一批 golden path。命中直接进 exploit，不命中成本几乎为零。==

路径列表以 `leak_probe.py` 为唯一权威来源（19 条，含 SPA 假阳性过滤 + body 关键字校验），避免四散维护。

对主目标（及已知子域名 TOP 10）逐个测：

```bash
# 构造目标 URL 列表，用 leak_probe.py 批量探测
printf '%s\n' http://TARGET:80 http://TARGET:443 > /tmp/golden_urls.txt
# 如有已知子域名 TOP 10，追加到 golden_urls.txt
python3 ${CLAUDE_SKILL_DIR}/scripts/leak_probe.py /tmp/golden_urls.txt
```

脚本内置规则覆盖：`.git/HEAD`, `.git/config`, `.env`, `phpinfo.php`, `actuator`, `actuator/env`, `actuator/health`, `actuator/heapdump`, `druid/index.html`, `swagger-ui.html`, `api-docs`, `nacos/`, `console`, `server-status`, `server-info`, `debug`, `debug/config`, `.DS_Store`, `wp-json/wp/v2/users`, `trace`。

==命中了 → 立即追加 timeline + 写入 targets/{id}.json info_leaks 字段 → 直接跳 web-exploit，不继续侦察。==

---

## 步骤 5：httpx 批量探活（共享）

==替代逐个 curl，一次性获取所有子域名的存活状态、标题、技术栈、CDN 信息。==

- SRC 模式: threads 50, rate-limit 100, 含 CDN 检测
- RedTeam 模式: threads 20, 避免触发告警
- CDN 绕过深度技巧（F5 LTM 解码/MX 记录/SSL 证书指纹/Hosts 碰撞）→ `reference/external-recon-advanced.md`

→ 详细命令见 `reference/commands.md`「httpx 命令」

### httpx 结果自动分流

==根据 httpx 探活结果，对每个存活 URL 按特征自动路由到对应的测试路径。==

```
对每个存活 URL，根据响应特征判断下一步：

纯登录页面（title 含 login/登录 + 无其他功能）:
  → 记录认证信息，recon 阶段不爆破
  → 后续: 验证码检测 → 锁定策略探测 → 交给 web-exploit P6

Vue/React/Angular SPA（tech 含 vue/react/angular）:
  → Playwright 渲染提取 JS API 端点
  → 或 katana --headless 模式爬取

有明确指纹（finger_match 匹配到产品）:
  → 查 POC 库有无对应厂商模板
  → 有 → nuclei -t /mnt/share/poc/{厂商}/
  → 无 → 按框架类型查知识库

Swagger/API 文档暴露（title 含 swagger/api-doc）:
  → 读取 API 文档，提取所有端点
  → 逐个测试未授权访问

OSS 存储桶（URL 含 oss/s3/cos）:
  → 检测目录列出
  → 检测未授权读写

RTSP/视频流服务（端口 554/8554）:
  → 测试未授权访问
  → 默认凭据（admin/admin, admin/12345）

普通 Web 应用:
  → 走正常 recon 流程（信息泄露 + 目录爆破 + JS 分析）
```

---

## 步骤 5.5：深度识别（共享）

==httpx 给出的是基础技术栈。私有指纹库识别冷门系统，被动标记规则发现攻击面。==

### 可选：mitmproxy 被动分析

如果需要对后续所有探测请求做被动分析，可在 Windows 本机启动 mitmproxy：

```powershell
mitmdump -p 8888 -s "$env:CLAUDE_SKILL_DIR\scripts\mitm_plugin.py" --set flow_detail=0
```

启动后 agent 的 python requests 可设置 `proxies={"http":"http://127.0.0.1:8888","https":"http://127.0.0.1:8888"}`，所有请求经过代理时自动做 yakit 规则扫描 + 指纹匹配，结果输出到 `mitm_tags.jsonl` 和 `mitm_fingers.jsonl`。

### A: 私有指纹匹配

使用 `${CLAUDE_SKILL_DIR}/scripts/finger_match.py`，基于 `${CLAUDE_SKILL_DIR}/data/fingerprints_merged_v5.json`（33107 条产品指纹）。

```bash
scp ${CLAUDE_SKILL_DIR}/scripts/finger_match.py kali@$KALI_IP:/tmp/
scp ${CLAUDE_SKILL_DIR}/data/fingerprints_merged_v5.json kali@$KALI_IP:/tmp/
ssh kali@$KALI_IP 'python3 /tmp/finger_match.py -f /tmp/fingerprints_merged_v5.json -l /tmp/httpx_alive.txt'
```

匹配到后自动检查 POC 库（`/mnt/share/poc/`），有对应厂商模板则直接打：
```bash
nuclei -u TARGET -t /mnt/share/poc/{厂商}/
```

### B: 被动攻击面标记

使用 `${CLAUDE_SKILL_DIR}/scripts/passive_tag.py`，基于 yakit MITM 规则（60 条正则）扫描 HTTP 响应，标记：
- 注入参数（SQL/命令/XPath/SSRF）
- 敏感信息泄露（密钥/手机号/身份证/AK）
- 攻击入口（文件上传、文件包含、登录点、Swagger、Shiro）
- 框架特征（Struts2、JWT、Java 反序列化）

> 拿到源码包（小程序/APP反编译/前端打包/.git泄露）后的敏感信息提取，使用完整的正则规则库：`reference/sensitive-info-patterns.md`（13 大类 100+ 条规则，覆盖国内云 AK、微信生态、云存储桶、各类凭据字段）。

```bash
scp ${CLAUDE_SKILL_DIR}/scripts/passive_tag.py kali@$KALI_IP:/tmp/
scp ${CLAUDE_SKILL_DIR}/data/yakit_rules.json kali@$KALI_IP:/tmp/
ssh kali@$KALI_IP 'python3 /tmp/passive_tag.py -r /tmp/yakit_rules.json -l /tmp/httpx_alive.txt'
```

输出中会附带建议的下一步操作和对应的知识库 skill 路径。

### C: 三脚本并行

```bash
# httpx 完成后同时启动三个识别脚本
ssh kali@$KALI_IP 'python3 /tmp/finger_match.py -f /tmp/fingerprints_merged_v5.json -l /tmp/httpx_alive.txt > /tmp/finger_results.txt 2>&1' &
ssh kali@$KALI_IP 'python3 /tmp/passive_tag.py -r /tmp/yakit_rules.json -l /tmp/httpx_alive.txt > /tmp/tag_results.txt 2>&1' &
ssh kali@$KALI_IP 'python3 /tmp/leak_probe.py /tmp/httpx_alive.txt > /tmp/leak_results.txt 2>&1' &
wait
```

### 指纹库自动更新

渗透过程中遇到指纹库未收录的系统时：
1. 通过 HTML 特征（title、特殊路径、JS 文件名、响应头等）判断产品名称
2. **提示用户确认**产品名称和匹配规则
3. 用户确认后，追加到 `${CLAUDE_SKILL_DIR}/data/fingerprints_merged_v5.json`

==未经用户确认不写入。==

---

## 步骤 6：智能筛选（共享）

==从几千个子域名中快速定位高价值目标。按 P1-P4 分级。==

分级规则:
- P1 高价值: host 含 test/dev/staging/admin + 旧框架 + 非CDN 403 + API gateway
- P2 关注: 非CDN + 非标端口 + 登录页（需 2+ 条件）
- P3 普通: 其余
- P4 跳过: 第三方 SaaS / 停泊页

```bash
# 自动化筛选
python3 ${CLAUDE_SKILL_DIR}/scripts/priority_filter.py $OUTDIR/recon/httpx.jsonl -o $OUTDIR/recon/priority.json
```

---

## 步骤 7：SRC 批量操作

==recon 阶段只跑信息收集类模板，不跑攻击类。攻击类留给 /web-exploit。==

7a: nuclei 信息收集 (tags: tech,exposure,config,misconfig,default-login,takeover)
7b: 子域名接管 (nuclei takeover + dangling CNAME)
7c: CORS 批量检测 (P1+P2 目标, 使用 `${CLAUDE_SKILL_DIR}/scripts/cors_check.py`)
7d: 信息泄露 (leak_probe.py, 含 SPA 假阳性过滤)
7e: 目录爆破 (P1 目标 top-30, ffuf)
7f: SRC 端口扫描 (高价值端口，非全端口)
7g: API 端点批量探测 (JS 提取的端点, 使用 `${CLAUDE_SKILL_DIR}/scripts/api_probe.py`)

→ 详细命令见 `reference/commands.md`「SRC 批量操作命令」

---

## 步骤 8：SRC → RedTeam 升级

==当 SRC 模式发现高价值目标时，自动切换到 RedTeam 深度侦察。==

触发条件（任一满足）：

```
1. nuclei 命中 critical/high 漏洞
2. 发现未授权 API 或信息泄露（/debug, /.env, /actuator 等返回数据）
3. 存在旧框架（ThinkPHP 5.x, Struts2, Spring Boot 1.x 等）
4. 多端口开放（同一 IP 开放 3+ 个 HTTP 端口）
5. test/dev/staging 子域名 + 非 CDN
```

触发后对该特定 IP 执行**步骤 6R-12R 完整 RedTeam 流程**（全端口扫描 + 多端口差异分析）。

---

## 步骤 6R：全端口扫描（RedTeam 模式 — 最后执行）

==全端口扫描是高风险操作。必须在被动分析和轻度探测全部完成后才能执行。==
==高速全端口扫描（min-rate 5000）极易触发 IDS/防火墙封禁 IP，导致后续所有连接超时、整个任务作废。==

**前置条件（全部满足才执行）：**
```
[ ] 步骤 12R (JS分析) 已完成
[ ] 步骤 8R (已知端口深入侦察) 已完成
[ ] 步骤 10R (SSL证书分析) 已完成
[ ] 以上步骤未触发目标异常（无连接拒绝、无 IP 封禁迹象）
```

**执行时使用低速率，分段扫描：**
```bash
# 第一阶段：高价值端口快速扫（低风险）
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -p 80,443,8080,8443,8000,8888,9090,3000,7001,8081-8090,9000-9002,9200,10000 --min-rate 500 -T3 --open -oA $OUTDIR/recon/nmap_common TARGET

# 确认目标未异常后，第二阶段：全端口低速扫描
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -p- --min-rate 500 -T3 --open -oA $OUTDIR/recon/nmap_full TARGET
```

==--min-rate 500（不是 5000）、-T3（不是 T4）。宁可慢 10 分钟也不要被封。==

## 步骤 7R：服务识别（RedTeam）

```bash
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -sV -sC -p $(paste -sd, /tmp/open_ports.txt) -oA /tmp/nmap_sv TARGET
```

## 步骤 8R：httpx 批量 + 逐端口深入（RedTeam，增强）

先用 httpx 批量探测所有发现的 HTTP 端口，再逐端口深入。

```bash
# httpx 批量探所有端口
for port in $(cat /tmp/open_ports.txt); do
  echo "http://TARGET:$port"
  echo "https://TARGET:$port"
done | httpx -status-code -title -tech-detect -content-length -web-server \
  -threads 10 -o /tmp/httpx_ports.txt -json -o /tmp/httpx_ports.json
```

然后对每个 HTTP 端口执行深入侦察：

```bash
PORT=<port>

# 指纹识别
whatweb -a 3 --no-colour --log-json=/tmp/whatweb_port${PORT}.json http://TARGET:$PORT
nuclei -u http://TARGET:$PORT -severity critical,high,medium -timeout 10

# 信息泄露路径 — 委托 leak_probe.py（规则唯一来源，含 SPA 假阳性过滤 + body 关键字校验，符合硬规则 6）
echo "http://TARGET:$PORT" > /tmp/leak_target.txt
python3 ${CLAUDE_SKILL_DIR}/scripts/leak_probe.py /tmp/leak_target.txt

# SERVER_NAME / DOCUMENT_ROOT 对比
curl -s http://TARGET:$PORT/debug | grep -E "SERVER_NAME|DOCUMENT_ROOT|PATH" \
  > /tmp/recon_port${PORT}_server_info.txt

# 目录爆破
ffuf -u http://TARGET:$PORT/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -mc 200,301,302,403,500 -t 30 -o /tmp/ffuf_port${PORT}.json

# WebDAV 探测（IIS/Apache 常见）
curl -sk -X OPTIONS "http://TARGET:$PORT/" -I | grep -i "Allow\|DAV"
# 如果返回 PROPFIND/PUT/MOVE/MKCOL → WebDAV 开启
# PUT 测试: curl -sk -X PUT "http://TARGET:$PORT/test.txt" -d "test"
# PROPFIND: curl -sk -X PROPFIND "http://TARGET:$PORT/" -H "Depth: 1"

# VPN/网络设备指纹（URL 路径探测）
for app_path in /dana-na/ /remote/login /vpn/index.html /tmui/ /+CSCOE+/ /global-protect/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://TARGET:$PORT$app_path" 2>/dev/null)
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[VPN] $app_path → HTTP $code → 见 @network-device.md"
done
```

### 8R-extra: 登录接口侦察（发现登录页时必做）

==发现登录接口 = 记录，不是攻击。recon 阶段的任务是摸清认证机制和锁定策略，而不是尝试突破。==

**recon 阶段允许：**
- 分析登录表单/JS，了解认证流程和加密方式
- 1次锁定策略探测（用明确错误密码）
- 1-2次快速默认凭据试探（admin/admin 级别）
- 只读用户枚举（见下方规则）

**recon 阶段禁止：**
- 跑密码列表/写爆破脚本
- 连续尝试 3 个以上密码
- 任何可能触发锁定的批量操作
- **注册账号来做枚举（会污染目标状态，不可逆）**

**发现登录后正确做法：** 记录到 target 文件 → 继续枚举其他端点 → 所有 recon 完成后再评估是否爆破。

#### 用户名枚举（不污染目标状态）

==教训：对 TryHackMe 靶机用 signup 接口枚举用户名，把 10 个候选用户名全注册了，之后无法区分原始用户和自己创建的。==

**核心原则：枚举 = 只读观察，不是写入操作。**

```
枚举接口优先级（从最安全到最危险）：

1. 注册页面的"用户名已存在"提示（最佳）
   → 但 不要提交完整有效表单！
   → 用无效 email（如 "x"）或缺少必填字段，让注册失败但仍触发用户名检查
   → 或者 ffuf 检测响应大小差异: -fs 过滤掉"注册成功"的尺寸

2. 忘记密码页面的"用户不存在"提示
   → 通常是只读操作，不改变状态
   → POST username → 比较"已发送重置邮件" vs "用户不存在"

3. 登录页面的错误消息差异
   → "用户名不存在" vs "密码错误" → 可区分
   → "用户名或密码错误"（统一提示）→ 无法区分，换其他接口

4. AJAX 用户名检查接口（如果 JS 中发现）
   → /api/check-username?u=xxx 这类接口是纯只读的
```

ffuf 枚举用户名标准命令：
```bash
# 注册接口枚举（按响应大小差异区分）
ffuf -u "http://TARGET/signup" -X POST \
  -d "username=FUZZ&email=x&password=x" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/Names/names.txt \
  -mr "already exists" \
  -o $OUTDIR/recon/raw/user_enum.json

# 关键：email=x 和 password=x 故意无效，防止注册成功
# -mr 匹配"already exists"响应 = 该用户名已存在
```

当 ffuf/手工发现登录页面时：

```bash
LOGIN_URL="http://TARGET:$PORT/path/to/login"

# 1. 认证方式识别（分析表单/JS: POST/Challenge-Response/OAuth/证书？）
# 2. 锁定策略探测（用明确错误密码试 1 次）
PROBE=$(curl -sk -X POST "$LOGIN_URL" \
  -d "username=admin&password=LOCKOUT_PROBE_TEST" -D- 2>/dev/null)
echo "$PROBE" | grep -iE "attempt|剩余|次数|limit|locked|锁定|cooldown|retry|冻结"

# 3. 验证码/CSRF Token 检测
echo "$PROBE" | grep -iE "captcha|verify|验证码|csrf|_token"
```

判断结果写入 `targets/{id}.json` 的 `auth` 字段：
```json
{
  "auth": {
    "type": "form_post | challenge_response | oauth | cert",
    "login_url": "/login",
    "has_captcha": false,
    "has_csrf_token": false,
    "lockout": {"threshold": 5, "cooldown_sec": 600, "type": "per_user", "safe_batch": 3},
    "known_users": ["从枚举中发现的用户名"]
  }
}
```

### 步骤 8R-oss: OSS 存储桶探测（R2 阶段执行）

==从域名、公司名、JS 文件中推测存储桶名称，检测未授权访问。成本极低，收益可能极高（数据库备份/源码/配置文件）。==

### 桶名推测规则

```bash
# 从目标信息推测可能的桶名前缀
# 假设目标域名 example.com，公司名"示例科技"，应用名"vita"
PREFIXES="example example-com examplecom vita vita-app vita-prod vita-test vita-dev vita-backup vita-static vita-upload"
# 如果 JS 中发现了 OSS/S3/COS 相关 URL → 直接用提取到的桶名
```

### 检测逻辑

```bash
# 阿里云 OSS
for prefix in $PREFIXES; do
  for region in cn-hangzhou cn-shanghai cn-beijing cn-shenzhen cn-chengdu cn-hongkong; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.oss-${region}.aliyuncs.com/" 2>/dev/null)
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[OSS] ${prefix}.oss-${region}.aliyuncs.com → HTTP $code"
  done
done

# 腾讯云 COS
for prefix in $PREFIXES; do
  for region in ap-guangzhou ap-shanghai ap-beijing ap-chengdu ap-hongkong; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.cos.${region}.myqcloud.com/" 2>/dev/null)
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[COS] ${prefix}.cos.${region}.myqcloud.com → HTTP $code"
  done
done

# AWS S3
for prefix in $PREFIXES; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.s3.amazonaws.com/" 2>/dev/null)
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[S3] ${prefix}.s3.amazonaws.com → HTTP $code"
done
```

### 结果判断

```
HTTP 200 → 桶存在且可列目录（严重：未授权访问）→ 立即采集证据
HTTP 403 → 桶存在但禁止访问（记录，后续尝试特定路径）
HTTP 301 → 桶存在，重定向（记录桶名）
HTTP 404 → 桶不存在，跳过
```

发现可列目录的桶 → 检查是否有敏感文件：
```bash
# 列出桶内容（如果 200）
curl -sk "https://BUCKET_URL/" | grep -oP '(?<=<Key>)[^<]+' | head -50
# 关注: .sql .bak .zip .tar.gz .env config database backup dump
```

## 步骤 8R-vhost: Virtual Host 枚举（R2 阶段执行）

==同一 IP 用不同 Host header 可能访问到不同应用。Nginx/Apache 虚拟主机根据 Host 路由，内部域名绕过外网 WAF。==

**检测方法**

```bash
# 1. 先取首页 body 大小作为基线
BASELINE_SIZE=$(curl -sk "http://TARGET_IP/" -w "%{size_download}" -o /dev/null)

# 2. ffuf VHOST 模式 — 用 SecLists 子域名字典，过滤掉与基线相同大小的响应
ffuf -u http://TARGET_IP/ \
  -H "Host: FUZZ.$KNOWN_DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs "$BASELINE_SIZE" -t 20 -o "$OUTDIR/recon/raw/vhost_enum.json"

# 3. 也尝试不带域名后缀的短名（内部服务常用）
ffuf -u http://TARGET_IP/ \
  -H "Host: FUZZ" \
  -w /usr/share/seclists/Discovery/DNS/namelist.txt \
  -fs "$BASELINE_SIZE" -t 20

# 4. 手工验证差异 Host
# 从 ffuf 输出中提取命中项，手工 curl 确认不是误报
```

**判定**

```
响应 200 + body 大小与基线不同 → 隐藏应用，需指纹识别
响应 301/302 → 有重定向，follow 看跳到哪里
响应 403 → 应用存在但禁止直接访问
响应与基线完全相同 → 默认虚拟主机，无额外应用
```

==发现隐藏应用 → 追加到 `targets/{id}.json` 的 `info_leaks`，创建对应新 target 文件。==

## 步骤 8R-nginx-route: Nginx 多级路由收集（R2 阶段执行）

==Nginx 做反向代理时,多级路由前缀可能对应不同的后端服务,且鉴权配置常常不一致。收集所有路由层级,每层都可能有意想不到的未授权入口。==

**核心概念：**
```
http://TARGET/h5/login       ← 一级路由 /h5
http://TARGET/ywxt/h5/login  ← 二级路由 /ywxt/h5
http://TARGET/api/v2/user    ← 一级路由 /api, 版本路由 /v2

每层路由:
  - 可能指向不同的后端 upstream
  - 可能有不同的鉴权规则(外层有鉴权,内层忘了加)
  - 可能有不同的 WAF 规则(外层全量规则,内层简化规则)
  - 可能有不同的路径标准化行为(off-by-slash、alias 缺陷)
```

**收集方法：**

```bash
# 1. 从已知 URL 提取所有路由前缀层级
echo "http://TARGET/ywxt/h5/login" | python3 -c "
from urllib.parse import urlparse
import sys

url = sys.stdin.read().strip()
path = urlparse(url).path.strip('/')
parts = path.split('/')

# 生成所有路由前缀
for i in range(1, len(parts)):
    prefix = '/' + '/'.join(parts[:i])
    print(prefix)
# 输出: /ywxt, /ywxt/h5
"

# 2. 从 JS 文件中提取所有 API 路由前缀
grep -roP '["\x27](/[a-zA-Z][a-zA-Z0-9_\-]*)+/' js_files/ | \
  cut -d'"' -f2 | cut -d"'" -f2 | sort -u | \
  while read prefix; do
    # 提取前两段
    echo "$prefix" | cut -d'/' -f1-3
  done | sort -u > route_prefixes.txt

# 3. 从 Swagger/OpenAPI 提取路由前缀
curl -sk "http://TARGET/v2/api-docs" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    paths = d.get('paths', {})
    prefixes = set()
    for p in paths:
        parts = p.strip('/').split('/')
        if len(parts) >= 2:
            prefixes.add('/' + '/'.join(parts[:2]))
    print('\n'.join(sorted(prefixes)))
except: pass
" 2>/dev/null >> route_prefixes.txt
```

**对每个路由前缀探测常见未授权入口：**

```bash
while read prefix; do
  echo "=== 测试前缀: $prefix ==="
  for probe in /actuator /swagger-ui.html /druid/index.html /api-docs \
               /.env /admin /console /debug /test /phpinfo.php; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      "http://TARGET${prefix}${probe}" --connect-timeout 5)
    [ "$code" != "404" ] && [ "$code" != "000" ] && \
      echo "  [!] ${prefix}${probe} → $code"
  done
done < route_prefixes.txt
```

**Nginx 配置缺陷专项检测：**

```bash
# 1. alias 缺尾斜杠 → 路径穿越
#    配置: location /static { alias /var/www/app/static; }
#    利用: /static../ 可访问 /var/www/app/
curl -sk "http://TARGET/static../WEB-INF/web.xml" -w "\n%{http_code}"
curl -sk "http://TARGET/files../etc/passwd" -w "\n%{http_code}"

# 2. merge_slashes off → 双斜杠绕过 location 匹配
#    配置: merge_slashes off; location /admin { deny all; }
#    利用: //admin 绕过
curl -sk "http://TARGET//admin/" -w "\n%{http_code}"
curl -sk "http://TARGET//api//user" -w "\n%{http_code}"

# 3. 内部 location 通过 Header 访问
#    配置: location /internal/ { internal; }
#    利用: 应用层注入 X-Accel-Redirect 响应头
curl -sk "http://TARGET/upload" -F "file=@test.txt;filename=../../internal/config"

# 4. $uri 注入(CRLF)
#    配置: return 302 $uri;
#    利用: /api%0d%0aLocation:%20http://evil.com%0d%0a → 响应头注入
curl -sk "http://TARGET/api%0d%0aX-Injected:%20test" -w "\n%{http_code}"
```

**判定：**
```
新路由前缀下发现未授权入口 → 高危(绕过一/二级路由鉴权)
多级路由响应不同应用 → 攻击面扩大,每个路由前缀作为一个独立子目标
alias 路径穿越成功 → 严重(任意文件读取)
merge_slashes 绕过 ACL → 高危
```

==发现新的路由前缀 → 追加到 `targets/{id}.json` 的 `route_prefixes` 字段,作为新的攻击面。==

## 步骤 8R-app: APK 浅层资产提取（RedTeam，有 APP 下载链接时执行）

==APP 安装包是域名/API 的金矿。不需要深度逆向，几秒就能从 APK 中提取数十个内部域名和 API 端点。==

> 注意: 此步骤聚焦 APK 浅层信息提取（字符串/配置文件中的域名和 URL），不做完整逆向分析。如果后续需要深度逆向（脱壳/so 分析/Smali 修改），应交由专门的移动安全工具处理。

### 快速域名提取

```bash
# 1. 解压 APK（APK 本质是 ZIP）
unzip -o app.apk -d apk_extracted/

# 2. strings 提取所有可打印字符串 → grep 域名/IP/URL
strings apk_extracted/*.dex 2>/dev/null | \
  grep -oP '(https?://[a-zA-Z0-9\.\-]+|[a-zA-Z0-9\-\.]+\.(com|cn|net|org|io|cc|co|xyz|top|club|dev|app|cloud|ai))' | \
  sort -u > apk_domains.txt

# 3. 也检查 assets 中的配置文件（JSON/XML/YAML）
find apk_extracted/assets/ -type f -exec strings {} \; | \
  grep -oP '(https?://[a-zA-Z0-9\.\-]+)' | sort -u >> apk_domains.txt

# 4. 提取 AndroidManifest.xml 中的 package name 和权限
# （二进制 XML，需要工具转换）
python3 -c "
import xml.etree.ElementTree as ET
# 使用 axmlparser 或 androguard 解析二进制 XML
# 或者直接用 strings + grep:
" 
strings apk_extracted/AndroidManifest.xml | grep -E 'http|\.com|\.cn|\.net' | sort -u
```

### 高价值提取目标

| 文件/位置 | 提取内容 | 价值 |
|-----------|---------|------|
| `res/values/strings.xml` | API Base URL、App Key、Secret | 直接可用的后端地址和凭证 |
| `assets/*.json` / `assets/*.js` | 后端配置、热更新地址 | 配置文件常含多环境域名 |
| `AndroidManifest.xml` | package name、permissions、intent-filter URL | 包名确认 + 权限暗示攻击面 + deep link |
| `.dex` → strings | 硬编码 URL、SDK Key、loadUrl 参数 | 开发遗留的测试/内网地址 |
| `lib/*.so` → strings | Native 层硬编码密钥、CURL/OKHttp URL | C/C++ 中的字符串不易被混淆 |
| `assets/www/` | Cordova/WebView 前端源码 | 直接拿到 H5 全部前端代码 |
| `META-INF/` | 签名信息 | 确认 APP 是否正规签名 |
| `res/raw/` / `assets/` 中的证书 | .p12 .pem .cer .jks | 客户端证书 = 内网 VPN 入口 |

### WebView URL 专项提取

==Android WebView 的 URL 通常硬编码在 loadUrl() 调用中。提取这些 URL = 拿到 APP 内嵌的全部 Web 页面。==

```bash
# 1. 从 dex 中 grep loadUrl 调用（最常见）
strings apk_extracted/*.dex | grep -oP 'loadUrl\("[^"]+"\)' | \
  sed 's/loadUrl("//;s/")//' | sort -u > webview_urls.txt

# 2. 也检查 shouldOverrideUrlLoading（URL 拦截逻辑）
strings apk_extracted/*.dex | grep -oP '(http|https)://[a-zA-Z0-9\.\-]+(:[0-9]+)?(/[^\s,"'\'']*)?' | \
  sort -u >> webview_urls.txt

# 3. 从 strings.xml 提取 WebView 配置
#    常见 key: webview_url, h5_url, web_url, base_url, home_url
grep -oP '(webview_url|h5_url|web_url|base_url|home_url|online_url)' \
  apk_extracted/res/values/strings.xml

# 4. CDN/静态资源域名单独提取（通常和 API 域名不同）
strings apk_extracted/*.dex | grep -oP '\b[a-zA-Z0-9\-]+\.(akamaized\.net|alicdn\.com|qiniucdn\.com|myqcloud\.com|cloudfront\.net|cdn\.\w+\.\w+)\b' | \
  sort -u > cdn_domains.txt
```

### 一键域名提取脚本

```bash
#!/bin/bash
# apk_quick_extract.sh — 输入 APK 路径,输出域名列表

APK=$1
OUTDIR=$(mktemp -d)

echo "[*] Extracting $APK..."
unzip -o "$APK" -d "$OUTDIR" 2>/dev/null

echo "[*] Running strings on dex..."
find "$OUTDIR" -name "*.dex" -exec strings {} \; 2>/dev/null | \
  grep -oPE 'https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?(/[a-zA-Z0-9\.\-_~/]*)?' \
  > apk_urls.txt

echo "[*] Extracting from assets config..."
find "$OUTDIR/assets" "$OUTDIR/res" -type f \( -name "*.json" -o -name "*.xml" -o -name "*.js" -o -name "*.properties" \) \
  -exec strings {} \; 2>/dev/null | \
  grep -oPE 'https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?(/[a-zA-Z0-9\.\-_~/]*)?' \
  >> apk_urls.txt

echo "[*] Deduplicating and filtering..."
sort -u apk_urls.txt > apk_urls_uniq.txt

# 统计域名
grep -oP 'https?://[a-zA-Z0-9\.\-]+' apk_urls_uniq.txt | \
  sed 's|https\?://||' | sort -u > apk_domains.txt

echo "[+] Found $(wc -l < apk_domains.txt) unique domains"
echo "[+] Found $(wc -l < apk_urls_uniq.txt) unique URLs"
cat apk_domains.txt

rm -rf "$OUTDIR"
```

### 提取结果回流

```
处理流程:
1. 新发现的域名 → 追加到子域名池 → 触发步骤 4 子域名枚举
2. 新发现的 API 端点 → 追加到 target.json 的 endpoints 字段
3. 新发现的内部 IP → 记录（可能是内网地址，需要 VPN/内网才能访问）
4. 新发现的 App Key / Secret → 追加到 credentials 字段 → 尝试在其他系统复用
5. 多环境域名 (test/dev/staging/api) → 这些环境通常防御最弱 → 优先攻击

特殊价值:
  - APP 中的域名往往是"真实后端"，而非 CDN/WAF 前端
  - APP 中可能直接暴露内网 IP（开发忘记切换成域名）
  - 热更新地址劫持 = APP 全量用户代码执行
  - WebView URL 配置劫持 = 钓鱼/数据窃取
```

### 比 Web 更容易出洞的原因

```
1. APP 后端 API 通常不经过 WAF（直接连后端或独立网关）
2. 移动端 API 认证逻辑往往比 Web 端简化（Token 而非 Session）
3. 旧版本 APP 的 API 可能已废弃但未下线 = 无人维护 = 无修复
4. APP 中硬编码的 Key/Secret 全量用户共享 → 泄露一个 = 全量泄露
5. 开发/测试环境地址常硬编码在 APP 中（debug 包尤其严重）
```

==判定: APP 中发现新域名 → 追加到资产池继续侦察。发现硬编码 Key/Secret → 高危(通常全量用户共享)。发现内网地址 → 画拓扑图,标记为内网入口。==

## 步骤 9R：多端口差异对比矩阵（RedTeam 核心）

==同一应用在不同端口可能有不同的反向代理/WAF 配置。对比各端口的频率限制、CSRF、CORS、内部 IP 映射，找到防护最弱的入口。==

生成对比表:

| 端口 | HTTP状态 | SERVER_NAME(内部IP) | /debug | /test | 频率限制 | CSRF | CORS |
|------|----------|-------------------|---------|-------|---------|------|------|
| (示例) | 200 | 内部IP | 有/无 | 有/无 | 有/无 | 有/无 | 有/无 |

==选择无频率限制+无CSRF的端口作为主要攻击入口。==

## 步骤 10R：SSL 证书分析（RedTeam）

```bash
openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative"

curl -s "https://crt.sh/?q=TARGET&output=json" --connect-timeout 15 -m 60 \
  -o /tmp/crtsh_target.json 2>/dev/null
python3 -c "
import json
try:
    data = json.load(open('/tmp/crtsh_target.json'))
    subs = set()
    for e in data:
        for name in e.get('name_value','').split('\n'):
            name = name.strip().lstrip('*.')
            if name: subs.add(name)
    for s in sorted(subs): print(s)
except: pass
"
```

## 步骤 11R：C 段扫描（RedTeam）

```bash
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE TARGET/24 -oA /tmp/nmap_csegment
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -p 80,443,888,3306,6379,8080,8443,8888 \
  --open -iL /tmp/csegment_alive.txt -oA /tmp/nmap_csegment_ports
```

## 步骤 12R：JS 文件情报提取（RedTeam）

==JS 注释里可能有旧 API 地址、硬编码密钥、测试账号等敏感信息。==

### 12R-a: 静态分析（grep，适合传统网站）

```bash
# 从 HTML 提取 JS 文件 URL
curl -s http://TARGET | grep -oP '(?<=src=")[^"]*\.js' | sort -u

# 下载每个 JS 并搜索关键信息
for js in $(cat /tmp/js_files.txt); do
  curl -s "$js" | grep -iE "http://|https://|api|key|secret|token|password|phone|code|邀请"
done

# 搜索被注释掉的旧 API 地址
grep -r "//.*http://" /tmp/*.js
grep -r "//.*api" /tmp/*.js
```

### 12R-b: 动态爬虫（Playwright，SPA 站点必用）

==SPA（Vue/React/Angular）的路由和 API 是动态生成的，静态 grep 抓不全。Playwright 爬虫自动渲染页面、拦截所有 XHR/fetch，发现量通常是静态 grep 的 3-10 倍。==

```bash
# 在 Windows 本机执行（Playwright 在本机）
python ${CLAUDE_SKILL_DIR}/scripts/playwright_crawler.py "https://TARGET:PORT/path/" \
  -o $OUTDIR/recon/raw/crawler_results.json
```

输出：
- `[FORM]` — 表单及字段（上传点/登录点）
- `[API]` — JS 中的 API 端点（fetch/axios/$.ajax）
- `[PARAM]` — 带参数的 URL（注入候选）

选择规则：
```
传统 MVC（PHP/JSP/ASP）→ 12R-a 静态 grep 足够
SPA（路由含 #/ 或 history API）→ 12R-b 动态爬虫必用
不确定 → 两个都跑，合并去重
```

结果写入 `targets/{id}.json` 的 `js_intel` 和 `endpoints`。

### 12R-c: 敏感信息深度扫描

==12R-a/b 收集到的 JS 文件包含大量代码，grep 粗筛容易漏。`sensitive_scanner.py` 用 48 条结构化规则（按严重级别+类别+误报提示）逐文件扫描，输出专为 AI 研判设计。==

```bash
# 对 12R-a 提取的每个 JS 文件和 12R-b crawler 输出的 JS 做深度扫描
mkdir -p $OUTDIR/recon/raw/sensitive_scan/

# 从 HTML 提取的 JS 文件逐个扫描
while read js_url; do
  curl -sk --max-time 10 "$js_url" -o /tmp/_scan.js 2>/dev/null
  [ ! -s /tmp/_scan.js ] && continue
  python3 ${CLAUDE_SKILL_DIR}/scripts/sensitive_scanner.py \
    -f /tmp/_scan.js --format json \
    > "$OUTDIR/recon/raw/sensitive_scan/$(echo $js_url | md5sum | cut -c1-8).json"
done < $OUTDIR/recon/raw/js_files.txt

# 对 crawler_results.json 中发现的 API 响应也扫一遍（如果有 -r 模式获取的响应体）
[ -f "$OUTDIR/recon/raw/crawler_results.json" ] && \
  python3 -c "
import json
data = json.load(open('$OUTDIR/recon/raw/crawler_results.json'))
for r in data:
    for resp in r.get('responses', []):
        if 'json' in resp.get('content_type','') or 'javascript' in resp.get('content_type',''):
            print(resp['url'])
" | while read api_url; do
  python3 ${CLAUDE_SKILL_DIR}/scripts/sensitive_scanner.py \
    -u "$api_url" --format json \
    > "$OUTDIR/recon/raw/sensitive_scan/api_$(echo $api_url | md5sum | cut -c1-8).json" 2>/dev/null
done

# 汇总所有命中
grep -rl '"severity"' $OUTDIR/recon/raw/sensitive_scan/ | while read f; do
  python3 -c "
import json
data = json.load(open('$f'))
for hit in data.get('hits', []):
    print(f\"[SENSITIVE] {hit.get('rule')} | {hit.get('severity')} | {hit.get('match','')[:60]}\")
"
done | sort -u
```

规则覆盖 6 大类：凭据泄露（AK/SK/Token/密码）、云服务密钥（OSS/S3/COS）、数据库连接串、API 端点泄露、个人信息（手机/身份证/邮箱）、内部地址泄露。每条规则含 `fp_note`（常见误报场景）供 AI 判假。

命中的凭据写入 `targets/{id}.json` 的 `js_intel.hardcoded`，严重级别（AK/SK/私钥）直接追加 `info_leaks`。

> 步骤 3d（GitHub/源码泄露）发现源码包后，同样跑 `sensitive_scanner.py -f <path>` 深度扫描。

---

## 步骤 12R-api: API 端点聚合（RedTeam）

==JS 文件不是唯一的端点来源。robots.txt、sitemap.xml、Swagger/OpenAPI 文档、Wayback Machine 历史记录都可能暴露隐藏 API。聚合 5 个来源，统一清洗后喂给 `api_probe.py`。==

### 12R-api-a: 下载原始响应（先落地，再提取）

```bash
mkdir -p "$OUTDIR/recon/raw/api_sources"

# 下载所有可能暴露 API 的文件，原始响应落地
curl -sk --max-time 5 "http://TARGET:$PORT/robots.txt" \
  -o "$OUTDIR/recon/raw/api_sources/robots.txt" 2>/dev/null

curl -sk --max-time 10 --compressed "http://TARGET:$PORT/sitemap.xml" \
  -o "$OUTDIR/recon/raw/api_sources/sitemap.xml" 2>/dev/null

for doc in /swagger.json /openapi.json /api-docs /v2/api-docs /v3/api-docs /swagger/v1/swagger.json; do
  curl -sk --max-time 5 "http://TARGET:$PORT$doc" \
    -o "$OUTDIR/recon/raw/api_sources/${doc//\//_}.json" 2>/dev/null
done

curl -sk --max-time 15 \
  "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=text&fl=original&limit=500" \
  -o "$OUTDIR/recon/raw/api_sources/wayback.txt" 2>/dev/null
```

### 12R-api-b: 多来源提取（容错解析）

```bash
# 来源1: robots.txt — 标准格式 + 乱码兜底
ROBOTS=$(cat "$OUTDIR/recon/raw/api_sources/robots.txt" 2>/dev/null)
if [ -n "$ROBOTS" ]; then
  echo "$ROBOTS" | grep -oP '(?:Allow|Disallow|Sitemap):\s*\K\S+' \
    | sed 's/[#*].*//' | grep '^/' | sort -u > /tmp/api_robots.txt 2>/dev/null
  # 兜底: 完全不按规则出牌 → 无脑提取所有 / 开头路径
  [ ! -s /tmp/api_robots.txt ] && echo "$ROBOTS" \
    | grep -oP '/[a-zA-Z0-9/_.-]+' | sort -u > /tmp/api_robots.txt
fi
touch /tmp/api_robots.txt

# 来源2: sitemap.xml — <loc> 标签 + 纯文本 URL 兜底
SITEMAP=$(cat "$OUTDIR/recon/raw/api_sources/sitemap.xml" 2>/dev/null)
if [ -n "$SITEMAP" ]; then
  echo "$SITEMAP" | grep -oP '(?<=<loc>)[^<]+' | sort -u > /tmp/api_sitemap.txt
  [ ! -s /tmp/api_sitemap.txt ] && echo "$SITEMAP" \
    | grep -oP 'https?://[^\s<>"]+' | sort -u > /tmp/api_sitemap.txt
fi
touch /tmp/api_sitemap.txt

# 来源3: Swagger/OpenAPI — jq 解析 + 畸形 JSON grep 兜底
> /tmp/api_swagger.txt
for f in "$OUTDIR/recon/raw/api_sources"/{_swagger.json,_openapi.json,_api-docs,_v2_api-docs,_v3_api-docs,_swagger_v1_swagger.json}; do
  SWAGGER=$(cat "$f" 2>/dev/null)
  [ -z "$SWAGGER" ] && continue
  echo "$SWAGGER" | jq -r '.paths | keys[]?' 2>/dev/null >> /tmp/api_swagger.txt
  # jq 挂了 → 粗暴正则兜底
  [ ${PIPESTATUS[0]} -ne 0 ] && echo "$SWAGGER" \
    | grep -oP '"/[a-zA-Z0-9/_{}-]+"' | tr -d '"' >> /tmp/api_swagger.txt
done
sort -u /tmp/api_swagger.txt -o /tmp/api_swagger.txt
touch /tmp/api_swagger.txt

# 来源4: Wayback Machine — 过滤静态资源噪音
cat "$OUTDIR/recon/raw/api_sources/wayback.txt" 2>/dev/null \
  | grep -viE '\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|xml)($|\?)' \
  | grep -iE '/api/|/v[0-9]/|/graphql|/rest/|/auth|/login|/admin|/user|/upload' \
  | sed 's|https\?://[^/]*||; s/\?.*//' \
  | sort -u > /tmp/api_wayback.txt
touch /tmp/api_wayback.txt

# 来源5: JS 提取端点（12R 已有 → crawler_results.json）
[ -f "$OUTDIR/recon/raw/crawler_results.json" ] && \
  jq -r '.[] | select(.type=="API") | .url // empty' \
    "$OUTDIR/recon/raw/crawler_results.json" 2>/dev/null \
  | sed 's|\?.*||' | sort -u > /tmp/api_js.txt
touch /tmp/api_js.txt
```

### 12R-api-c: 合并清洗 + 批量探测

```bash
cat /tmp/api_robots.txt /tmp/api_sitemap.txt /tmp/api_swagger.txt \
    /tmp/api_wayback.txt /tmp/api_js.txt \
  | grep '^/' \
  | grep -v '^\*$\|^//$\|^\s*$' \
  | sed 's/[#;].*//; s/\?.*//' \
  | sort -u \
  > "$OUTDIR/recon/raw/api_endpoints_all.txt"

COUNT=$(wc -l < "$OUTDIR/recon/raw/api_endpoints_all.txt")
echo "[聚合] 5 来源 → $COUNT 唯一端点"

if [ "$COUNT" -gt 0 ]; then
  python3 ${CLAUDE_SKILL_DIR}/scripts/api_probe.py \
    "http://TARGET:$PORT" \
    "$OUTDIR/recon/raw/api_endpoints_all.txt" \
    > "$OUTDIR/recon/raw/api_probe_results.txt"
fi
```

原始响应保存在 `$OUTDIR/recon/raw/api_sources/`，后续发现新提取规则可直接 `cat` 重跑，不用再打一次目标。

---

## 侦察结果汇总 — 进入 PHASE 2 前必做（SRC / RedTeam 共享）

### SRC 模式汇总

```
=== SRC 侦察汇总 ===

目标: $DOMAIN ($COMPANY)
模式: SRC（宽度优先）

子域名: 发现 N 个，存活 M 个
数据源: subfinder N1 | crt.sh N2 | FOFA N3 | amass N4 | DNS爆破 N5

存活分布:
  CDN 后: X 个 | 非CDN: Y 个
  状态码: 200=A | 301/302=B | 403=C | 其他=D
  Top 技术栈: nginx, php, thinkphp, jquery, ...

筛选结果:
  P1 高价值: X 个（test/dev/旧框架/非CDN边缘资产）
  P2 关注: Y 个（非CDN/管理后台/非标端口）
  P3 普通: Z 个
  P4 跳过: W 个

nuclei 命中:
  Critical: X | High: Y | Medium: Z | Low: W
  [列出所有 critical/high 具体漏洞]

子域名接管: N 个候选
CORS 问题: N 个
信息泄露: N 个

高价值目标（已升级到 RedTeam 深度侦察）:
  - test.example.com (ThinkPHP 5.0, 非CDN)
  - admin.example.com (Swagger UI 暴露)
  - ...
```

### RedTeam 模式汇总

```
=== RedTeam 侦察汇总 ===

目标: X.X.X.X
模式: RedTeam（深度优先）

开放端口: [实际扫描结果]
框架: [实际检测结果]
WAF: [实际检测结果]

内部架构:
  [从 /debug 等路径提取的端口→内部IP映射]

关联资产:
  [SSL SAN / C段 / 配置泄露中发现的关联资产]

最弱入口: [无频率限制/无CSRF/无WAF的端口及原因]

信息泄露:
  - /api/Uploads/test → 数据库数据直接返回
  - /debug → 服务器内部IP和路径
  - /debug/config → 数据库名称和应用配置
```

### 完成自检清单

==进入 web-exploit 前逐项确认，缺项补完再走。==

**RedTeam 模式：**
```
[ ] 全端口扫描完成（至少常用 1000 端口 + 高价值端口）
[ ] 每个 HTTP 端口：指纹识别 + 信息泄露探测 + 目录爆破
[ ] SSL 证书分析完成（有 SSL 的话）
[ ] C 段存活扫描完成（如有必要）
[ ] JS 文件情报提取完成（传统 grep 或 Playwright 爬虫）
[ ] 敏感信息深度扫描完成（sensitive_scanner.py → JS/泄露文件）
[ ] API 端点聚合完成（5 来源 → api_probe.py）
[ ] 多端口差异对比完成
```

**SRC 模式：**
```
[ ] 子域名枚举完成（subfinder + crt.sh + DNS 爆破）
[ ] httpx 批量探活完成
[ ] 智能筛选完成（P1/P2/P3 分级）
[ ] nuclei 信息收集模板完成
[ ] 高价值目标升级 RedTeam 深度侦察完成（如有触发）
```

然后自动进入 web-exploit。

## 步骤 9：自动决策 — PHASE 2 攻击路径建议

==侦察汇总后、进入 web-exploit 前，先用 validate_target.py 检查每个 target.json 完整性，确认必须字段没有缺漏。==

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/validate_target.py $OUTDIR/targets/ --all
```

然后根据侦察结果，按以下规则自动生成攻击路径：

```
=== PHASE 2 建议攻击路径 ===

基于侦察结果的自动决策逻辑:

1. 发现已知框架CVE (nuclei命中 / ThinkPHP / Struts / Spring等)
   → 调用 /web-exploit，优先尝试已知CVE利用
   → 如果是 ThinkPHP → 进入 web-exploit P1 CVE匹配流程

2. 发现信息泄露 (.git/源码/.env/actuator/debug等)
   → 调用 /web-exploit，分析泄露内容寻找凭据/密钥
   → .git 泄露 → 尝试 git-dumper 还原源码 → 代码审计
   → .env/actuator → 提取数据库密码/API密钥

3. 发现文件上传端点
   → 调用 /web-exploit，尝试上传绕过 (双扩展名/MIME/截断)

4. 发现登录页面/后台
   → 先尝试 TOP20 弱口令 (admin/admin, admin/123456 等)
   → 有多个用户名线索 + 无锁定策略 → 调用 /brute-force 针对性爆破
   → 仅单个登录页 + 无用户名线索 → 记录到 targets/{id}.json auth 字段，交给 web-exploit P6

5. 发现API端点无认证
   → 测试越权 (水平IDOR: 改ID查他人数据)
   → 测试参数注入 (SQLi/SSRF/SSTI)

6. 发现WAF拦截
   → 调用 /waf-bypass 选择绕过策略

7. 发现云资产/云凭证 (OSS Key/IMDS/AK-SK/云存储桶)
   → 调用 /cloud-attack 进行云平台渗透 (AWS/阿里云/Azure)

8. 发现域环境 (Kerberos/LDAP/SMB/AD 相关端口或服务)
   → 调用 /ad-attack 进入域渗透全链路

9. 发现容器化环境 (K8s ServiceAccount Token/kubelet/Docker socket)
   → 调用 /k8s-attack 进行集群渗透

10. 目标完全不出网 (无 DNS/HTTP/ICMP 出站)
   → 调用 /no-outbound 切换不出网利用模式 (内存马/时间盲注/隧道)

11. 单个漏洞无法直接利用
   → 调用 /chain-attack 组合利用

12. 发现 VPN/网络设备 (Pulse Secure/Fortinet/Citrix/F5/Cisco/SonicWall/PaloAlto)
   → 调用 @network-device.md 进行设备漏洞利用

输出格式:
  排序 | 目标URL | 攻击类型 | 建议skill | 置信度 | 预期等级
  1    | http://test.x.com | ThinkPHP RCE | web-exploit P1 + P3 | high | 严重
  2    | http://api.x.com/upload | 文件上传绕过 | /web-exploit | medium | 高危
  3    | http://admin.x.com | 弱口令+越权 | /web-exploit | low | 中危

==排序规则: 置信度 × 严重程度。high+严重 > high+高危 > medium+严重 > medium+高危 > low+任意。置信度相同的按预期等级排列。攻击路径排完后，在 confidence=low 的行加 ⚠ 标记"需先手工确认"。==

### 下游交接规范

==步骤 9 路由到下游 skill 时，下游 skill 的 agent 应先读下表指定的文件确认前置条件满足，不要盲目开始。==

| 路由目标 | 读取文件 | 关键字段 |
|---------|---------|---------|
| `/web-exploit` | `targets/{id}.json` | `id, url, port, framework, server, cdn, waf, endpoints, info_leaks, auth, attack_status` |
| `/brute-force` | `targets/{id}.json` | `auth`（登录URL/参数/用户名线索/锁定策略）, `attack_status` |
| `/cloud-attack` | `targets/{id}.json`, `recon/ports.json` | `info_leaks`（AK-SK/OSS/IMDS 发现）, `ports`（云服务端口 80/443 外的其他云 API 端口） |
| `/ad-attack` | `targets/{id}.json`, `recon/ports.json` | `ports`（88 Kerberos/389 LDAP/445 SMB/636 LDAPS/3268 GC）, `dns`（域后缀线索） |
| `/k8s-attack` | `targets/{id}.json` | `info_leaks`（kubelet/etcd/SA token）, `ports`（10250/2379/6443/10255） |
| `/no-outbound` | `targets/{id}.json`, `recon/ports.json` | `network`（出站限制确认）, `info_leaks`, `framework`（用于选择不出网利用链） |
| `/waf-bypass` | `targets/{id}.json` | `waf`（类型/拦截特征）, `url` |
| `/chain-attack` | `targets/{id}.json` | `attack_status`（所有搁置路径及其状态）, `info_leaks`, `endpoints` |
| VPN/网络设备 | `targets/{id}.json`, `@network-device.md` | `url`, `server`（设备型号/版本）, `ports`（443/8443/10443 等管理端口） |

==读取示例：进入 brute-force 前，Read targets/{id}.json → 搜索 "auth" 字段 → 有用户名线索 + 无锁定策略才启动 hydra，否则跳过。==

---

## 增量侦察（exploit 回流）

==exploit 阶段发现新攻击面时，不是重跑全流程，只补侦察新增部分。==

```
触发场景 → 处理:
  响应/JS 中发现新子域名 → 追加到 subdomains.txt → httpx 探测该域名 → 补 target 文件
  报错泄露内部 IP/端口 → 追加到 targets/{id}.json info_leaks → 评估是否需要 nmap 补扫
  JS 中发现隐藏 API 端点 → 追加到 endpoints.no_auth → api_probe.py 定向探测
  遇到新端口/新服务 → 追加到 ports.json → 指纹识别 + 逐端口深入
  发现凭据/密钥 → 立即写 credentials/found.json → 追加 timeline
```

流程：
1. 写回对应字段（不创建新 target 文件，追加到已有）
2. 只跑相关脚本（如新端点 → api_probe.py，新子域名 → httpx）
3. 同步更新 `validate_target.py` 检查结果
4. 追加 timeline 记录回流触发原因

---

## 并行执行策略

### SRC 模式并行组

```
并行组 S1（零依赖，立即启动）:
  Job 1: subfinder -d $DOMAIN -all
  Job 2: amass enum -passive -d $DOMAIN
  Job 3: crt.sh 存文件查询
  Job 4: FOFA API 查询（如有 key）
  Job 5: Hunter API 查询（如有 key）
  Job 6: DNS 爆破扩展字典
  Job 7: WHOIS / ASN 查询

并行组 S2（等 S1 合并去重后）:
  Job 1: httpx 批量探活
  Job 2: 通配符 DNS 过滤

并行组 S3（等 httpx 完成后）:
  Job 1: 智能筛选 + 分级
  Job 2: 子域名接管检查（nuclei takeover 模板）
  Job 3: CDN 统计

并行组 S4（等筛选完成后）:
  Job 1-N: nuclei 分块并行扫描
  Job N+1: CORS 批量检测
  Job N+2: 信息泄露批量探测（P1 目标）
  Job N+3: 目录爆破（P1 目标 top 30）
  Job N+4: SRC 端口扫描（P1 目标高价值端口）

并行组 S5（升级）:
  对每个触发条件的高价值目标 → fork RedTeam 流水线
```

### RedTeam 模式并行组

==按风险递增排列。被动/轻度先行，重度扫描最后。每组完成后确认目标未异常再进下组。==

```
并行组 R1（零风险，立即启动 — 被动分析）:
  Job 1: SSL 证书分析 (openssl s_client)
  Job 2: DNS/WHOIS 查询
  Job 3: 已知页面 HTML 提取 JS 文件列表
  Job 4: 响应头分析 (curl -skI，单次请求)
  Job 5: WAF 指纹识别 (wafw00f + HPP 参数行为差异探测 → 判断 WAF 类型和后端解析器)
  Job 5b: TLS/SSL 审计 (testssl.sh / sslscan → 写入 recon/ssl_audit.json，检测弱密码套件)
  Job 6: GitHub/源码泄露搜索 (公司名/域名 + password/secret/token)
  Job 7: 邮箱收集 (theHarvester / hunter.io → 写入 recon/emails.json → 供 /phishing-evasion 使用)
  Job 7b: SMTP 服务探测 (端口 25/465/587 → VRFY 用户枚举 + SPF/DKIM/DMARC 分析 → 见 reference/smtp-exploitation.md)
  Job 8: Wayback Machine 历史 URL (已删除路径/旧 API/泄露配置)
  Job 8b: APP/APK 分析 (如目标有移动应用 → 见 reference/mobile-app-analysis.md)

并行组 R2（低风险 — 正常浏览器行为级别）:
  Job 1: JS 情报提取（传统站点 grep / SPA 站点用 playwright_crawler.py 动态爬取）
  Job 2: 常见信息泄露路径探测（leak_probe.py，curl 级别）
  Job 3: 登录接口认证机制分析 + 锁定策略探测(1次)
  Job 4: OSS 存储桶探测（从域名/公司名/JS中推测桶名，检测未授权）
  Job 5: Virtual Host 枚举（同 IP 不同 Host header，发现隐藏应用）
  Job 6: API 文档发现 (/swagger.json, /openapi.yaml, /v2/api-docs, /graphql introspection, /services/, /dwr/, *.hessian)
  Job 7: 敏感信息深度扫描（sensitive_scanner.py 扫 JS/泄露文件，找 AK/SK/Token/密码）

并行组 R3（中风险 — 轻度主动探测）:
  Job 1: 已知端口指纹识别 (whatweb)
  Job 2: nuclei 信息收集模板 (tags: tech,exposure,config —— 不含攻击payload)
  Job 3: 目录爆破低并发 (ffuf -t 10)

并行组 R4（高风险 — 确认目标扛得住再执行）:
  前置: R1-R3 全部完成，且目标未出现连接拒绝/超时/封禁迹象
  Job 1: 高价值端口扫描 (nmap 常用端口，--min-rate 500 -T3)
  Job 2: C 段扫描（如有必要）

并行组 R5（最高风险 — 可选，视情况决定）:
  前置: R4 完成，目标仍正常响应
  Job 1: 全端口扫描 (nmap -p- --min-rate 500 -T3)
  Job 2: 服务识别 (nmap -sV -sC 仅针对已发现端口)

并行组 R6（汇总）:
  Job 1: 多端口差异对比矩阵（如有多端口）
  Job 2: 侦察结果汇总 → 生成 targets/*.json
```

==R5 全端口扫描是可选的。如果 R1-R4 已经获得足够攻击面（JS 泄露 API、信息泄露、登录接口），可以跳过 R5 直接进 Phase 2。宁可少发现一个端口，也不要被封。==

### 并行检查清单

每个并行组完成后追加 `timeline.jsonl`：

```
SRC 模式:
[ ] S1 完成 → "子域名枚举完成, 共 N 个"
[ ] S2 完成 → "httpx 探活完成, 存活 M 个"
[ ] S3 完成 → "智能筛选完成, P1=X P2=Y"
[ ] S4 完成 → "批量扫描完成, nuclei 命中 N 条"
[ ] S5 完成 → "高价值目标深度侦察完成"

RedTeam 模式:
[ ] R1 完成 → "被动分析完成: SSL证书/DNS/JS列表/响应头"
[ ] R2 完成 → "轻度探测完成: JS深入分析/信息泄露/登录机制"
[ ] R3 完成 → "中度探测完成: 指纹/nuclei信息收集/目录爆破"
[ ] R4 完成 → "端口扫描完成(常用端口), N 个开放"
[ ] R5 完成(可选) → "全端口扫描完成" 或 "跳过(已有足够攻击面)"
[ ] R6 完成 → "侦察汇总, targets/*.json 已生成"
```

---

## 数据输出规范

==recon 的输出写入 `$OUTDIR/` 下的分文件，不再使用单一 target_profile.json。详见 @environment.md「步骤 4：工作目录初始化」。==

### recon 写入的文件

| 文件 | 内容 | 写入时机 |
|------|------|---------|
| `recon/nmap.gnmap` | nmap 原始输出 | 全端口扫描完成后 |
| `recon/ports.json` | 端口+服务摘要（解析自nmap） | 扫描完成后 |
| `recon/subdomains.txt` | 子域名列表（SRC模式） | 枚举合并后 |
| `recon/httpx.jsonl` | httpx 批量探活结果 | 探活完成后 |
| `recon/priority.json` | P1/P2/P3 分级（SRC模式） | 筛选完成后 |
| `recon/emails.json` | 收集到的邮箱列表（见下方格式定义） | R1 Job 7 完成后 |
| `recon/raw/*` | nuclei/ffuf/whatweb 原始输出 | 各工具完成后 |
| `targets/{id}.json` | 每个攻击目标的完整侦察汇总 | 侦察汇总步骤 |
| `timeline.jsonl` | 追加操作记录 | 每个关键步骤后 |

### emails.json 格式

==供 /phishing-evasion 使用，收集自 theHarvester/hunter.io/网页抓取/WHOIS。==

```json
{
  "_note": "recon/emails.json — RedTeam R1 Job 7 产出",
  "collected_at": "2026-05-27T10:00:00Z",
  "sources": ["theHarvester", "hunter.io", "web_scrape", "whois"],
  "entries": [
    {
      "email": "zhangsan@target.com",
      "name": "张三",
      "role": "IT管理员",
      "source": "theHarvester",
      "confidence": "high",
      "validated": false,
      "notes": "LinkedIn 确认此人仍在职"
    }
  ],
  "stats": {
    "total": 42,
    "by_source": {"theHarvester": 20, "web_scrape": 15, "whois": 7},
    "validated": 0,
    "unique_domains": ["target.com"]
  }
}
```

字段说明:
- `confidence`: high(多源交叉验证) / medium(单源但格式匹配) / low(仅模式推测)
- `validated`: 是否已验证邮箱存在（VRFY/RCPT TO/注册接口差异检测）
- `role`: 用于钓鱼精准化——IT管理员→技术类诱饵，财务→发票类诱饵

### target 文件结构

每个 `targets/{id}.json` 是一个攻击目标的全部上下文：

```json
{
  "id": "{ip}_{port}_{app}",
  "url": "https://x.x.x.x:port/path/",
  "port": 7282,
  "app_name": "应用名称",
  "framework": "框架+版本",
  "server": "Web服务器",
  "priority": "P1",
  "_priority_note": "recon的P1-P4是资产分级(目标价值)。web-exploit的P0-P9是攻击优先级(利用顺序)。两者共存于同一JSON但语义不同——P1资产上可能跑P0-P9所有攻击。",
  "confidence": "high",
  "_confidence_note": "high=有明确版本+CVE匹配/可直接利用 | medium=有特征但需验证 | low=仅推测可能存在。step 9 按 confidence×priority 排序攻击路径。",
  "cdn": false,
  "waf": "none|类型",

  "auth": {
    "type": "认证方式描述",
    "login_url": "/login",
    "lockout": {"threshold": 0, "cooldown_sec": 0},
    "known_users": []
  },

  "endpoints": {
    "no_auth": [],
    "need_auth": [],
    "error_leaks": []
  },

  "info_leaks": [
    {"type": "描述", "evidence": "具体数据"}
  ],

  "js_intel": {
    "files": [],
    "api_prefixes": {},
    "crypto_algo": "",
    "hardcoded": []
  },

  "rate_profile": {
    "max_concurrent": 30,
    "delay": 0.1,
    "ban_duration_sec": 0
  },

  "dns": {
    "domain_suffix": "", "cname_records": [], "wildcard_ip": ""
  },

  "network": {
    "outbound_dns": true, "outbound_http": true, "outbound_icmp": false,
    "egress_ports": [80,443], "vpn_present": false
  },

  "attack_status": {
    "P0_unauth_api":    {"status": "pending", "result": ""},
    "P0_info_leak":     {"status": "pending", "result": ""},
    "P1_cve":           {"status": "pending", "result": ""},
    "P2_cors":          {"status": "pending", "result": ""},
    "P3_injection":     {"status": "pending", "result": ""},
    "P3_method_abuse":  {"status": "pending", "result": ""},
    "P3_ssrf":          {"status": "pending", "result": ""},
    "P3_jwt":           {"status": "pending", "result": ""},
    "P3_openredirect":  {"status": "pending", "result": ""},
    "P3.6_oauth_saml":  {"status": "pending", "result": ""},
    "P3.7_session":     {"status": "pending", "result": ""},
    "P3.8_protocol":    {"status": "pending", "result": ""},
    "P3_idor":          {"status": "pending", "result": ""},
    "P4_upload_lfi":    {"status": "pending", "result": ""},
    "P5_xss_client":    {"status": "pending", "result": ""},
    "P5_race":          {"status": "pending", "result": ""},
    "P6_brute":         {"status": "pending", "result": ""},
    "P7_port_services": {"status": "pending", "result": ""},
    "P8_biz_logic":     {"status": "pending", "result": ""},
    "P9_supply_chain":  {"status": "pending", "result": ""},

    "_optional": {
      "note": "以下仅当侦察发现对应技术栈时才添加入口，否则标记为 skipped",
      "graphql":    {"status": "pending", "result": ""},
      "websocket":  {"status": "pending", "result": ""},
      "prototype_pollution": {"status": "pending", "result": ""},
      "cache_attack": {"status": "pending", "result": ""},
      "subdomain_takeover": {"status": "pending", "result": ""}
    }
  }
}
```

**attack_status 状态语义：**

| 状态 | 含义 |
|------|------|
| `pending` | 未开始 |
| `in_progress` | 正在测 |
| `done` | 测试完成，无发现 |
| `found` | 确认漏洞（写 vulns/） |
| `blocked` | 被 WAF/锁定等阻断 |
| `skipped` | 不适用此目标（如无登录入口则 P6=skipped） |
| `incomplete` | 只测了部分（如 P3 只测了 SQLi 未测 SSTI/XXE） |

==切换目标前检查: 是否有 pending 的项？是否有 incomplete 的项需要补全？==

### 命名规则

```
RedTeam: {ip}_{port}_{path-slug}.json
  例: 61.189.194.159_7282_TheNextWebApp.json

SRC: {subdomain}.json
  例: test.example.com.json
```

### recon 汇总步骤

==侦察完成时，将散落的发现归类写入对应 target 文件。这是 recon 的收尾动作。==

```
1. 识别目标上的独立应用（按路径前缀/子域名区分）
2. 为每个应用创建 targets/{id}.json
3. 将端口信息、指纹、信息泄露、JS分析、认证机制等写入对应文件
4. 更新 meta.json phase=2
5. 追加 timeline: recon_summary done
```

### 证据采集

==漏洞确认后进行人工复测时采集，按 @environment.md「证据采集」操作。探测阶段不必每个发现都截图。==

### 各 skill 读写边界

```
/recon 写入:    recon/*, targets/*.json, timeline.jsonl
/web-exploit 读: targets/*.json, recon/priority.json → 写入 vulns/*

/report 读:     全部文件 → 生成报告
/bsrc 读写:     与 recon 相同，额外遵守 SRC 规则
```

---

## 知识库路由

| 场景 | KB 路径 | 关键内容 |
|------|---------|---------|
| 子域名枚举 | `01-信息收集/外网/子域名.md` | 子域名收集方法论和工具链 |
| 绕过 CDN 找真实 IP | `01-信息收集/外网/绕过cdn找真实ip.md` | 历史DNS/邮件头/证书/Shodan |
| 敏感信息收集 | `01-信息收集/外网/敏感信息收集.md` | .env/备份文件/源码泄露 |
| 目录扫描 | `01-信息收集/外网/目录扫描.md` | 字典选择/递归深度/状态码解读 |
| 指纹识别 | `06-工具与命令/外围打点/指纹识别工具.md` | whatweb/wappalyzer/EHole 对比 |
| 在线工具 | `01-信息收集/外网/在线收集工具速查.md` | crt.sh/SecurityTrails/Shodan/FOFA |
| 空间搜索引擎 | `01-信息收集/外网/在线收集工具速查.md` | FOFA/Hunter/Quake 语法速查 |
| 边缘资产探测 | `01-信息收集/外网/边缘资产探测.md` | 非标端口/忘记关掉的测试服务 |
| OSINT | `01-信息收集/OSINT与社工/` | 搜索引擎语法/社交网络 |
| 信息收集速查 | `01-信息收集/外网/信息收集速查.md` | 全流程 checklist |
| 信息收集高级技巧 | **内置**: `reference/external-recon-advanced.md` | CDN绕过深度/F5解码/Hosts碰撞/供应链/GitHub搜索/JS提取/工具矩阵 |
| 漏洞库查询 | `01-信息收集/外网/漏洞库.md` | CVE/CNNVD/Exploit-DB |
| 敏感信息提取规则 | **内置**: `reference/sensitive-info-patterns.md` | 100+ 条正则：云AK/微信/凭据/存储桶/个人信息/SQL错误 |

不可用时，使用本 skill 内置流程。

---

## 脚本工具清单（Agent 可直接调用）

==以下脚本位于 `${CLAUDE_SKILL_DIR}/scripts/`，数据文件位于 `${CLAUDE_SKILL_DIR}/data/`。所有脚本都有无依赖的纯 bash/curl 降级方案。==

### 被动分析类（R1-R2 阶段，单次 HTTP 请求级）

**1. `finger_match.py` — 指纹识别**

```
用途: 对 URL 做 CMS/产品指纹匹配（33K 规则）
数据: fingerprints_merged_v5.json
用法: python3 finger_match.py <url>
       python3 finger_match.py -l urls.txt
       python3 finger_match.py -f custom.json --min-level L1 <url>
       python3 finger_match.py --category OA,Security <url>
输出: [FINGER] URL | 产品名 | 匹配方法 | 级别 | 分类 → POC目录
触发: 步骤 5.5-A（httpx完成后对所有存活URL）
降级: curl -sk <url> | grep -iE "关键字1|关键字2"  # whatweb/wappalyzer 特征匹配
      或 whatweb -a 3 <url>  # Kali 自带
```

**2. `passive_tag.py` — 被动攻击面标记**

```
用途: 用 yakit MITM 规则（60条正则）扫描 HTTP 响应，标记注入参数/泄露/攻击入口
数据: yakit_rules.json
用法: python3 passive_tag.py <url>
       python3 passive_tag.py -l urls.txt
       python3 passive_tag.py -r custom_rules.json <url>
输出: [TAG] URL | 标签名 | 位置(request/response/header/body) | 匹配片段 → 下一步action
触发: 步骤 5.5-B（httpx完成后对所有存活URL）
降级: curl -sk <url> | grep -iP "accesskey|secret|password|token|jdbc:|ssh-rsa"
       # 按 reference/sensitive-info-patterns.md 的正则逐条 grep
```

**3. `sensitive_scanner.py` — 敏感信息深度扫描**

```
用途: 对单个 URL/JS文件/本地文件做敏感信息扫描（48条规则，6大类）
      每条规则含 description/risk_analysis/fp_note，为 AI 研判设计
数据: sensitive_rules.json
用法: python3 sensitive_scanner.py -u https://target.com/app.js
       python3 sensitive_scanner.py -f bundle.js
       python3 sensitive_scanner.py -r https://target.com/api --header "Authorization: Bearer xxx"
       python3 sensitive_scanner.py -l urls.txt --min-severity high --category 凭据泄露
输出: 匹配规则/严重级别/匹配内容/AI 研判提示（误报场景标注）
触发: 步骤 12R-b 后（JS 文件下载后），步骤 3d（源码泄露发现后）
降级: grep -iPE "$(cat reference/sensitive-info-patterns.md | grep '正则' -A1)" file.js
```

### 主动探测类（R2-R3 阶段，批量请求级）

**4. `leak_probe.py` — 信息泄露路径探测**

```
用途: 对 URL 列表探测敏感路径（19条规则），含 SPA 假阳性过滤 + body 关键字校验
      内置: /.git/HEAD, /.env, /actuator/*, /druid/*, /swagger*, /nacos/, /debug 等
用法: python3 leak_probe.py /tmp/urls_p1.txt
输出: [LEAK] 状态码 URL (大小) | 描述
触发: 步骤 7d（SRC批量），步骤 8R（RedTeam逐端口深入）
降级: for path in /.git/HEAD /.env /actuator ...; do
        HASH=$(curl -sk http://TARGET/ | md5sum)
        RESP=$(curl -sk http://TARGET$path)
        [ "$(echo $RESP|md5sum)" != "$HASH" ] && echo "[200] $path"
      done
      注意: 降级方案缺少 body 关键字校验，需人工确认非 SPA 假阳性
```

**5. `cors_check.py` — CORS 配置检测**

```
用途: 对 URL 列表做 CORS 检测（含 OPTIONS 预检 + SameSite + 浏览器可利用性判定）
用法: python3 cors_check.py /tmp/urls.txt
输出: 每个 URL 的 CORS 头配置 + 可利用性级别
触发: 步骤 7c（SRC批量，P1+P2目标）
降级: curl -sk -H "Origin: https://evil.com" -I <url> | grep -i "access-control"
       curl -sk -X OPTIONS -H "Origin: https://evil.com" -I <url> | grep -i "access-control"
```

**6. `api_probe.py` — API 端点批量探测**

```
用途: 对端点列表同时测 GET/POST，输出状态码 + 响应摘要 + 高亮标记
      内置字典: common（56条常用路径）、sensitive（36条敏感路径）、all（212K全量路径）
用法: python3 api_probe.py https://target.com /tmp/endpoints.txt
       python3 api_probe.py https://target.com --dict common
       python3 api_probe.py https://target.com -e '/api/user,/api/login'
       python3 api_probe.py https://target.com /tmp/endpoints.txt --token "Bearer xxx"
输出: 表格形式，每行 GET/POST 状态码 + 响应摘要
触发: 步骤 7g（SRC 批量），步骤 12R-api-c（RedTeam 5来源聚合后）
降级: while read ep; do
        echo "$ep | $(curl -sk -o /dev/null -w '%{http_code}' http://TARGET$ep) | \
              $(curl -sk -X POST -o /dev/null -w '%{http_code}' http://TARGET$ep)"
      done < endpoints.txt
```

**7. `openredirect_probe.py` — 开放重定向检测**

```
用途: 对含 redirect/next/return 参数的 URL 做重定向反射检测
用法: python3 openredirect_probe.py -u https://target.com/login?redirect=/home -p redirect,next
       python3 openredirect_probe.py -f urls_with_params.txt --callback https://evil.com
输出: 每个参数的重定向类型 + 危险程度
触发: web-exploit P3.3 阶段（发现重定向参数时）
降级: curl -skI "https://target.com/page?redirect=https://evil.com" | grep -i "^location"
```

**8. `ssrf_probe.py` — SSRF 回调检测**

```
用途: 对含 URL/地址类参数的端点做 SSRF 回调验证
用法: python3 ssrf_probe.py -u https://target.com/api/fetch -p url,image_url --callback http://YOUR_SERVER
       python3 ssrf_probe.py -f urls_with_params.txt --callback http://bsrc-ssrf.n.baidu-int.com/UID
输出: 每个参数的回显类型 + 置信度
触发: web-exploit P3.5 阶段（发现 URL 参数时）
降级: curl -sk "https://target.com/api?url=http://YOUR_CALLBACK_SERVER/$(date +%s)"
       # 手工检查回调服务器日志
```

**9. `jwt_probe.py` — JWT 分析**

```
用途: 封装 jwt_tool 标准 Playbook，逐个检测 JWT：算法、弱密钥、kid 注入等
依赖: Kali 上的 jwt_tool（/usr/bin/jwt_tool 或 pip install jwt_tool）
用法: python3 jwt_probe.py /tmp/jwts.txt
       python3 jwt_probe.py -t eyJhbGciOiJIUzI1NiIs...
       python3 jwt_probe.py -f jwts.txt --wordlist rockyou_top100.txt
输出: 每个 JWT 的检测结果 + 可利用性判定（算法混淆/空签名/弱密钥/kid注入）
触发: web-exploit P3.7 阶段（发现 JWT 时）
降级: jwt_tool <token> --playbook standard  # 直接在 Kali 上跑
      或手动: echo <token> | cut -d'.' -f2 | base64 -d  # 看 payload 结构
```

### 动态渲染类（SPA 站点专用）

**10. `playwright_crawler.py` — JS 渲染爬虫**

```
用途: Playwright 无头浏览器渲染 SPA，拦截 XHR/fetch 请求，提取 API/表单/带参URL
      发现量通常是静态 grep 的 3-10 倍
依赖: pip install playwright && playwright install chromium
用法: python3 playwright_crawler.py https://target.com
       python3 playwright_crawler.py -l urls.txt -o results.json
       python3 playwright_crawler.py --no-headless https://target.com  # 调试
输出: [FORM] 表单/字段 | [API] JS端点 | [PARAM] 带参URL | 完整 JSON
触发: 步骤 12R-b（SPA 站点，路由含 #/ 或 history API）
      步骤 8R-extra 登录接口侦察（分析前端加密逻辑）
降级: katana -u https://target.com -headless  # Kali 替代
      或 curl -sk https://target.com | grep -oP '(?<=src=")[^"]*\.js' | while read js; do
        curl -sk "$js" | grep -oP '"(/api/[^"]+)"'
      done
```

### 批量处理/代理类

**11. `mitm_plugin.py` — mitmproxy 被动扫描插件**

```
用途: mitmproxy 插件，对经过代理的所有 HTTP 流量自动扫描（yakit规则+指纹匹配）
      输出 mitm_tags.jsonl / mitm_fingers.jsonl / mitm_flows.jsonl
用法: mitmdump -p 8888 -s mitm_plugin.py --set flow_detail=0
      启动后 agent 的 python requests 设置 proxies 指向 127.0.0.1:8888
触发: 步骤 5.5（可选，需要 Windows 本机 mitmproxy）
降级: 不需要。passive_tag.py + finger_match.py 的效果等价（主动fetch而非被动代理）
```

### 分析/筛选类（httpx 后处理）

**12. `priority_filter.py` — 智能分级 P1-P4**

```
用途: 从 httpx JSONL 输出中按规则自动分级（host特征/状态码/技术栈/CDN）
用法: python3 priority_filter.py /tmp/httpx.jsonl -o /tmp/priority.json
输出: priority.json 含 P1/P2/P3/P4 分组列表 + 分级依据
触发: 步骤 6（httpx完成后）
降级: 手工规则匹配（grep host含test/dev/admin → P1; 非CDN+非标端口 → P2; 其余 → P3）
      # SPA fallback: grep -E "200|301|302" /tmp/httpx_alive.txt | grep -v "cdn"
```

### 工具/辅助类

**13. `timeline.py` — 操作时间线追加**

```
用途: 统一格式写入 timeline.jsonl（自动补时间戳）
用法: python3 timeline.py --phase recon --action "subfinder done" --result "200 subs" --target example.com
       python3 timeline.py --phase exploit --action "P1 CVE check done" --status blocked
输出: 追加一行到 $OUTDIR/timeline.jsonl
触发: 每个关键步骤完成后
降级: echo '{"time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","phase":"recon","action":"desc","result":"ok"}' >> timeline.jsonl
```

**14. `validate_target.py` — target 文件完整性校验**

```
用途: 进入 web-exploit 前校验 target.json 必填字段是否缺失
用法: python3 validate_target.py $OUTDIR/targets/ace.baidu.com.json
       python3 validate_target.py $OUTDIR/targets/ --all
输出: 通过/缺失/告警三级，按攻击优先级标注影响
触发: 步骤 9（侦察汇总后，生成攻击路径建议前）
降级: 手工检查 target.json 是否包含: id/url/port/framework/server/cdn/waf/endpoints/info_leaks/auth
```

**15. `webpack_extract.py` — Webpack 源码还原**

```
用途: 从网站的 Webpack 打包 JS 中提取模块、恢复源码结构
      支持 webpackJsonp 格式和模块化打包格式
用法: python3 webpack_extract.py https://target.com/app.js -o /tmp/webpack_output/
       python3 webpack_extract.py -f bundle.js --format tree  # 只输出模块树
       python3 webpack_extract.py https://target.com/ --recursive  # 从HTML发现所有JS入口
输出: 解包后的模块文件 + 目录树 + 模块依赖图
触发: JS 分析中发现 webpackJsonp / __webpack_require__ / chunk 模式时
降级: grep -oP '"[a-zA-Z0-9_/.-]+":"[^"]*"' bundle.js | head -50  # 手动提取模块名-路径映射
      或 source-map-unpacker（如果存在 .map 文件）
```

### 脚本执行策略

```
脚本可用时:     python3 ${CLAUDE_SKILL_DIR}/scripts/<script>.py [args]
脚本不可用时:   使用上面每个脚本的"降级"方法（纯 bash/curl/grep）
混合模式:       Kali 上优先用脚本；Windows 本机无 python 时用降级 bash
```

### 数据文件对照

| 脚本 | 依赖数据文件 | 文件大小/规模 |
|------|------------|-------------|
| finger_match.py | `fingerprints_merged_v5.json` | 33,107 条指纹 |
| passive_tag.py | `yakit_rules.json` | 60 条 MITM 正则 |
| sensitive_scanner.py | `sensitive_rules.json` | 48 条规则, 6 大类 |
| api_probe.py | `dict_merged_paths.json` (--dict all) | 212,000 条路径 |
| leak_probe.py | 无（规则硬编码在脚本内） | 19 条路径规则 |
| priority_filter.py | 无（规则硬编码在脚本内） | — |
| 其余脚本 | 无外部数据依赖 | — |

### 其他数据文件（未被脚本直接引用，可供手工/ffuf/nuclei 使用）

| 文件 | 用途 |
|------|------|
| `dict_merged_subdomains.json` | 子域名爆破字典（脚本使用） |
| `dict_merged_subdomains.txt` | 子域名爆破字典（ffuf/subfinder 等外部工具） |
| `dict_merged_paths.json` | 路径爆破字典（api_probe.py --dict all） |
| `dict_merged_paths.txt` | 路径爆破字典（ffuf/gobuster 等外部工具） |
| `dict_merged_keywords.json` | 敏感关键词字典 |
| `dict_upload_extensions.json` | 文件上传后缀字典 |
| `dict_js_fuzzpath.json` | JS 模糊路径字典 |
| `dict_risky_params.json` | 高风险参数名字典 |
| `dict_sensitive_regex_urlfinder.json` | 敏感 URL 正则规则 |
| `findsomething_rules.json` | FindSomething 浏览器插件规则（JS 敏感信息提取） |
| `phpggc_chains.json` | PHPGGC 反序列化链索引 |
| `bbscan_paths.json` | BBScan 扫描路径字典 |
| `oneforall_data.json` | OneForAll 子域名收集辅助数据 |

> 完整数据文件说明见 `reference/tools-ecosystem.md`