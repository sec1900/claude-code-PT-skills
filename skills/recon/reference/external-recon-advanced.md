# 信息收集高级技巧

> 补充 recon SKILL.md 基础流程之外的高级收集技术。覆盖 CDN 绕过深度技巧、Hosts 碰撞、公司名→产品/APP/供应链发现、GitHub 泄露搜索、JS 信息提取、指纹识别工具链。

## 一、CDN 绕过找真实 IP（深度技巧）

基础方法（多地 ping、子域名 IP、DNS 历史）已在 recon SKILL.md 中覆盖。以下为高级技巧。

### 1.1 MX 记录泄露真实 IP

```
原理：如果目标网站与邮件服务部署在同一台服务器，MX 记录会直接暴露真实 IP。

查询方法：
  dig MX target.com
  nslookup -type=MX target.com
  host -t MX target.com

获取 MX 记录中的邮件服务器域名 → 解析其 A 记录 → 可能是真实 IP
如果该 IP 直接访问 80/443 返回目标网站内容 → 确认真实 IP
```

### 1.2 SSL 证书指纹搜索（Censys）

```
原理：直接访问真实 IP 的 443 端口时，SSL 证书会暴露。
     即使有 CDN 保护，真实 IP 的 SSL 证书 SHA1 指纹不变。
     将指纹放入 Censys 搜索 → 找到所有使用该证书的 IP。

步骤：
  1. openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -fingerprint -sha1
     → 得到 SHA1 指纹（如：AB:CD:EF:...）
  2. 去掉冒号后粘贴到 Censys IPv4 搜索
     → 找到所有使用该证书的 IP 列表
  3. 逐一验证：https://IP:443 → 看是否直接显示目标网站

也可用 crt.sh 的证书透明度日志：
  https://crt.sh/?q=%.target.com
  → 查找最早的证书记录（可能在 CDN 启用之前）
```

### 1.3 DNS 历史记录深度查询

```
工具链：
  SecurityTrails: https://securitytrails.com/domain/target.com
    → 左侧菜单 "Historical Data" → 查看域名历史上绑定的所有 IP
    
  dnsdb.io: https://dnsdb.io/zh-cn/
    → 输入 "target.com" type:A
    → 列出域名历史上解析过的所有 IP
    
  ViewDNS.info: http://viewdns.info/
    → IP History 功能 → 查看域名 IP 变更历史

  Netcraft: http://toolbar.netcraft.com/site_report?url=target.com
    → 查看网站托管历史记录

  ipip.net CDN检测: https://tools.ipip.net/cdn.php
    → 输入域名 → 判断 CDN 类型 + 可能的历史 IP

  threatbook.cn (微步在线): https://x.threatbook.cn/
    → 查询域名 → 情报标签页 → 历史解析记录
```

### 1.4 F5 LTM 解码找真实 IP

```
原理：F5 BIG-IP LTM 负载均衡会在 Set-Cookie 中嵌入真实 IP 的编码。

特征 Cookie：
  Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000

解码步骤：
  1. 取 Cookie 值的第一节数字（小数点前）：487098378
  2. 转为十六进制：487098378 → 0x1D08880A
  3. 从后往前，每两位取一段：0A . 88 . 08 . 1D
  4. 每段十六进制转十进制：10 . 136 . 8 . 29
  5. 得到真实 IP：10.136.8.29

快速解码（Python）：
  import struct, socket
  cookie = "487098378.24095.0000"
  encoded = int(cookie.split(".")[0])
  ip = socket.inet_ntoa(struct.pack(">I", encoded))
  print(ip)
```

### 1.5 Hosts 碰撞（隐藏域名发现）

```
原理：很多内网系统配置了"禁止 IP 直接访问"（直接访问 IP 返回 401/403/404/500），
     必须用正确的 Host 头才能正常访问。
     当目标删除了域名的 A 记录但反向代理配置未更新时 → 域名解析失效但服务仍存活。
     用收集到的域名 + IP 段组合 → 在 HTTP 请求中指定 Host 头 → 发现隐藏资产。

场景：
  - IP 直接访问 → 401/403/404/500（看起来像死资产）
  - 域名绑定 Hosts → 返回正常业务系统（实际是活的）

碰撞流程：
  1. 收集目标的所有域名（包括历史域名、已过期域名）
  2. 收集目标资产的所有 IP 段（历史解析 IP + C 段）
  3. 以 [域名] × [IP] 组合，发送 HTTP 请求时指定 Host 头
  4. 比较每个请求的响应：title、响应大小、状态码
  5. 发现异常 → 手动验证

工具：
  参考: https://github.com/fofapro/Hosts_scan (Go 实现的 Hosts 碰撞工具)

IP 来源：
  - 目标域名历史解析 IP（site.ip138.com / ipchaxun.com）
  - C 段 IP
  - 目标备案信息中的 IP

域名来源：
  - 子域名枚举结果
  - 历史域名
  - 已过期的域名（DNS 记录已删除但服务可能仍在运行）
```

---

## 二、公司名称 → 深层资产发现

recon SKILL.md 已覆盖：公司名 → 域名（爱企查/天眼查）。以下为更多维度。

### 2.1 产品与 APP 发现

```
小蓝本 (https://sou.xiaolanben.com/):
  - 搜索公司名 → 查看 APP 列表（iOS/Android）
  - 查看商标信息
  - 查看媒体/新闻

爱企查 (https://aiqicha.baidu.com/):
  - 搜索公司名 → "知识产权" → "软件著作权"
  → 列出公司自主开发的软件/系统名称
  → 这些系统可能对应独立的 Web 系统或 API

天眼查 / 凤鸟:
  - 同上，功能类似，交叉验证
```

### 2.2 股权穿透 → 子公司发现

```
爱企查 → "股东信息"/"对外投资":
  - 查看持股比例 ≥50% 的子公司
  - 子公司域名可能使用相同的域后缀或完全独立的域名
  - 子公司的安全防护通常比母公司弱 → 优先目标

操作：
  1. 查目标公司 → 对外投资列表
  2. 筛选持股 >50% 的子公司
  3. 对每个子公司 → 回退到步骤 1（递归发现）
```

### 2.3 供应链/供应商分析

```
FOFA 搜索供应商标识:
  很多企业网站页脚写了技术支持公司名称
  → body="北京XX科技有限公司" 
  → 发现所有使用该产品的网站

应用场景：
  - 目标 A 的安全防护很强
  - 但目标 A 使用的 OA 系统是 B 公司开发的
  - B 公司的产品也可能部署在其他客户 C 处
  - C 的安全防护可能较弱 → 从 C 入手
  - 获取 B 产品的源码/漏洞 → 回到目标 A 利用

备案号追溯:
  ICP 备案号可以通过 FOFA 反查：
  body="京ICP备12345号"
  → 发现同一公司的所有备案域名
```

### 2.4 Google 产品手册搜索

```
搜索目标使用的产品/系统的手册：
  site:target.com filetype:pdf "手册" OR "操作手册" OR "用户手册"
  site:target.com filetype:pdf "admin" OR "管理员"
  "产品名称" "默认密码" OR "初始密码" OR "default password"
  
  → 可能泄露默认账号密码、系统架构、运维方式
```

---

## 三、GitHub 源码泄露深度搜索

recon SKILL.md 已有基础搜索，以下为系统化 Dork 模式。

### 3.1 邮箱 × 凭据组合

```
site:github.com smtp password @target.com
site:github.com smtp @target.com
site:github.com "smtp.target.com" password

# 数据库连接
site:github.com "jdbc:mysql://" "@target.com"
site:github.com "jdbc:postgresql://" "@target.com"
site:github.com "sa" password @target.com
site:github.com root password @target.com

# FTP 凭据
site:github.com ftp @target.com password

# SSH 密钥
site:github.com "-----BEGIN RSA PRIVATE KEY-----" @target.com
```

### 3.2 代码搜索关键词

```
site:github.com in:name <target>          # 仓库名含目标
site:github.com in:file <target>          # 文件名含目标

# 特定类型文件
site:github.com filename:".env" <target>
site:github.com filename:"config.php" <target>
site:github.com filename:"application.properties" <target>
site:github.com filename:"web.config" <target>
site:github.com filename:"credentials.json" <target>
site:github.com filename:"id_rsa" <target>
```

### 3.3 中文关键词搜索

```
site:github.com "密码" @target.com
site:github.com "内部" @target.com
site:github.com "测试" "账号" @target.com
site:github.com "运维" "密码" @target.com
```

---

## 四、JS 信息收集工具链

### 4.1 工具对比

| 工具 | 用途 | 特点 |
|------|------|------|
| **LinkFinder** | JS 中提取 URL/路径 | 命令行，支持离线分析，分析完整 JS |
| **JSFinder** | JS 中提取 URL/子域名 | LinkFinder 增强版，支持批量 |
| **FindSomething** | 浏览器插件被动提取 | 实时，不需手动操作，火狐/Chrome |

### 4.2 FindSomething（浏览器插件）

```
安装后无需配置，浏览器访问目标网站时自动：
  1. 从所有加载的 JS 文件中提取 URL/URI
  2. 从 JS 中提取疑似 API 端点
  3. 从页面响应中提取敏感信息（身份证/手机号/邮箱）
  4. 自动去重 → 在插件面板展示
```

### 4.3 JS 中的 exploit 模式

```
提取后关注：
  - 含 "/api/" 的路径 → API 端点
  - 含 "token"/"secret"/"key" → 硬编码凭据
  - 含 "admin"/"manage"/"dashboard" → 管理后台路径
  - 含 "test"/"debug"/"dev" → 测试环境
  - 含 "v1"/"v2"/"v3" → API 版本（老版本可能未维护、有漏洞）
```

---

## 五、指纹识别工具扩展

recon SKILL.md 已覆盖 whatweb/wappalyzer/EHole，以下为补充工具。

### 5.1 TideFinger（潮汐指纹）

```
在线平台: http://finger.tidesec.net/
开源项目: https://github.com/TideSec/TideFinger

特点：
  - 整合多个开源指纹库并重组
  - 支持 CMS / OA / 框架 / 中间件 / 路由器 等多维度指纹
  - 在线 + 离线双模式
```

### 5.2 FOFA icon_hash 搜索

```
原理：每个网站的 favicon.ico 有唯一的 hash 值，可用此搜索同类站点。

获取 icon_hash：
  1. 访问目标 /favicon.ico
  2. 用 FOFA 的 icon_hash 计算工具或 API
  3. FOFA 搜索: icon_hash="<hash值>"
  → 发现使用同一套系统的其他网站 / 子域名

应用：
  - 目标使用了某 CMS → 找同 CMS 的其他站点 → 已知漏洞测试
  - 目标有 CDN → 同 icon_hash 可能揭示未加 CDN 的子域
```

### 5.3 BBScan 批量信息泄露扫描

```
https://github.com/lijiejie/BBScan

特点：
  - 高并发、轻量级
  - 专门针对信息泄露（.git/.env/.svn/phpinfo/probe 等）
  - 适合对大批量 IP/域名做初筛
  - 不能替代目录扫描（dirsearch），但可以在 dirsearch 之前快速粗筛

使用场景：
  拿到大量 IP/域名 → BBScan 快速筛选 → 命中目标 → dirsearch 深度扫描
```

---

## 六、工具链完整对比

### 6.1 子域名枚举

| 工具 | 原理 | 特点 |
|------|------|------|
| SubDomainBrute | DNS 字典爆破 | 泛解析检查，速度快 |
| Sublist3r | 多引擎聚合（Google/Yahoo/crt.sh 等） | 覆盖面广 |
| OneForALL | 证书透明度 + 6 模块（censys/certspotter/crtsh/entrust/google/spyse） | 功能最全 |

### 6.2 目录扫描

| 工具 | 特点 |
|------|------|
| dirsearch | 最常用，支持自定义 UA/线程/字典，递归扫描 |
| 7kbscan | 功能全面（UA自定义/多线程/自定义字典），Web 界面 |
| dirb | 经典工具，递归式目录扫描，支持认证 |
| BBScan | 轻量级信息泄露扫描，适合批量初筛 |

### 6.3 端口扫描

| 工具 | 特点 | 适用场景 |
|------|------|---------|
| nmap | 最全面，准确率高，-sV 版本检测，-O 操作系统识别 | 精确扫描 |
| masscan | 速度比 nmap 快 10 倍，适合大规模网段 | 快速摸底 |
| FOFA | 资产测绘，不需主动发包 | 被动信息收集 |

### 6.4 指纹识别

| 工具 | 用途 | 特点 |
|------|------|------|
| wappalyzer | 浏览器插件 | 实时识别，逐个网站 |
| whatweb | 命令行 | 批量，-v 详细输出，JSON 格式 |
| TideFinger | 在线+离线 | 多源指纹库融合 |
| EHole | 资产识别+漏洞检测 | 支持 FOFA/Hunter 提取资产 |
| wafw00f | WAF 检测 | 识别 WAF 类型 |

---

## 七、按输入类型的收集路径

### 拿到域名

```
域名
  ├── CDN 检测 (ping / nslookup / 多地ping)
  │     ├── 有 CDN → 绕过找真实 IP
  │     │     ├── 子域名 IP（子域通常无 CDN）
  │     │     ├── DNS 历史记录 (SecurityTrails / dnsdb.io / threatbook)
  │     │     ├── MX 记录 → 邮件服务器 IP
  │     │     ├── SSL 证书指纹 → Censys 搜索
  │     │     ├── F5 LTM Cookie 解码
  │     │     └── 网站漏洞（phpinfo/SSRF/XSS盲打/GitHub泄露）
  │     └── 无 CDN → 直接得到 IP
  ├── 子域名收集
  │     ├── Google: site:target.com
  │     ├── FOFA: domain="target.com" / host="target.com" / icon_hash="hash"
  │     ├── 360Quake/Hunter/微步在线
  │     ├── 工具: SubDomainBrute / Sublist3r / OneForALL
  │     └── crt.sh 证书透明度
  └── Hosts 碰撞（域名 × IP 段 → 发现隐藏资产）
```

### 拿到 IP

```
IP
  ├── 端口扫描 (masscan 快速 + nmap 精确)
  ├── IP 反查域名 (SearchMap / ip138 / FOFA C 段)
  ├── C 段扫描 (nmap -sn / FOFA ip="x.x.x.x/24")
  ├── 旁站查询 (webscan.cc)
  └── 指纹识别 + 目录扫描
```

### 拿到公司名称

```
公司名称
  ├── 企业查询 (爱企查/天眼查/凤鸟)
  │     ├── 域名（主域名 + 更多网址）
  │     ├── 股权穿透（控股 ≥50% 的子公司 → 递归）
  │     ├── 产品发现（软件著作权 → 系统名称）
  │     └── 手机号/邮箱（HR/管理员联系方式）
  ├── APP/小程序 (小蓝本 / 爱企查知识产权)
  ├── 供应链（FOFA body 搜技术支持公司 → 同产品客户）
  ├── ICP 备案
  │     ├── 备案号 → 备案网站反查域名
  │     └── FOFA body="备案号" → 同一公司所有备案域名
  └── 源码泄露
        ├── GitHub: site:github.com <公司名> password / token / key
        ├── Google: <产品名> "默认密码" / "操作手册" filetype:pdf
        └── 网盘搜索引擎
```



---

## 八、在线工具 URL 速查表

> 标注 `[A]` 表示该工具有 API 接口，可脚本化调用。标注 `[R]` 表示需要注册获取 API Key。

### CDN 检测 / 多地 Ping

| 工具 | URL | 说明 |
|------|-----|------|
| ipip.net CDN检测 | https://tools.ipip.net/cdn.php | 判断 CDN 类型 + 历史 IP |
| 奇安信 CDN 检测 | https://cdn.chinaz.com/ | 多地 ping + CDN 判断 |
| Ping.pe | https://ping.pe/ | 全球多地 ping + 端口检测 |
| 17CE | https://www.17ce.com/ | 国内多节点 ping/DNS/Traceroute |
| ITDog | https://www.itdog.cn/ | 国内多节点 ping/HTTP 状态 |

### 网络空间搜索引擎

| 工具 | URL | 说明 |
|------|-----|------|
| FOFA | https://fofa.info/ | 国内首选，规则丰富 |
| Hunter 鹰图 `[A][R]` | https://hunter.qianxin.com/ | 奇安信，与 FOFA 互补 |
| 0.zone 零零信安 | https://0.zone/ | 资产测绘 |
| 360Quake `[A]` | https://quake.360.net/ | 360 测绘空间 |
| ZoomEye 钟馗之眼 `[A]` | https://www.zoomeye.org/ | 知道创宇 |
| Shodan `[A]` | https://www.shodan.io/ | 国际首选 |
| Censys `[A][R]` | https://censys.com/ | 证书/资产搜索 |
| ARL 灯塔 `[自部署]` | https://github.com/ki9mu/ARL-plus-docker | 自动化资产侦察，Docker 部署 |

### 移动资产收集

| 工具 | URL | 说明 |
|------|-----|------|
| 七麦 APP搜索 | https://www.qimai.cn/ | APP 应用搜索，查看企业 iOS/Android 应用 |
| 搜狗微信搜索 | https://weixin.sogou.com/ | 公众号/小程序信息搜索 |
| 微信搜一搜 | 微信内置 | 直接搜索企业小程序 |
| 小蓝本 | https://sou.xiaolanben.com/ | APP/产品/商标查询 |

### 威胁情报平台

| 工具 | URL | 说明 |
|------|-----|------|
| 微步在线 `[A][R]` | https://x.threatbook.cn/ | 域名情报 + 历史解析 |
| 绿盟威胁情报 | https://ti.nsfocus.com/ | 威胁情报云 |
| 华为安全中心 | https://isecurity.huawei.com/sec | 华为威胁情报 |

### DNS 历史记录

| 工具 | URL | 说明 |
|------|-----|------|
| SecurityTrails `[A][R]` | https://securitytrails.com/domain/target.com | DNS 历史 + 子域名 + IP 关联 |
| dnsdb.io `[A]` | https://dnsdb.io/zh-cn/ | DNS 历史解析记录 |
| 微步在线 `[A][R]` | https://x.threatbook.cn/ | 域名情报 + 历史解析 + 子域名 |
| Netcraft | http://toolbar.netcraft.com/site_report?url=target.com | 托管历史 |
| ViewDNS.info | http://viewdns.info/ | IP/DNS/WHOIS 综合查询 |
| crt.sh `[A]` | https://crt.sh/?q=%.target.com | 证书透明度日志（免费 API） |
| Censys `[A][R]` | https://search.censys.io/ | SSL 证书指纹搜索 |
| Complete DNS | https://completedns.com/ | DNS 历史 + 子域名 |
| Virustotal `[A][R]` | https://www.virustotal.com/ | 域名/IP 关联分析 |

### IP 反查 / 旁站

| 工具 | URL | 说明 |
|------|-----|------|
| ip138 | https://site.ip138.com/ | IP 反查域名 + 历史解析 |
| ipchaxun | https://ipchaxun.com/ | IP 反查域名 |
| webscan.cc | https://www.webscan.cc/ | 旁站查询（同 IP 网站） |
| SearchMap `[A]` | https://fofa.info/extensions/source | FOFA 扩展：域名/IP 互查 |
| yougetsignal | https://www.yougetsignal.com/tools/web-sites-on-web-server/ | 反向 IP 查询 |
| SameSub | https://samesub.com/ | 同 IP 子域名发现 |
| dnsgrep `[A]` | https://dnsgrep.cn/ | DNS 数据查询（国内） |

### 子域名 / 域名查询

| 工具 | URL | 说明 |
|------|-----|------|
| 站长之家 Whois | https://whois.chinaz.com/ | Whois + DNS |
| phpinfo.me | http://phpinfo.me/domain/ | 域名注册信息查询 |
| AlienVault OTX `[A][R]` | https://otx.alienvault.com/ | 域名关联 + 子域名 API |
| SecurityTrails `[A][R]` | https://securitytrails.com/ | 子域名 + DNS 历史（API 丰富） |
| ridgey | https://ridgey.com/ | DNS 反向查询 |

### 企业 / 备案查询

| 工具 | URL | 说明 |
|------|-----|------|
| 爱企查 | https://aiqicha.baidu.com/ | 企业信息 + 知识产权 + 股权 |
| 天眼查 | https://www.tianyancha.com/ | 企业信息 + 对外投资 |
| 小蓝本 | https://sou.xiaolanben.com/ | APP/产品/商标查询 |
| 凤鸟 | https://www.fengniao.com/ | 企业信息（备用） |
| 工信部 ICP 备案 | https://beian.miit.gov.cn/ | ICP 备案号查询 |
| ICP 备案反查 | https://www.beianx.cn/ | 备案号 → 域名列表 |

### 目录扫描

| 工具 | URL | 说明 |
|------|-----|------|
| dirsearch | https://github.com/maurosoria/dirsearch | Python 目录扫描 |
| 7kbscan | https://github.com/7kb/7kbstorm | Web 界面目录扫描 |
| dirb | https://github.com/v0re/dirb | 经典目录爆破 |
| BBScan | https://github.com/lijiejie/BBScan | 轻量级信息泄露扫描 |
| 御剑目录扫描 | https://github.com/foryujian/yjdirscan | 命令行Web目录扫描，支持爬虫/fuzz |
| Gobuster | Kali 自带 (`apt install gobuster`) | DNS/目录/VHOST 多模式枚举 |

### JS 信息提取

| 工具 | URL | 说明 |
|------|-----|------|
| LinkFinder | https://github.com/GerbenJavado/LinkFinder | JS 中提取 URL/路径 |
| JSFinder | https://github.com/Threezh1/JSFinder | LinkFinder 增强版 |
| BurpAPIFinder | https://github.com/shuanx/BurpAPIFinder | Burp 插件：API 挖掘 + 指纹 |
| Packer-Fuzzer | https://github.com/rtcatc/Packer-Fuzzer | Webpack 前端打包分析 + 敏感信息 |
| URLFinder | https://github.com/pingc0y/URLFinder | JS/HTML 中提取 URL + 敏感信息 |

### 指纹识别

| 工具 | URL | 说明 |
|------|-----|------|
| TideFinger | https://github.com/TideSec/TideFinger / http://finger.tidesec.net/ | 多源指纹库 + 在线版 |
| whatweb | https://github.com/urbanadventurer/WhatWeb | 命令行指纹识别 |
| wappalyzer | https://www.wappalyzer.com/ | 浏览器插件实时识别 |
| EHole | https://github.com/EdgeSecurityTeam/EHole | 资产识别 + 漏洞检测 |
| wafw00f | https://github.com/EnableSecurity/wafw00f | WAF 类型检测 |
| 云悉指纹 (在线) | http://finger.tidesec.net/ | 在线 CMS 指纹识别 |
| 数字观星 (在线) | https://fp.shuziguanxing.com/#/ | 在线 CMS 指纹识别 |
| FOFA icon_hash | https://fofa.info/ | favicon hash 发现同类站点 |

### 端口扫描

| 工具 | URL | 说明 |
|------|-----|------|
| nmap | https://nmap.org/ | 最全面的端口扫描器 |
| masscan `[A]` | https://github.com/robertdavidgraham/masscan | 极速端口扫描 |
| ToolLine (在线) | https://toolonline.net/port-scan | 在线端口扫描 |
| Ip33 (在线) | http://www.ip33.com/port_scan.html | 在线端口扫描 |
| coolaf (在线) | http://coolaf.com/tool/port | 在线端口扫描 |

### 可脚本化工具汇总（`[A]` 标记）

以下工具提供 API，适合开发自动化脚本：

```
DNS 历史 + 子域名:
  SecurityTrails API  → GET /v1/domain/{domain}/associated
  Censys API          → GET /v2/hosts/{ip}
  crt.sh API          → GET https://crt.sh/?q=%.{domain}&output=json
  AlienVault OTX API  → GET /api/v1/indicators/domain/{domain}/passive_dns
  Virustotal API      → GET /api/v3/domains/{domain}
  dnsdb.io API        → (需注册获取 API Key)

IP 反查 / 测绘:
  FOFA API            → GET /v1/search/ip?ip={ip}
  SearchMap API       → FOFA 扩展 API
  masscan CLI         → 本地直接调用（无外部 API 依赖）

指纹 / 证书:
  crt.sh              → 免费 JSON 接口，无需认证
  Censys API          → SQL-like 查询证书指纹
```

Python 示例 — crt.sh 无 API Key 获取子域名：

```python
import requests

def crtsh_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = requests.get(url, timeout=30)
    names = set()
    for entry in resp.json():
        name = entry.get("name_value", "")
        for n in name.split("\\n"):
            names.add(n.strip().lstrip("*."))
    return sorted(names)

print(crtsh_subdomains("example.com"))
```


---

## 九、补充技巧与方法论

### 9.1 操作系统判断

```
方法1 — TTL 值判断（ping 目标后看 TTL，不修改时准确）:
  TTL=128 → Windows (NT/2000/7/10/11)
  TTL=64  → Linux / Android
  TTL=255 → Unix / Solaris
  TTL=32  → Windows 95/98

  注意: TTL 可被用户修改，只能作为参考，需结合其他手段。

方法2 — Nmap -O 参数:
  nmap -O <target>    # TCP/IP 指纹识别，比 TTL 更准确

方法3 — 大小写敏感:
  Windows: 目录不区分大小写 (/Admin 和 /admin 返回相同内容)
  Linux:   目录区分大小写 (/Admin → 404, /admin → 200)
  → 访问 /index.html 和 /Index.html 对比响应码即可判断
```

### 9.2 网站备份文件发现

```
攻击面: 管理员将源码/数据库备份在 Web 目录下 → 可直接下载。

常见备份文件后缀:
  压缩包:  .rar .zip .7z .tar.gz .tgz .tar .gz
  代码:    .bak .old .temp .backup .swp .save
  数据库:  .sql .sql.gz .db .mdb .sqlite
  编辑器:  .phps .txt ~ (vim 临时文件)
  版本:    .git .svn .DS_Store

常见文件名模式:
  - 域名/应用名 + 后缀:  target.rar, wwwroot.zip, web.zip
  - 日期命名:            20240101.sql, backup_2024.zip
  - 关键词:              backup, www, web, site, db, data, sql, code, source

快速探测:
  for ext in rar zip 7z tar.gz tgz bak sql sql.gz; do
    curl -s -o /dev/null -w "%{http_code}" http://target.com/www.$ext
    curl -s -o /dev/null -w "%{http_code}" http://target.com/backup.$ext
    curl -s -o /dev/null -w "%{http_code}" http://target.com/target.$ext
  done
```

### 9.3 SVN 源码泄露

```
原理: SVN 在工作目录下创建 .svn 隐藏文件夹，含源代码信息。
      管理员用"复制"而非"导出"部署代码 → .svn 暴露在 Web 目录。

检测:
  访问: http://target.com/.svn/entries
  → 存在（200）或 403 → 可能存在 SVN 泄露

利用:
  SvnHack: https://github.com/callmefeifei/SvnHack
  python2 SvnHack.py -u http://target.com/

  对比 Git 泄露:
  - Git:   .git/ 目录 + GitHack 下载还原
  - SVN:   .svn/ 目录 + SvnHack 下载还原
  - DS_Store: .DS_Store 文件 → 目录结构泄露

BBScan 内置了 .git/.svn/.DS_Store 等泄露检测规则，
对大批量资产做初筛时可用 BBScan 快速过一遍。
```

### 9.4 子域名枚举工具对比

```
补充 recon SKILL.md 未覆盖的工具:

Gobuster DNS 模式:
  apt-get install gobuster
  gobuster dns -d target.com -t 50 -w /path/to/subdomains.txt
  # -t 50: 50 线程，速度快
  # 也支持目录模式: gobuster dir -u http://target.com -w dict.txt

Layer 子域名挖掘机:
  https://github.com/euphrat1ca/LayerDomainFinder/releases
  # GUI 工具，Windows 下使用
  # 三种模式: 服务接口 / 暴力搜索 / 同服挖掘
  # 一键导出存活域名+IP+WebServer

Subfinder:
  # Kali: apt-get install subfinder
  subfinder -d target.com
  # 多源搜集（Google/Shodan/Censys/Virustotal 等）
  # 支持 JSON/CSV/TXT 输出
  # 可集成 Amass/Assetnote 做后续处理

OneForAll 详细:
  # 功能最全的子域名收集工具
  python oneforall.py --target http://target.com run
  # 模块: 证书透明度/搜索引擎/DNS数据集/威胁情报/爬虫
  # 爆破: massdns 引擎，每秒 350000+ DNS 解析
  # 验证: 自动解析+HTTP请求+存活判断+接管检查
  # 输出: txt/csv/json + banner信息
```

### 9.5 移动资产收集方法论

```
当 Web 资产无从下手时，转向移动端（APP/小程序）:

APP 发现路径:
  1. 爱企查/天眼查 → 知识产权 → 软件著作权 → APP 名称
  2. 七麦搜索 (qimai.cn) → 搜公司名 → iOS/Android APP 列表
  3. 各大应用商店 → 直接搜公司/产品名

小程序发现路径:
  1. 微信搜一搜 → 搜公司名/产品名 → 小程序
  2. 搜狗微信搜索 (weixin.sogou.com) → 搜公众号 → 关联小程序
  3. 支付宝搜索 → 搜公司名 → 小程序
  4. 社工: 关注公司运营人员 → 查看关联小程序

移动端攻击价值:
  - APP/小程序通常安全性低于 Web 主站
  - API 接口可能与 Web 端共享但认证较弱
  - 小程序可能暴露内网 API 端点
  - 抓包分析 APP 流量 → 发现隐藏 API
```

### 9.6 域名去重脚本

```
信息收集后得到大量域名 → 需要去重 + 标准化格式:

"""
Python 域名去重脚本（保存为 dedup.py）:
  - 自动补全 http:// 前缀
  - URL 标准化（去除 query/fragment/params）
  - 去重后保存到 domains_new.txt
"""

import urllib.parse

def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed_url = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(
        parsed_url._replace(path='/', params='', query='', fragment='')
    )

def process_domains_file(file_path):
    seen_urls = set()
    result = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            url = line.strip()
            normalized_url = normalize_url(url)
            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                result.append(normalized_url)
    with open('domains_new.txt', 'w', encoding='utf-8') as new_file:
        for url in result:
            new_file.write(url + '\n')
    return result

file_path = "domains.txt"
final_urls = process_domains_file(file_path)
for url in final_urls:
    print(url)
```

### 9.7 Gobuster 多模式速查

```
Gobuster 支持三种模式，用途不同:

1. DNS 模式 — 子域名爆破:
   gobuster dns -d target.com -t 50 -w subdomains.txt
   # -t 50: 50 线程
   # -d: 目标域名

2. Dir 模式 — 目录/文件爆破:
   gobuster dir -u http://target.com -w directory-list.txt
   # -x php,asp,aspx,jsp: 指定扩展名
   # -k: 跳过 TLS 证书验证
   # -s 200,204,301,302,307,401,403: 只显示这些状态码
   # -b 404,500: 排除这些状态码
   # -U user -P pass: Basic 认证

3. VHOST 模式 — 虚拟主机发现:
   gobuster vhost -u http://target.com -w vhosts.txt

三种模式共用选项:
   -c "session=xxx"    # Cookie
   -H "Header: value"  # 自定义请求头
   -o output.txt       # 输出到文件
```

### 9.8 Packer-Fuzzer 与 URLFinder

```
Packer-Fuzzer — Webpack 前端打包分析:
  适用: 使用 Webpack 等前端打包工具构建的网站
  功能: 解析打包后的 JS → 提取 API/路径/敏感信息
  命令:
    python3 PackerFuzzer.py -u http://target.com -t adv
    python3 PackerFuzzer.py -u http://target.com -j http://target.com/js/app.js
    # -t adv: 高级模式
    # -j: 附加 JS 文件进行额外分析

URLFinder — 页面 JS/URL 快速提取:
  适用: 所有网站，轻量快速
  功能: 从页面 JS 和 HTML 中提取 URL + 敏感信息
  命令:
    URLFinder.exe -u http://target.com -s 200,403 -m 3
    # -s: 只显示指定 HTTP 状态码的 URL
    # -m 3: 三层递归爬取
```
