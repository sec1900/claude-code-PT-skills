---
description: 单个漏洞无法直接利用时使用。提供漏洞组合利用的模式库(15种)，将多个低危漏洞链成高危攻击链。覆盖不出网×内存马、K8s×SA滥用、钓鱼×多层持久化、MCP劫持、零信任突围等复合场景。
---

# 漏洞链组合利用

## 核心原则

==单个低危漏洞看起来没用，但链起来可以致命。红队的价值不在于找到一个 Critical，而在于把三个 Low 链成 Critical。==

### 何时翻阅本文件

**触发条件（满足任一）：**
- 手上有 2+ 个发现，单独看都不够致命
- web-exploit 单点利用到了瓶颈，payload 正确但缺一块跳板
- 有一个可读写但无法直接 RCE 的入口
- CSRF/CORS/Open Redirect 等"低危"配置缺陷 —— 它们单独提交 SRC 价值低，但链条里是钥匙

**不是什么时候都翻** —— 如果单个漏洞已经有明确的直通利用路径（如直接 SQLi 出数据、直接 RCE），不需要为了"链"而链。

## 组合模式库

### 模式1：信息泄露 × 注入 = 数据窃取

```
Debug信息泄露（DB名/表名/列名）
  + LIKE数组注入（绕过认证查询）
  = 枚举用户数据、提取敏感字段
```

实例：debug 模式泄露数据库名和表前缀 → LIKE注入布尔预言逐字符提取用户表数据

### 模式2：CORS × XSS = Admin 接管

==前置条件: CORS 必须通过 @web-exploit.md P2-verify 的浏览器可利用性验证（OPTIONS 预检 + SameSite 检查）。仅 curl 可利用的 CORS 不满足此模式。==

```
场景A: CORS 浏览器可利用
  CORS反射Origin + Allow-Credentials（通过浏览器验证）
    + Stored XSS（中危）
    = 跨域读取所有后台接口数据（严重）

场景B: CORS 仅 curl 可利用（浏览器不通过）
  XSS 在同域上下文执行时不需要 CORS — 直接用 admin session fetch 同域 API
  Stored XSS（中危）
    = 同域内遍历后台接口（高危，不依赖 CORS）
  此时 CORS 配置不当仅作为额外发现单独报告（低危）
```

实例：C2 全站 CORS 反射 → XSS 投递到 SMS 数据 → admin 查看触发 → JS 用 admin cookie fetch 所有后台页面

### 模式3：文件上传 × 反序列化 = RCE

```
文件上传（.phar/.jpg 可上传，低危）
  + PHAR反序列化链（phpggc生成，需触发点）
  + 任意文件操作函数（file_exists/getimagesize 用了用户输入的路径）
  = phar:// 触发反序列化 → RCE
```

### 模式4：用户注册 × 数据注入 × 后台渲染 = XSS

```
开放注册API（低危）
  + 联系人/SMS字段无转义（低危）
  + admin后台渲染用户数据（正常功能）
  = Stored XSS → 偷admin session
```

### 模式5：配置泄露 × 多端口差异 = 绕过防御

不同端口可能有不同限速/CSRF/WAF策略，利用配置泄露定位最弱端口，绕过防御。
多端口差异分析方法详见 @recon.md「步骤9R」

```
getappconfig 泄露 is_login 状态（低危）
  + 某端口无CSRF保护（中危）
  = 在最弱端口无限制攻击admin登录
```

### 模式6：错误日志 × 公开目录 = 敏感数据泄露

```
应用写错误日志到公开目录（中危）
  + 日志包含用户输入（手机号/验证码等）
  + 日志文件名可预测（YYYYMMDDHHerror.txt）
  = 持续读取受害者实时数据
```

### 模式7：WordPress subscriber × Application Password × REST API = 持久侦察

```
开放注册（subscriber权限）
  + 创建Application Password（subscriber可以）
  + REST API 读取用户/文章/媒体列表
  = 持久的API访问 + 信息收集
```

### 模式8：CSRF × X = 高危 → 账户接管

==CSRF 本身不值钱（SOP 阻止跨域读响应），要链才有价值。核心问题不是"有没有 CSRF 保护"，是"链什么"。==

CSRF 单点利用细节见 @web-exploit.md「P3_csrf」，这里只写组合。

```
场景A: CSRF + SameSite bypass + 状态变更
  无 SameSite 保护的 cookie (None/Lax with GET)
    + 或 SameSite Strict 但有子域名 XSS / 重定向链绕过
    + 能触发状态变更操作（加管理员/改密码/改绑定手机）
    = CSRF 直接创建管理员入口 → 账户接管

场景B: CSRF + Open Redirect + OAuth
  CSRF 修改 OAuth 回调参数
    + Open Redirect 将授权码重定向到攻击者
    = 劫持 OAuth 授权 → 登录他人账号

场景C: CSRF + JSONP / CORS 读
  CSRF 修改用户数据（头像/签名）为攻击者控制的 URL
    + JSONP 端点或 CORS 反射
    = 读 admin 个人信息（从 URL 内嵌的数据外传）
```

**SameSite bypass 方法：**
```
SameSite=Strict:
  - 子域名 XSS → 同站上下文发请求
  - 跨域重定向链 → 新 tab 打开后 302 到目标站（cookie 带上是因为 SameSite=Lax 的导航请求规则）
  - cookie jar overflow → 填满 cookie 容器使浏览器降级 SameSite 检查

SameSite=None + Secure:
  - Secure 意味着只在 HTTPS 下发，如果目标有 HTTP 端口且 CSRF 在 HTTP 端
  - 这本身不是绕过，是配置不一致的利用
```

==判定: CSRF 无链 → 中危（或 SRC 忽略）。CSRF + 创建管理员 → 高危。CSRF + OAuth 接管 → 严重。==

### 模式9：SSRF × 内部服务 = RCE / 云控制台

```
场景A: SSRF → AWS/阿里云 IMDS → AK/SK
  目标: http://169.254.169.254/latest/meta-data/
    + SSRF 可控制 URL 且支持 file:// 或 http://
    = 获取临时 AK/SK → AWS CLI 接管 ECS/Lambda/S3
  亮点: 单个 SSRF 漏洞（中危）→ 完整的云资源接管

场景B: SSRF → Redis/Memcached/内部 API
  目标: http://127.0.0.1:6379/
    + SSRF 可写数据（gopher:// 协议）
    = Redis 写入 SSH 公钥 / crontab → RCE
  变体: SSRF → 内部 Solr/ElasticSearch/Gogs → 代码执行

场景C: SSRF → 内部管理面板
  目标: http://10.0.0.x/admin/
    + 内网管理面板无认证（防火墙挡住了外部，没挡内部）
    = 直接后台操作 → 创建管理员/导出数据
```

SSRF 探测和协议利用细节见 @web-exploit.md「P3_ssrf」。

==判定: SSRF 读文件 → 中危。SSRF 出云 AK/SK → 严重。SSRF to RCE (Redis/Gopher) → 严重。SSRF 内网管理面板 → 高危。==

### 模式10：Open Redirect × OAuth = 账户接管

==这可能是 SRC 里最常见的"低危变严重"链。Open Redirect 单独提交绝大多数平台忽略，链上 OAuth 就是账户接管。==

```
场景A: OAuth redirect_uri 白名单绕过
  正常: redirect_uri=https://target.com/callback
  绕过: redirect_uri=https://target.com/callback?next=https://evil.com
        redirect_uri=https://target.com.evil.com/callback (弱白名单正则)
        redirect_uri=https://target.com@evil.com/path (URL 解析器差异)
    = 授权码发到攻击者服务器 → 用 code 换 token → 登录受害者账号

场景B: SSO 回调污染 + Open Redirect
  目标有 /login/sso?returnUrl=/dashboard
    + returnUrl 不受限制（或只用相对路径"校验"）
    + 构造: /login/sso?returnUrl=//evil.com/phish
    = SSO 登录成功后跳转到钓鱼页 → 收集凭据/SSO token

场景C: Open Redirect → 偷 Referer 中的敏感参数
  target.com/page?redirect=https://evil.com
  如果前面的 page 在 URL 参数中含 token/key（如 ?token=xxx&redirect=evil.com）
    → evil.com 的 Referer 就是完整的 target.com URL
    → token 泄露
```

Open Redirect 单点探测见 @web-exploit.md「P3_openredirect」。

==判定: 反射 30x → 低危（单独）。OAuth redirect_uri 可控 → 高危。OAuth + Open Redirect 链 → 严重。==

### 模式11：不出网 RCE × 内存马 = 无文件持久控制

==最隐蔽的攻击链之一。目标不出网，payload 无法反弹 shell，但漏洞存在。==

```
场景A: fastjson/Shiro 反序列化 + 内存马注入（首选）
  反序列化漏洞（fastjson <= 1.2.24 / Shiro RememberMe）
    + 不出网环境（无 DNS/无 JNDI/无反弹 shell）
    + TemplatesImpl 本地字节码加载
    = 在反序列化 payload 中嵌入 Filter 内存马字节码
    → 内存马无文件落地，后续通过 HTTP 头回显命令结果

场景B: SQL 注入 + 不出网 + 写 webshell → 注内存马 → 删 webshell
  SQL 注入有写权限（INTO OUTFILE）
    + 写入 JSP/PHP webshell 到 web 目录
    + 访问 webshell → 执行代码注入内存马
    + 删除 webshell 文件
    = 最终只有内存马 → 无文件落地

场景C: 文件上传 + 不出网 + 反序列化 → 内存马
  上传 .phar / .jar 到已知路径
    + 触发反序列化（phar:// 协议或 ClassLoader）
    + 加载内存马字节码
    = 上传文件只是触发媒介，删除后内存马仍存活
```

不出网利用和内存马注入细节见 @no-outbound.md。

==判定: RCE + 不出网 → 高危。RCE + 不出网 + 内存马 → 严重（无文件持久化）。==

### 模式12：K8s Pod Shell × ServiceAccount 滥用 = 集群控制

==从最低权限的 Pod shell 到控制整个 K8s 集群的链。==

```
场景A: Pod Shell + list secrets SA → 窃取高权限 Token → 集群控制
  Web 漏洞拿到 Pod shell（看似低价值）
    + SA 有 list secrets 权限（K8s 默认 RBAC 常见配置）
    + 读取 kube-system 下的高权限 SA token
    + 用高权限 token 创建 cluster-admin ClusterRoleBinding
    = 完整集群控制

场景B: Pod Shell + create pods SA → 特权 Pod → 宿主机
  低权限 Pod shell
    + SA 有 create pods 权限
    + 创建特权 Pod（privileged: true + hostPID + hostNetwork）
    + 新 Pod 挂载宿主机根目录 → chroot → 宿主机 root
    = 从容器逃逸到所有 Node

场景C: SSRF + K8s API Server = 集群入口
  应用有 SSRF 漏洞
    + K8s Pod 内 SSRF 目标: https://kubernetes.default.svc.cluster.local
    + 加上 ServiceAccount token（从 SSRF 目标的文件系统读取）
    + 调用 K8s API 创建 Pod / 列 Secrets
    = 一个 SSRF 漏洞 → K8s 集群入侵
```

K8s 攻击详细手法见 @k8s-attack.md。

==判定: Pod shell 本身 → 低危。Pod shell + SA 提权 → 高危。Pod shell → 集群控制 → 严重。==

### 模式13：钓鱼 × Webshell × 内存马 = 多层持久化

==钓鱼拿到入口后不只满足于一次访问，用 webshell + 内存马建立多层持久化。==

```
场景A: 钓鱼文档 → 初始访问 → 写 webshell + 注内存马
  钓鱼邮件/文档 → 目标执行 payload → C2 上线
    + 发现目标有 Web 服务器 → 写 webshell（备份入口）
    + 发现是 Java 应用 → 注入 Filter 内存马（隐蔽入口）
    + Web 层入口独立于 C2 → C2 被清不影响 web 入口
    = 双通道持久化

场景B: 钓鱼 → 凭据窃取 → OAuth 持久化（不依赖密码）
  钓鱼拿到密码 → 登录 O365/GSuite
    + 创建 OAuth App / Application Password
    + 即使密码被改，OAuth token 仍有效
    = 密码无关的持久化

场景C: 钓鱼 → CI/CD 投毒 → 供应链持久化
  钓鱼拿到开发机权限
    + 修改 Jenkinsfile / .gitlab-ci.yml
    + 或投毒内部 NPM/Maven 私服
    + 每次 CI 构建 → 自动植入后门
    = 高持久性（修了还会被 CI 重新植入）
```

钓鱼免杀细节见 @phishing-evasion.md。

==判定: 钓鱼一次性访问 → 高危。钓鱼 + 多层持久化 → 严重。==

### 模式14：XSS/CSRF × MCP 工具调用 = AI 辅助攻击链

==新型攻击面：利用 Web 漏洞诱导 AI 的 MCP 工具执行恶意操作。==

```
场景A: Stored XSS + MCP 文件读取
  在应用数据中写入恶意内容（SMS/评论/文档）
    + 管理员通过 AI 助手（配置了 MCP 工具）分析此内容
    + 内容含伪造的 tool 描述或隐藏指令
    + AI 调用 read_file 或 run_command
    = XSS 劫持 AI 的工具调用 → 间接攻击宿主机

场景B: SSRF + MCP = 内网跳板
  应用有 SSRF → 指向内网 MCP Server
    + MCP Server 可能无认证（内网服务）
    + SSRF 伪造 tool call → MCP Server 执行
    = 一个外网 SSRF → 通过 MCP 横向到内网

场景C: 投毒 MCP 记忆 → 影响 AI 所有后续决策
  在多轮对话中逐步投毒 AI 记忆系统
    → AI 接受了虚假的安全配置信息
    → 后续所有安全评估建议都不准确
    = 长期隐蔽影响
```

MCP 安全风险分析见 `reference/mcp-security.md`。

==判定: 传统 XSS → 中高危。XSS + MCP 劫持 → 严重（新型攻击面）。==

### 模式15：零信任/微隔离中的链式突围

==零信任环境下单点漏洞不够，需要链式突破多层认证。==

```
场景A: SSRF + IMDS + 云 API = 改安全组
  应用 SSRF → 访问云 IMDS 获取临时 AK/SK
    + 临时 AK/SK 有 ec2:ModifySecurityGroupRules 权限
    + 修改安全组规则 → 放行自己的 IP
    = 零网络可达 → 通过网络策略绕过建立可达

场景B: 低权限凭据 + AD CS 证书滥用 = 高权限证书
  低权限用户密码/哈希
    + AD CS 配置不当（ESC1: 模板允许在 SAN 中指定任意主体）
    + 用低权限用户申请 Domain Admin 证书
    + 证书认证 → 不经过传统 Kerberos/NTLM 网络策略
    = 零信任网络隔离被证书认证绕过

场景C: 应用漏洞 + 信任跳板链
  Web 漏洞 → 应用服务器 A
    + A → 数据库 B（微隔离允许: app→db）
    + B 有 xp_cmdshell → B 上执行命令
    + B → 管理服务器 C（微隔离允许: db→mgmt）
    + C 是管理入口 → 控制整个环境
    = 单点 entry → 三次"合法"跳转 → 核心区
```

DMZ/零信任突破详细手法见 @post-exploit.md「场景J」「场景K」。

==判定: 单点在零信任环境中 → 中危。链式突破多层 → 严重。==

## 交叉引用表

==每个模式的单点利用细节在 web-exploit 对应章节，此处只写链。==

| 模式 | 链用到的单点 | web-exploit 章节 |
|------|------------|-----------------|
| 模式1 信息泄露×注入 | 信息泄露 / SQL/LIKE 注入 | P0_info_leak / P3_injection |
| 模式2 CORS×XSS | CORS 验证 / XSS payload | P2_cors / P5_xss_client |
| 模式3 上传×反序列化 | 文件上传 / phar 触发 | P4_upload_lfi |
| 模式4 注册×注入×XSS | 开放注册 / LIKE 注入 / Stored XSS | P3_injection / P5_xss_client |
| 模式5 配置泄露×多端口 | 多端口扫描 / CSRF/限速差异 | recon 步骤9R |
| 模式6 日志×公开目录 | 错误日志 / 目录遍历 | P0_info_leak / P4_upload_lfi |
| 模式7 WP + REST API | WP Application Password / REST API | P8_biz_logic |
| 模式8 CSRF×X | CSRF / SameSite bypass / Open Redirect | P3_csrf / P3_openredirect |
| 模式9 SSRF×内部服务 | SSRF 协议利用 / 内网探测 | P3_ssrf |
| 模式10 OAuth + Open Redirect | OAuth SSO / Open Redirect | P3.6_oauth_saml / P3_openredirect |
| 模式11 不出网×内存马 | 反序列化 / 内存马注入 / SQL写文件 | @no-outbound.md |
| 模式12 K8s×SA滥用 | Pod Shell / SA Token / RBAC提权 | @k8s-attack.md |
| 模式13 钓鱼×多层持久化 | 钓鱼初始访问 / webshell / 内存马 / OAuth | @phishing-evasion.md |
| 模式14 XSS/SSRF×MCP | XSS / SSRF / MCP 工具调用劫持 | `reference/mcp-security.md` |
| 模式15 零信任突围 | SSRF+IMDS / AD CS / 信任跳板链 | @post-exploit.md「场景J」「场景K」 |
| 模式16 版本窗口绕过 | DB大版本更新 → 新语法/新函数 → WAF/EDR规则滞后3-12个月 | @waf-bypass.md「DB版本特性绕过」 + @post-exploit.md「MSSQL代理执行链」 |

==模式16 通用原则：每次大版本更新引入的新特性，安全产品规则滞后 3-12 个月。不仅适用于 SQL 注入——K8s 新 API 版本、云新服务、AD 新 Kerberos 扩展都有同样的绕过窗口。==

## 组合发现方法

```
手里有什么？
├── 有信息泄露 → 能不能用泄露的信息帮助其他漏洞？
├── 有注入但读不到目标表 → 能写数据吗？写XSS？写内存马？
├── 有上传但不解析 → 有没有文件包含/phar触发？能配合不出网注入内存马？
├── 有XSS但admin不上线 → 有CORS吗？能跨域利用吗？能劫持 MCP 工具吗？
├── 有弱口令但有验证码 → 有OCR工具/无限速端口吗？
├── 有 Pod shell 但权限低 → SA token 能做什么？能调 K8s API 吗？
├── 内网全封了 → 有没有信任链跳板？AD CS 能滥用吗？
└── 什么都没有 → 回到信息收集，找关联资产
```

## 实战案例：CORS × XSS × 多端口 = Admin 完全接管（本次渗透）

这个案例展示了如何把三个"低危"配置缺陷链成完整的admin接管：

### 前置条件（看起来都没什么）
1. **7个端口无CSRF保护** — 正常的业务端口有频率限制，但副端口没有
2. **全站CORS反射+Allow-Credentials** — 所有Origin都反射，且带Credentials
3. **数据输入无XSS过滤** — SMS/联系人/设备字段可以写入任意HTML/JS。XSS 多渠道投递优先级详见 @post-exploit.md「场景L：C2 反制 → XSS 投递」
4. **未授权数据写入** — LIKE数组注入绕过认证，无需注册即可写数据

### 攻击链
```
步骤1: 选择无频率限制的副端口
  → 使用 LIKE 数组注入绕过认证，写入 XSS payload 到 SMS 数据
  → 操作符: `["LIKE", "%"]` `["NOTLIKE", "%"]` `["BETWEEN", [1, 999]]` `["IN", [1,2,3]]` `["EXP", "sleep(5)"]`。利用大小写绕过中间件（TP6 中间件别名匹配大小写敏感：`s=admin/User/index` 通过而 `s=Admin/User/index` 不通过）

步骤2: 构造恶意页面放在攻击者服务器
  → CORS反射任意Origin → 恶意页面可以跨域读取C2响应
  → 内嵌XSS payload: fetch所有后台API + 外传数据

步骤3: 等admin登录后台查看SMS数据
  → XSS在admin浏览器执行
  → 利用admin的session + CORS反射
  → 遍历所有后台功能，外传数据到攻击者服务器

结果: 不需要爆破密码，不需要绕过2FA，不需要webshell
     → 完整admin级别数据访问
```

### 为什么有效
- CORS反射Origin → 任意网站可以用受害者浏览器发跨域请求
- Allow-Credentials → 请求自动带上受害者cookie
- XSS在admin上下文执行 → 请求以admin身份发出
- 副端口无防护 → 整个攻击链没有被限速/WAF阻挡

==三个低危配置缺陷，链在一起就是完整的admin接管。这就是红队的价值。==

## 实战检查清单

拿到任何一个漏洞后，问自己：

- [ ] 这个漏洞能**读**什么？（源码/配置/用户数据）
- [ ] 这个漏洞能**写**什么？（数据库/文件/日志）
- [ ] 这个漏洞能帮助**其他漏洞**吗？（泄露的信息→精准利用）
- [ ] 这个漏洞能**持久化**吗？（创建账号/植入后门/定时任务）
- [ ] 这个漏洞和**已有漏洞**能链起来吗？

## 知识库

知识库可用时，查阅 `11-实战经验/漏洞链组合利用.md` + `11-实战经验/红队攻击链决策树.md`。
不可用时，使用本 skill 内置的 15 种组合模式和组合发现方法。