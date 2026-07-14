---
description: 渗透测试详细报告生成。汇总所有阶段数据、漏洞详情、攻击链、证据、修复建议。个人使用，越详细越好，不删减不套模板。
---

# 渗透测试报告生成

> 依赖: `$OUTDIR` 由 @environment.md 设置。本 skill 读取 `$OUTDIR/` 全部子目录生成报告。

## 核心原则

==报告是给自己看的完整记录，不是给甲方交差。越详细越好：每个漏洞的完整利用链、每次失败的尝试、每一条有用的信息。时间久了你能靠这份报告回忆起这次渗透的全部细节。==

> 数据来源: @recon.md → @web-exploit.md → @post-exploit.md（以及其他专项 skill）的产出都汇总到 $OUTDIR 下，报告是最后一环。

## 输入

从 `$OUTDIR/` 目录结构读取数据。按顺序读取：

```
1. meta.json                   → 目标、模式、场景
2. timeline.jsonl              → 完整攻击时间线（最重要）
3. targets/*.json              → 每个攻击目标的详细发现
4. vulns/confirmed.json        → 已确认漏洞列表
5. vulns/dead_ends.json        → 失败路径和卡点（不要删，复盘用）
6. credentials/found.json      → 获取的凭据
7. evidence/screenshots/*.png  → 浏览器截图
8. evidence/commands/*.png     → 命令输出截图
9. evidence/requests/*.txt     → 原始 HTTP 请求/响应
10. recon/ports.json           → 端口扫描摘要
11. recon/raw/nuclei.txt       → nuclei 扫描结果
12. recon/raw/nmap_*.txt       → nmap 扫描结果
```

## 报告完整性检查清单

==生成报告前逐项检查，缺什么补什么。这不是给甲方看的 checklist，是自己确认没有遗漏。==

```
[ ] 每个确认漏洞都有完整的复现 curl 命令
[ ] 每个确认漏洞都有原始请求/响应证据（不是截图，是可复现的原始数据包）
[ ] 每个确认漏洞都标注了危害等级和评级依据
[ ] 每个确认漏洞都有具体修复建议（不是"加强过滤"这种废话）
[ ] 攻击时间线无断档（每个关键操作的时间点都记录了）
[ ] 端口扫描结果已汇总（开放端口 → 服务 → 版本 → 已知漏洞映射）
[ ] 指纹识别结果已汇总（框架/中间件/CMS/语言/云厂商）
[ ] 信息泄露发现已逐条记录（URL + 泄露内容类型 + 泄露数据摘要）
[ ] 获取的所有凭据已记录（来源 + 类型 + 权限范围）
[ ] 后利用操作已记录（提权路径 + 横向移动路径 + 持久化方法）
[ ] 内网/云/域/K8s 发现已记录（对应专项 skill 的产出）
[ ] 失败路径已记录（什么尝试没成功、为什么、卡在哪里）
[ ] 关键截图已嵌入对应章节
[ ] IOC 已整理（如果涉及 C2 反制）
[ ] 攻击链可视化（从初始入口到最终目标的全路径）
```

## 报告结构

==按实际发现动态生成章节，有什么写什么。但以下结构是标准框架，实际生成时可以增减。==

```
报告/
├── README.md                 # 索引 + 关键发现摘要
├── 00-执行摘要.md             # 一句话结论 + Top N 发现 + 攻击链概览
├── 01-目标概况.md             # 资产清单、端口、指纹、攻击面
├── 02-信息收集.md             # 被动/主动收集的全部信息（非漏洞）
├── 03-漏洞详情.md             # 核心章节，每个漏洞完整记录
├── 04-漏洞利用与攻击链.md      # 漏洞如何组合、利用过程
├── 05-后渗透.md               # 提权/横向/持久化/凭据获取
├── 06-内网-云-域-K8s.md       # 专项攻击面的发现（有则写）
├── 07-IOC与反制.md            # C2 反制相关（有则写）
├── 08-修复建议.md             # 按优先级排列的具体修复方案
├── 09-附录.md                 # 完整端口表/目录爆破结果/扫描日志
└── evidence/                  # 截图和原始数据包（软链接或子目录）
```

---

## 00-执行摘要

==一句话说清楚这次渗透打到了什么程度。读完这段就能判断要不要深看。==

```markdown
# 执行摘要

**目标**: {target}
**测试时间**: {开始日期} — {结束日期}
**测试范围**: {IP 段/域名/URL 范围}

## 结论

{一段话总结：从哪个入口进去的 → 拿到了什么权限 → 影响范围多大}

## 关键发现

| 严重程度 | 数量 | 最高危发现 |
|---------|------|-----------|
| 严重 | N | {一句话描述} |
| 高危 | N | {一句话描述} |
| 中危 | N | {一句话描述} |
| 低危 | N | {一句话描述} |

## 攻击链概览

{用 ASCII 图画出从入口到最终目标的完整路径}

入口 → 漏洞A → 权限B → 横向到C → 提权到D → 最终目标

## 资产暴露面

- 开放端口: N 个（Web: N, DB: N, 远程管理: N）
- Web 服务: N 个（{列出技术栈}）
- 云/容器: {AWS/阿里云/K8s 等}
```

---

## 01-目标概况

```markdown
# 目标概况

## 基本信息

| 属性 | 值 |
|------|---|
| 目标 | {域名/IP/URL} |
| 解析 IP | {IP 列表} |
| CDN/WAF | {Cloudflare/阿里云WAF/无} |
| 云厂商 | {AWS/阿里云/Azure/无} |
| 开放端口 | {总数} 个 |

## 端口与服务

| 端口 | 服务 | 版本 | 备注 |
|------|------|------|------|
| 80 | nginx | 1.18.0 | 反代到 8080 |
| 443 | nginx | 1.18.0 | HTTPS |
| 22 | OpenSSH | 8.4 | 仅内网可达 |
| 3306 | MySQL | 5.7.38 | 仅 localhost |
| 6379 | Redis | 6.2.6 | 无密码 |

## 技术栈指纹

| 组件 | 识别结果 | 识别方式 |
|------|---------|---------|
| Web 框架 | ThinkPHP 6.0.3 | 报错页面 + 响应头 X-Powered-By |
| 中间件 | Nginx 1.18.0 | Server 头 |
| 后端语言 | PHP 7.4 | 探针文件 |
| 数据库 | MySQL 5.7 | 报错泄露 |
| 前端 | Vue 2.6 | JS 文件名 + chunk hash |

## 子域名/关联资产

{如果做了子域名枚举，列出发现}
| 子域名 | IP | 服务 | 备注 |
|--------|----|------|------|

## 目录/路径发现

{目录爆破或爬虫发现的有价值路径}
| 路径 | 状态码 | 内容 | 价值 |
|------|--------|------|------|
```

---

## 02-信息收集

==不是漏洞，但有助于理解目标和后续利用的信息。==

```markdown
# 信息收集

## WHOIS / DNS

| 类型 | 记录 |
|------|------|
| 注册商 | {注册商} |
| 注册邮箱 | {邮箱} |
| NS 服务器 | {NS 列表} |
| MX 记录 | {MX 列表} |
| TXT/SPF | {SPF 记录} |

## 泄露信息

从接口/文件/报错中泄露的非漏洞信息：

| URL | 泄露类型 | 内容摘要 | 危害 |
|-----|---------|---------|------|
| /api/user/info | 用户信息 | 返回了内部用户名/部门/手机号 | 信息收集 |
| /actuator/env | 环境变量 | 暴露了数据库密码 | 严重 |
| /.git/HEAD | 源码泄露 | Git 仓库可完整下载 | 严重 |

## 社会工程相关信息

{从 recon 或 OSINT 收集到的组织信息}
- 员工邮箱格式: {格式}
- 组织架构: {IT部门/运维部门负责人等}
- 使用的技术栈: {VPN设备/OA系统/邮件系统}
```

---

## 03-漏洞详情（核心章节）

==这是报告最重要的部分。每个漏洞都按以下模板写，不要偷懒省略。==

### 漏洞编号规则

```
VULN-{序号}-{类型缩写}-{严重程度}
类型缩写: sqli/xss/ssrf/rce/idor/upload/info_leak/logic/ssti/xxe/lfi/...
严重程度: C(严重)/H(高危)/M(中危)/L(低危)
示例: VULN-001-sqli-C, VULN-002-info_leak-H, VULN-003-rce-C
```

### 严重程度评估矩阵

| 严重程度 | 定义 | 典型场景 |
|---------|------|---------|
| 严重(C) | 直接获取服务器权限/核心数据 | RCE、SQLi 直接读库、SSRF→IMDS、任意文件读取含密钥 |
| 高危(H) | 间接获取权限/敏感数据泄露 | 文件上传无限制、未授权访问后台、敏感信息泄露 |
| 中危(M) | 需配合其他漏洞/条件苛刻 | 目录遍历、CSRF、反射型 XSS、低危信息泄露 |
| 低危(L) | 危害有限/需极端条件 | 点击劫持、用户名枚举、缺少安全头 |

### 漏洞详情模板

```markdown
## VULN-{序号}-{类型}-{严重程度}: {一句话描述漏洞}

| 属性 | 值 |
|------|---|
| URL | {完整 URL} |
| 参数/位置 | {GET/POST/Cookie/Header 中的具体参数} |
| 请求方式 | {GET/POST/PUT/...} |
| 发现时间 | {ISO8601} |
| 发现方式 | {nuclei/手动 fuzz/代码审计/信息泄露/...} |

### 漏洞描述

{2-4 句话说清楚}
1. 这个漏洞是什么（SQL 注入 / 未授权访问 / 反序列化 ...）
2. 为什么存在（参数未过滤 / 默认配置 / 版本漏洞 ...）
3. 攻击者能做什么（读库 / 写文件 / 执行命令 / 获取 AK/SK ...）

### 受影响版本/组件

{如果知道具体版本号，写出来。如果是已知 CVE，标注 CVE 编号}
- ThinkPHP 6.0.3 (CVE-2021-xxx)
- Shiro 1.7.0 使用默认 AES key

### 复现步骤

\```bash
# 第一步：发送 payload
curl -X POST "http://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1","password":"xxx"}'

# 第二步：确认注入成功
# 返回了所有用户数据 → 布尔盲注确认

# 第三步：利用 sqlmap 自动化
sqlmap -u "http://target.com/api/login" --data='{"username":"admin","password":"xxx"}' \
  --dbms=mysql --dbs --batch
\```

### 原始请求与响应

\```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin' OR '1'='1","password":"xxx"}

---

HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"data":{"users":[...所有用户数据...]}}
\```

### 证据截图

![登录接口 SQL 注入](../evidence/screenshots/001_sqli_login.png)
![sqlmap 执行结果](../evidence/screenshots/002_sqlmap_dbs.png)

### 获取的数据/权限

{通过这个漏洞实际拿到了什么}
- 数据库: production_db 完整 dump，含 N 万用户
- 表: users (id, username, password_hash, email, phone)
- 敏感字段: password_hash 为 MD5 无盐，可直接彩虹表碰撞

### 修复建议

{具体到代码/配置级别，不写废话}

\```
1. 参数化查询：
   - 文件: src/controller/Login.php L34
   - 当前: $sql = "SELECT * FROM users WHERE username='$username'";
   - 改为: $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
           $stmt->execute([$username]);

2. 密码哈希升级：
   - 当前: MD5 无盐 → 彩虹表秒破
   - 改为: bcrypt (cost=12) 或 argon2id
   - 迁移策略: 用户下次登录时自动重新哈希

3. 数据库连接限制：
   - 应用账户去掉 DROP/ALTER/FILE 权限
   - 只给 SELECT/INSERT/UPDATE/DELETE 对应业务的表
\```
```

---

## 04-漏洞利用与攻击链

==单个漏洞看危害，组合利用看路径。这一章讲你是怎么把多个漏洞串起来的。==

```markdown
# 漏洞利用与攻击链

## 攻击链总览

{ASCII 流程图，从初始访问到最终权限}

信息泄露接口 → 获取用户名列表 → 弱口令爆破 → 后台登录
    → 后台文件上传（绕过后缀黑名单）→ webshell
    → webshell 提权（SUID find）→ root

## 关键节点详述

### 节点1: 信息泄露 → 用户名列表

**入口**: GET /api/user/search?keyword=
**利用**: 未做权限校验，返回所有匹配用户的完整 profile
**产出**: 87 个有效用户名、部门、邮箱格式

### 节点2: 弱口令爆破 → 后台登录

**入口**: POST /admin/login
**利用**: 用节点1的用户名列表 + 常用弱口令字典定向爆破
**产出**: 3 个弱口令账号，其中 1 个有文件上传权限
**规避**: 每个账号间隔 3 秒，单线程，避免触发锁定

### 节点3: 文件上传绕过 → webshell

**入口**: POST /admin/article/add (富文本编辑器的图片上传)
**绕过方法**: 后缀 phtml → Nginx 不解析但 Apache 解析（AJP 反代场景）
**产出**: webshell → www-data 权限
**规避**: 文件名用随机 UUID，避免被运维发现

### 节点4: 提权 → root

**方法**: find / -perm -4000 发现 /usr/bin/find 有 SUID
**利用**: find . -exec /bin/sh -p \; -quit
**产出**: root shell
```

---

## 05-后渗透

==获取初始权限后的所有操作都记录在这里。==

```markdown
# 后渗透

## 初始立足点

| 属性 | 值 |
|------|---|
| 入口 | {webshell/反序列化/SSH 弱口令/...} |
| 主机 | {hostname / IP} |
| 权限 | {root/www-data/SYSTEM/...} |
| 系统 | {CentOS 7.9 / Windows Server 2019 / Ubuntu 20.04} |
| 杀软/EDR | {无/火绒/卡巴斯基/CrowdStrike/...} |
| 内网 IP | {IP + 网段} |

## 信息收集（后利用阶段）

### 系统信息

\```bash
hostname: WEB-PROD-01
uname -a: Linux web-prod-01 5.4.0-109-generic #123-Ubuntu SMP
whoami: www-data (uid=33)
ip addr: eth0 10.0.1.5/24, eth1 172.16.0.3/16 (内网)
\```

### 用户与组

| 用户 | UID | 组 | 可登录 |
|------|-----|----|--------|
| root | 0 | root | 是 |
| app | 1001 | app,docker | 是 |
| www-data | 33 | www-data | 否 |

### 进程与安全软件

| 进程 | 用途 |
|------|------|
| /usr/sbin/nginx | Web 服务 |
| /usr/bin/php-fpm | PHP |
| /usr/bin/mysqld | 数据库 |
| 无杀软/EDR 进程 | 防御薄弱 |

### 网络连接

| 本地地址 | 远程地址 | 状态 | 进程 |
|---------|---------|------|------|
| 0.0.0.0:80 | * | LISTEN | nginx |
| 127.0.0.1:3306 | * | LISTEN | mysqld |
| 10.0.1.5:22 | * | LISTEN | sshd |
| 172.16.0.3:45678 | 172.16.0.1:389 | ESTABLISHED | php-fpm |

### 凭据发现

| 来源 | 类型 | 凭据 | 权限范围 |
|------|------|------|---------|
| /var/www/html/.env | 数据库密码 | DB_PASSWORD=xxx | MySQL production_db |
| /home/app/.ssh/id_rsa | SSH 私钥 | id_rsa (无密码) | 可 ssh 登录 app 用户 |
| /etc/redmine/database.yml | 数据库密码 | redmine:password@localhost | redmine 库 |
| Redis (6379) | 无密码 | 直接连接 | Redis 所有数据 + 写 crontab |

## 提权

### 尝试过的路径

| 方法 | 结果 | 原因 |
|------|------|------|
| SUID 提权 | ✓ 成功 | /usr/bin/find 有 SUID bit |
| sudo -l | ✗ 失败 | www-data 不在 sudoers |
| 内核漏洞 | ✗ 不适用 | 内核 5.4 已打补丁 |
| Docker 组 | ✗ 不适用 | www-data 不在 docker 组 |

### 成功提权路径

\```bash
# 1. 发现 SUID 程序
find / -perm -4000 -type f 2>/dev/null
# /usr/bin/find (SUID root)

# 2. 利用 GTFObin
find . -exec /bin/sh -p \; -quit
# 或
/usr/bin/find /etc/passwd -exec /bin/bash -p \;

# 3. 确认
id
# uid=33(www-data) gid=33(www-data) euid=0(root)
\```

## 横向移动

### 发现的内网资产

| IP | 主机名 | 开放端口 | 服务 | 备注 |
|----|--------|---------|------|------|
| 10.0.1.5 | web-prod-01 | 80,22 | nginx/ssh | 当前立足点 |
| 10.0.1.10 | db-prod-01 | 3306 | MySQL | 数据库服务器 |
| 10.0.1.20 | dc01 | 88,389,445 | AD DC | 域控制器 |
| 172.16.0.3 | web-prod-01 | — | — | 双网卡，内网段 172.16.0.0/16 |

### 横向移动路径

| 从 | 到 | 方法 | 凭据 | 结果 |
|----|----|------|------|------|
| web-prod-01 (root) | db-prod-01 (root) | SSH 密钥 | 发现 root 用户的 SSH 密钥同样能登录 db | ✓ |
| db-prod-01 (root) | dc01 | PSExec | 从 db 的 .bash_history 发现域管理员密码 | ✓ |

## 持久化

| 方法 | 位置 | 触发方式 | 隐蔽性 |
|------|------|---------|--------|
| SSH 公钥追加 | /root/.ssh/authorized_keys | SSH 登录 | 中 |
| crontab 反弹 | /var/spool/cron/crontabs/root | 每小时 | 低 |
| webshell | /var/www/html/modules/system.php | HTTP 请求 | 中 |
```

---

## 06-内网/云/域/K8s

==渗透过程中涉及了哪个专项领域，就写哪一节。没涉及的跳过。==

### 域环境（参考 @ad-attack.md 产出）

```markdown
## 域环境

| 属性 | 值 |
|------|---|
| 域名 | corp.local |
| 域控 | dc01.corp.local (10.0.1.20), dc02.corp.local (10.0.1.21) |
| 域功能级别 | Windows Server 2016 |
| 林功能级别 | Windows Server 2016 |

### BloodHound 关键发现

{高危 ACL 路径 / Kerberoastable 用户 / 委派配置问题 / AD CS}

### 获取的域凭据

| 用户 | 权限组 | 获取方式 | 哈希/密码 |
|------|--------|---------|----------|
| svc_sql | Domain Users | Kerberoasting | NTLM: xxx |
| administrator | Domain Admins | DCSync | NTLM: xxx |
```

### 云环境（参考 @cloud-attack.md 产出）

```markdown
## 云环境

| 属性 | 值 |
|------|---|
| 平台 | {AWS / 阿里云 / Azure} |
| 账户 ID | {12 位 AWS account ID / 阿里云 UID} |
| 当前权限 | {IAM Role / RAM User 名称} |

### AK/SK 获取路径

| 来源 | AK/SK 类型 | 权限范围 | 获取方式 |
|------|-----------|---------|---------|
| .env 文件 | 永久 AK/SK | S3 读写 + EC2 只读 | 文件读取 |
| IMDS | 临时 STS Token | AdministratorAccess | SSRF → IMDS |

### 横向到其他云服务

| 服务 | 操作 | 影响 |
|------|------|------|
| S3: company-backup | 列举 + 下载 | 获取所有备份文件和数据库 dump |
| EC2: i-xxx | 创建 AMI + 共享 | 导出所有服务器数据 |
| IAM | 创建后门用户 | 持久化 |

### 持久化

{创建的 IAM 用户/角色/Function 后门}
```

### K8s/容器（参考 @k8s-attack.md 产出）

```markdown
## K8s/容器环境

| 属性 | 值 |
|------|---|
| 当前 Pod | nginx-deployment-7b8f9c5d6-x7k2m |
| Namespace | production |
| SA Token 权限 | list/get pods, secrets (当前 namespace) |
| 是否特权 | 否 |

### RBAC 提权路径

{从当前 SA → 更高权限 SA → cluster-admin 的路径}

### 逃逸方法

{是否成功逃逸 / 尝试了哪些方法}

### 持久化

{创建的 SA/Webhook/Shadow API Server}
```

---

## 07-IOC 与反制

==如果渗透过程中发现了攻击者的痕迹（C2 反制场景），整理这一章。==

```markdown
# IOC 与反制

## 攻击者基础设施

| 类型 | 值 | 来源 | 置信度 |
|------|---|------|--------|
| C2 域名 | update.cdn-target.com | webshell 中硬编码的回连地址 | 高 |
| C2 IP | 45.xxx.xxx.xxx | DNS 解析结果 | 高 |
| 钓鱼域名 | login-target.com | 受害者收到的钓鱼邮件 | 高 |
| 攻击者邮箱 | attacker@proton.me | C2 域名注册 WHOIS | 中 |

## 攻击者身份线索

| 线索类型 | 值 | 来源 |
|---------|---|------|
| 社交账号 | Telegram @xxx | C2 配置文件中发现 |
| 手机号 | +86 1xxxxxxxxxx | C2 服务器上的注册信息 |
| 加密货币地址 | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | C2 勒索信息中的收款地址 |

## 受害评估

{基于数据库记录数/日志分析/其他证据估算}

- 受影响用户: 约 N 人（基于 users 表记录数）
- 数据泄露: {具体泄露了哪些数据}
- 持续时长: {从第一个后门创建时间到发现时间}
```

---

## 08-修复建议

==按优先级排列，每条建议对应一个具体漏洞。==

```markdown
# 修复建议

## 优先级总览

| 优先级 | 数量 | 涉及漏洞 |
|--------|------|---------|
| 立即修复 (P0) | N | VULN-003-rce-C, VULN-007-sqli-C |
| 本周修复 (P1) | N | VULN-001-info_leak-H, VULN-004-ssrf-H |
| 本月修复 (P2) | N | VULN-002-xss-M |
| 持续改进 (P3) | N | 安全头缺失等 |

## 立即修复 (P0)

### VULN-003-rce-C: Shiro RememberMe 反序列化

**威胁**: 攻击者可直接执行任意命令，获取服务器控制权

**修复**:
1. 升级 Shiro 到 1.10.0+（最新稳定版）
2. 如果暂时不能升级:
   - 更换默认 AES key 为随机生成的无意义 key
   - 设置 rememberMe cookie 的 httpOnly 和 secure 标志
3. 验证: 用 Shiro 检测工具确认 key 不再可被利用

### VULN-007-sqli-C: 登录接口 SQL 注入

**威胁**: 攻击者可读取全库数据，包括所有用户密码哈希

**修复**:
1. 所有数据库查询改用参数化查询（PreparedStatement）
2. 登录逻辑加入失败次数限制（同 IP 5 次失败锁定 15 分钟）
3. 数据库应用账户收回 DROP/ALTER/FILE 权限
4. 密码哈希升级为 bcrypt(argon2id)，用户下次登录时自动迁移

## 本周修复 (P1)

{同上格式，每个漏洞一条}

## 加固建议（非漏洞相关）

{安全头配置/日志/监控/CSP 等通用加固建议}
```

---

## 09-附录

```markdown
# 附录

## A. 完整端口扫描结果

{从 recon/raw/nmap_*.txt 提取精华，不要太长}

\```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.4
80/tcp   open   http       nginx 1.18.0
443/tcp  open   ssl/http   nginx 1.18.0
3306/tcp closed mysql
6379/tcp open   redis      Redis 6.2.6
8080/tcp open   http       Apache Tomcat 9.0.54
\```

## B. 目录爆破结果

{有意义的路径，不是全部输出}

| 路径 | 状态码 | 大小 | 备注 |
|------|--------|------|------|
| /admin/ | 302 | — | 重定向到登录页 |
| /.env | 200 | 156B | 环境变量文件（敏感） |
| /api/swagger.json | 200 | 8KB | API 文档 |

## C. 使用工具清单

| 工具 | 用途 | 版本 |
|------|------|------|
| nmap | 端口扫描 | 7.94 |
| nuclei | 漏洞扫描 | 3.x |
| sqlmap | SQL 注入利用 | 1.7 |
| mimikatz | 凭据提取 | 2.2.0 |
| certipy | AD CS 攻击 | 4.8 |

## D. Timeline 完整记录

{从 timeline.jsonl 生成完整列表，不截断}
```

---

## 生成后检查

==报告写完后逐项确认：==

```
[ ] README.md 里写了 top 3 发现和执行摘要结论
[ ] 每个漏洞都有编号（VULN-NNN-type-level）
[ ] 每个漏洞都有复现 curl 命令且已验证可复现
[ ] 每个漏洞都有原始请求/响应（不是截图）
[ ] 每个漏洞的修复建议具体到配置文件/代码行/命令
[ ] 提权/横向/持久化每个操作都有记录
[ ] 凭据表格完整（来源+值+权限范围）
[ ] 内网/云/域/K8s 发现已填充（如果有的话）
[ ] 时间线无断档
[ ] 失败路径已记录
[ ] 附录端口扫描结果是精确版本（-sV），不是猜测
[ ] 涉及 @skill-name 专项攻击的，该 skill 的产出已纳入对应章节
```

## 知识库路由

| 报告元素 | KB 路径 | 参考内容 |
|---------|---------|---------|
| 报告模板参考 | `11-实战经验/` | 各复盘报告的写法和结构 |
| 漏洞修复建议 | `03-漏洞利用/` | 各组件漏洞的修复方案 |
| 后利用清理 | `08-应急响应/` | 从防御视角反推修复优先级 |
| 红队基建 | `07-红队基建/` | report 生成脚本可放这里 |