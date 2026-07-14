---
description: 百度SRC(BSRC)专属漏洞挖掘模式。仅当目标是百度资产(*.baidu.com等)且用户确认参与BSRC时使用。包含BSRC红线规则、业务系数表、SSRF靶场、合规边界、高回报漏洞策略。
---

# BSRC 漏洞挖掘引擎

## 核心原则

==SRC 挖洞 ≠ 红队攻防。SRC 的目标是在规则内高效发现漏洞拿赏金，不是拿权限。==

```
红队模式: 目标→权限  | 无视边界 | 深度渗透 | 追求控制
SRC模式:  目标→漏洞  | 遵守规则 | 轻量验证 | 追求效率+合规
```

---

## PHASE 0: 合规检查（强制，不可跳过）

### 0a. 红线禁令（触犯=永久封禁+法律追责）

| 红线 | 具体行为 |
|------|---------|
| 数据泄露 | 将测试中获取的任何数据在第三方平台售卖/传播 |
| 恶意攻击 | 删除/篡改生产数据、大规模 DoS、利用漏洞做黑产 |
| 骗取奖励 | 伪造漏洞、重复提交、脚本刷单 |
| 未授权披露 | 漏洞修复前在任何渠道公开细节/PoC |
| 攻击平台 | 对 BSRC 平台本身进行攻击 |

### 0b. 合规边界（违反=扣信用分200-1000）

| 规则 | 限制 |
|------|------|
| **数据获取** | ≤10 条，严禁大规模遍历 |
| **扫描方式** | 禁止高频无差别全量扫描（nmap --min-rate / masscan / 全端口） |
| **测试范围** | 仅限百度自有资产，禁止 C 段扫描、禁止探测非百度资产 |
| **SSRF** | 证明存在+有回显即可，禁止深入内网渗透 |
| **后门** | 禁止留存 webshell/系统账号/监控软件（未报告说明） |
| **报备** | 特定类型测试需先通过 BSRC 报备入口报备 |
| **漏洞证明** | 需读取 hostname/id 等机器信息，不以 dnslog 回包为依据 |
| **写操作可逆性** | 写操作验证前必须评估可逆性。不可逆操作（有冷却期/配额消耗/数据删除/状态不可回退）只需证明接口可达+参数被接受即可（如返回参数校验错误已证明接口存活），不实际执行写入；或执行前必须告知用户不可逆风险并获得确认。可逆操作可直接验证。 |

### 0c. SSRF 专项规则

```
SSRF 靶场:
  域名: http://bsrc-ssrf.n.baidu-int.com/bsrc_uid
  IP:   http://<BSRC_SSRF_IP>/bsrc_uid

获取 BSRC UID:
  https://bsrc.baidu.com/v2/api/info → 参数 userId

SSRF 评分（不分业务等级）:
  完全回显: 600 分 （目标服务器返回所有数据原封不动展示）
  AI总结回显: 300 分 （通过AI将内容以文本总结展示）
  部分回显: 75 分  （仅展示部分，如图片形式展示靶场内容）
  无回显: 38 分    （无回显的图片SSRF不收录）
  不通内网: 0 分   （忽略）
```

---

## PHASE 1: 资产识别（合规侦察）

==与红队 /recon 不同：SRC 侦察只做被动信息收集+轻量主动探测，不做全端口/C段/高频扫描。==

### 1a. 确认资产归属

```
收录范围:
  *.baidu.com、apolloxcloud.com、*.yy.com 等百度自有资产

不收录:
  百度外卖、91助手、千千音乐、太合音乐、纵横文学、度小满金融
  百度云租户、YY游戏 → 反馈给现归属公司
  租户域名: bceapp.com、jomoxc.com 等
  bcebos.com / bdysite / aipage 等可注册控制域名下的 XSS → 忽略
```

### 1b. 业务系数识别（决定打什么）

==系数越高，同一漏洞得分越高。优先打高系数业务。==

**【系数 7-10】核心业务（最高优先）**

| 业务 | 关键域名/产品 |
|------|-------------|
| 百度搜索 | www.baidu.com、m.baidu.com |
| 百度账号 | passport.baidu.com |
| 百度云 | 云服务器、BOS、IAM、AIHC、千帆、数据库 |
| 文心一言 | AI内容生成、AI聊天 |
| 百度DuerOS | — |
| 百度APP | 个人中心基础组件 |
| 百度地图 | 驾车/导航/公交/步骑行/周边/检索/打车/定位 |
| 百度文库 | — |
| 百度网盘 | — |
| 萝卜快跑 | 交易系统/运力调度/安全风控/路线配置 |

**【系数 2-6】重要业务**

百度贴吧、百度知道、百度百科、百度输入法、百度统计、百度指数、如流、百度健康、以及 7-10 业务中未包含的功能模块

**【系数 1】边缘业务**

百度游戏、百度视频、YY全民娱乐直播、百度阅读、百度拆分业务

### 1c. 合规侦察方法

```bash
# 允许的侦察手段:
1. 子域名枚举（crt.sh / 被动DNS / subfinder）
2. 搜索引擎 dork（site:*.baidu.com）
3. JS 文件分析（提取 API 端点）
4. 常规目录探测（低频，非爆破）
5. 指纹识别（whatweb -a 1）
6. robots.txt / sitemap.xml

# 禁止的侦察手段:
✗ 全端口扫描（nmap -p-）
✗ C 段扫描
✗ 高频目录爆破（ffuf 高线程）
✗ 大规模 nuclei 扫描
✗ 探测非百度资产
```

### 1d. 执行指令

==不要手动 curl 逐个探测。调用 @recon.md 的 SRC 模式流程执行侦察，但遵守上方 0b 合规边界的约束。==

```
具体流程:
1. 调用 recon 步骤 3（被动信息收集）— 子域名枚举、JS/DNS/证书分析
2. 调用 recon 步骤 5（httpx 批量探活）— 获取存活状态、标题、技术栈
3. SPA 站点用 recon 步骤 12R-b（Playwright 动态爬取）提取 API 端点
4. 调用 recon 步骤 5.5（深度识别）— 指纹匹配、被动攻击面标记
5. 跳过 recon 中 BSRC 禁止的步骤（全端口扫描、C段、高频爆破、大规模 nuclei）
6. 结果写入 $OUTDIR/ 标准目录结构（targets/*.json + timeline.jsonl）

这样做的好处:
- 侦察质量与 recon SRC 模式一致
- 有 timeline 记录，中断后可恢复
- 自动触发 SPA 假阳性过滤（recon 硬规则 6）
- 指纹匹配可自动路由到 POC 库
```

---

## PHASE 1.5: 自动 Triage（进入挖掘前必做）

==recon 发现一堆东西，但不是每个都能换分。先过滤，再开打。==

### 过滤流程

```
1. 逐条对照 0 分列表（见下方），标记为 "忽略" + 原因
2. 同类问题按合并规则预分组（如同域名 debug/phpinfo → 算 1 个漏洞）
3. 输出: 计分候选列表 + 忽略项列表
```

### 0 分项清单（立即删除/标记忽略）

| 类型 | 判断标准 |
|------|---------|
| Self-XSS | 仅对攻击者自己浏览器生效 |
| 无敏感操作的 CSRF | 无实际危害的 CSRF |
| 内网 IP/域名泄露 | 仅泄露 IP/域名无进一步利用 |
| JSON hijacking | 无敏感信息的 JSON |
| 不通内网的 SSRF | SSRF 无回显或无法访问内网 |
| 租户域名 XSS | bcebos.com / bdysite / aipage 等可控域名 |
| 无 Chrome 外的 XSS | 仅特定浏览器触发 → 最高低危 |
| AI 越狱/Prompt Leak | 非隐私数据泄露 → 不收录 |
| 沙箱代码执行 | 除非能逃逸 |

### 合并规则（同类不算重复提交）

| 情况 | 处理 |
|------|------|
| 同接口不同参数 | 合并为 1 个 |
| 同 JS 引起的多个漏洞 | 合并为 1 个 |
| 同站点 debug/phpinfo 多处泄露 | 合并为 1 个 |
| 同函数被不同路径调用 | 合并为 1 个 |
| 同域名同类问题 30 工作日内 | 最多收前 3 个（建议打包） |
| 修 1 个其他自动修复 | 合并为 1 个 |

### 输出格式

```
=== BSRC Triage ===
计分候选 (N):
  1. [高危] ace.baidu.com/api/xxx — 未授权返回用户数据 — 参考 P0
  2. [中危] test.baidu.com — .env 泄露 DB 密码 — 组合利用
  ...

忽略 (M):
  - ace.baidu.com — 内网 IP 10.x.x.x 泄露 — 不计分
  - test.baidu.com — self-XSS — 不计分
  ...
```

---

## PHASE 2: 漏洞挖掘策略（按回报排序）

### 2a. 最高回报：RCE（3倍积分常态化）

```
RCE 通内网/控集群/网络通百度内网(SSRF除外) → 严重 × 3倍
大规模影响百度用户使用的漏洞 → 严重 × 3倍

挖掘方向:
  - 已知框架 CVE（ThinkPHP/Struts/Spring/Fastjson/Log4j）
  - 反序列化漏洞
  - 文件上传 getshell
  - 模板注入 SSTI
  
验证方式:
  必须读取 hostname / id / ifconfig
  不能只靠 dnslog（百度内部爬虫会干扰）
```

### 2b. 高回报：SSRF（不分业务系数，固定分值）

```
挖掘方向:
  - URL 参数中的 http:// https:// 输入点
  - 图片/文件加载功能
  - Webhook/回调 URL
  - PDF 生成/导出功能
  - API 代理/转发功能

验证方式:
  批量脚本: `${CLAUDE_SKILL_DIR}/../recon/scripts/ssrf_probe.py` --callback http://bsrc-ssrf.n.baidu-int.com/{UID}
  http://bsrc-ssrf.n.baidu-int.com/{your_bsrc_uid}
  或 http://<BSRC_SSRF_IP>/{your_bsrc_uid}
  
  证明有回显即可，禁止深入内网
```

### 2c. 高回报：严重级漏洞（基础200-300分 × 业务系数）

```
1. 直接获取系统权限（RCE/Webshell/SQLi→权限）
2. 核心系统业务拒绝服务
3. 严重敏感信息泄露（核心DB的SQLi、大量用户/订单/银行卡信息）
4. 核心系统严重逻辑缺陷（批量发伪造消息、任意账号资金消费、批量改密码）
```

### 2d. 中等回报：高危漏洞（基础100-135分 × 业务系数）

```
1. 有限制条件的严重类漏洞（需特定环境/辅助漏洞）
2. 任意文件读取/包含
3. 源码泄露（SVN/Git 导致重要产品线源码泄露）
4. 绕过认证访问后台 / 后台弱密码 / SSRF获取大量内网信息
5. 越权修改他人重要信息/订单操作
6. 自动传播的存储型XSS / 获取BDUSS的XSS / 涉及交易的CSRF
```

### 2e. 不值得打的（忽略级 = 0 分）

```
✗ Self-XSS、仅针对自身浏览器的XSS
✗ 无敏感操作的CSRF
✗ 内网 IP/域名泄露
✗ 无敏感信息的 json hijacking
✗ 不通内网的 SSRF
✗ bcebos.com / bdysite / aipage 域名下的 XSS
✗ 无法重现的漏洞 / 扫描器结果无实际危害证明
✗ 非Chrome才能触发的XSS → 最高低危
✗ AI越狱/Prompt Leak（非隐私数据泄露）→ 不收录
✗ 沙箱内的代码执行（除非能逃逸）
```

---

## PHASE 3: 高效挖掘流程

### 3a. 批量低垂果实扫描（先跑脚本，再手工）

==进入手工挖掘前，对全部存活资产跑一遍低成本批量检查。这些是自动化程度最高、最容易被忽略的漏洞。每个目标 < 5 秒，不会触发频率限制。==

```bash
# 批量 CORS 错配检测
cat $OUTDIR/recon/httpx.jsonl | jq -r '.url' | while read url; do
  curl -sk -H "Origin: https://evil.com" "$url" -o /dev/null -w "%{http_code} | $url | %{response_headers}" 2>/dev/null | \
    grep -i "Access-Control-Allow-Origin.*evil.com\|Access-Control-Allow-Credentials.*true"
done

# 批量安全头缺失检测
cat $OUTDIR/recon/httpx.jsonl | jq -r '.url' | while read url; do
  headers=$(curl -skI "$url" 2>/dev/null)
  missing=""
  echo "$headers" | grep -qi "X-Frame-Options" || missing="$missing X-Frame-Options"
  echo "$headers" | grep -qi "X-Content-Type-Options" || missing="$missing X-Content-Type-Options"
  echo "$headers" | grep -qi "Content-Security-Policy" || missing="$missing CSP"
  echo "$headers" | grep -qi "Strict-Transport-Security" || missing="$missing HSTS"
  [ -n "$missing" ] && echo "[缺失] $url →$missing"
done

# 批量目录列举检测（常见开放目录）
for suffix in .git/HEAD .env .DS_Store .svn/entries robots.txt sitemap.xml crossdomain.xml; do
  cat $OUTDIR/recon/httpx.jsonl | jq -r '.url' | while read url; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$url/$suffix" 2>/dev/null)
    [ "$code" = "200" ] && echo "[+] $url/$suffix → HTTP $code"
  done
done

# 批量 debug 端点检测
for debug_path in actuator /actuator/health /debug /phpinfo.php /info.php /_debug /api/debug /console; do
  cat $OUTDIR/recon/httpx.jsonl | jq -r '.url' | while read url; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "$url$debug_path" 2>/dev/null)
    [ "$code" = "200" ] && echo "[DEBUG] $url$debug_path → HTTP $code"
  done
done

# 批量开放重定向检测
cat $OUTDIR/recon/httpx.jsonl | jq -r '.url' | while read url; do
  code=$(curl -sk -o /dev/null -w "%{http_code} | %{redirect_url}" "$url?redirect=https://evil.com&url=https://evil.com&next=https://evil.com&return=https://evil.com" 2>/dev/null)
  echo "$code" | grep -q "evil.com" && echo "[开放重定向] $url → $code"
done
```

==命中后: CORS/安全头 → 写 vulns/，标注 BSRC 低危(3-6分)；.git/.env/actuator → 跳 web-exploit P0 信息泄露流程；开放重定向 → 尝试组合利用(SSRF绕过/OAuth劫持)。==

### 3b. 针对系数 7-10 业务的挖掘 checklist

```
[ ] passport.baidu.com — 认证绕过/逻辑缺陷/CSRF→改密码
[ ] 百度云控制台 — AKSK泄露/越权/SSRF/云函数RCE
[ ] 文心一言 — 训练数据泄露/越权获取他人对话/模型架构篡改
[ ] 百度APP — Deeplink漏洞/WebView RCE/BDUSS泄露
[ ] 百度搜索 — XSS(获取BDUSS)/SSRF/开放重定向链
[ ] 百度地图 — API越权/定位信息泄露/支付逻辑
[ ] 百度网盘 — 越权访问他人文件/分享链接泄露/文件上传
[ ] 萝卜快跑 — 交易系统支付逻辑/订单篡改/调度越权
```

### 3c. 通用漏洞挖掘 checklist

```
[ ] SQL注入 — 优先核心业务API参数，手工测试不用sqlmap爆破
[ ] XSS — 存储型>反射型，优先能获取BDUSS的点
[ ] SSRF — 所有URL输入点，用官方靶场验证
[ ] 越权 — 水平越权(改ID查他人数据)、垂直越权(普通用户→管理员)
[ ] 文件上传 — 图片上传点尝试绕过扩展名检测
[ ] 逻辑漏洞 — 支付金额篡改、优惠叠加、短信绕过风控
[ ] 信息泄露 — API返回多余字段、错误信息泄露栈、源码打包泄露
```

---

## PHASE 4: 漏洞提交（格式合规）

### 4a. 提交标准（必须满足，否则退回）

```
1. 网络请求用纯文本/附件提交原始数据包，不可仅截图
2. 站点域名准确，报告围绕提交域名说明
3. 漏洞名称与报告证明一致，不夸大危害
```

### 4b. 提交模板

```
漏洞标题: [漏洞类型] [域名] [简述]
例: SQL注入 cloud.baidu.com 某API接口参数未过滤

站点域名: cloud.baidu.com

漏洞类型: SQL注入

漏洞等级: 高危

漏洞描述:
  在 https://cloud.baidu.com/api/xxx 接口中，
  参数 xxx 未做有效过滤，可通过构造 payload 获取数据库信息。

复现步骤:
  1. 登录百度账号，访问 xxx
  2. 抓包修改参数 xxx 为 xxx
  3. 发送请求，返回 xxx

原始数据包:
  [粘贴完整HTTP请求/响应]

漏洞证明:
  - 读取到 hostname: xxx
  - 数据库版本: xxx
  - 获取数据条数: ≤10条

影响范围:
  影响 xxx 业务的 xxx 功能

修复建议:
  对参数 xxx 进行 xxx 过滤
```

### 4c. 加分/扣分规则

```
加分:
  + 提供详细URL/数据包/触发点
  + 提供完整复现步骤和账户权限说明
  + 漏洞发现方式新颖
  + 3个以上同类问题打包提交

扣分:
  - 不贴URL链接
  - 无法稳定复现
  - 10位以上混合字符爆破才能触发
  - DoS类漏洞仅给fuzz调试信息无具体问题函数
```

---

## PHASE 5: 积分最大化策略

### 5a. 积分计算公式

```
安全币 = 基础安全币 × 业务系数

| 业务系数  | 严重(200-300) | 高危(100-135) | 中危(15-22) | 低危(3-6) |
|----------|-------------|-------------|-----------|---------|
| 高(7-10) | 1400-3000   | 700-1350    | 105-220   | 21-60   |
| 中(2-6)  | 400-1800    | 200-810     | 30-132    | 6-36    |
| 低(1)    | 200-300     | 100-135     | 15-22     | 3-6     |

安全币:现金 = 1:5

特殊加成:
  RCE通内网/控集群 → 基础积分 × 3
  高质量漏洞 → 额外 1~50万现金
  通用漏洞首发 → 双倍积分
```

### 5b. ROI 最高的挖掘路径

==此表是理论最高分，不是执行顺序。执行时先跑低成本自动化脚本（SSRF/未授权API），再手工打高价值目标。==

```
理论最高分:
1. 系数7-10业务 + RCE     → 1400-3000 × 3 = 4200-9000 分
2. 任何业务 + SSRF完全回显  → 固定 600 分
3. 系数7-10业务 + 严重逻辑  → 1400-3000 分
4. 系数7-10业务 + SQLi获取权限 → 1400-3000 分
5. 系数7-10业务 + 高危越权   → 700-1350 分
```

---

## 同类问题合并规则

==不要重复提交同类漏洞，会被合并==

```
合并规则:
  - 同接口不同参数 → 算1个
  - 同JS引起的多个漏洞 → 算1个
  - 同站点debug/phpinfo多处泄露 → 算1个
  - 同函数/接口被不同路径调用 → 算1个
  - 同域名同类问题30工作日内 → 只收前3个（建议打包提交）
  - 修1个其他自动修复 → 算1个
```

---

## 行为指令

拿到百度目标后：

1. **确认 BSRC UID** → 询问用户是否有 BSRC 账号和 UID
2. **识别业务系数** → 判断目标域名/产品属于哪个系数档
3. **合规侦察** → 被动信息收集 + 轻量指纹识别，不做全端口/C段
4. **选择攻击面** → 按执行成本从低到高排序。==SSRF 排第一是因为 BSRC 固定 600 分不分业务系数，自动化成本最低回报确定。== SSRF（ssrf_probe.py 批量扫，600 固定分）→ P0 未授权 API（api_probe.py 批量）→ RCE/CVE（nuclei + POC）→ 严重逻辑漏洞（手工为主）→ 高危越权（手工逐个 API）
5. **手工深挖** → 脚本批量扫完后，top-N 结果才手工深入，避免自动化扫描触发报警
6. **最小化验证** → 证明漏洞存在即可，数据 ≤10 条，SSRF 用靶场
7. **整理报告** → 按提交模板准备，附原始数据包
8. **提交到 bsrc.baidu.com**
