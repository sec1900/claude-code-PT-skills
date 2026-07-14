---
description: AD域渗透。从域用户到Domain Admin全链路。参考手册见 SKILL.ref.md
---

# AD 域渗透

## 触发条件
recon 或 post-exploit 发现 Kerberos/LDAP/SMB/AD 服务时触发

## 攻击链
```
1. 域枚举       → BloodHound/SharpHound/PowerView
2. Kerberoasting → 请求TGS → hashcat离线破解
3. AS-REP        → 无需凭据 → 破解用户hash
4. ACL滥用       → GenericAll/WriteDacl/ForceChangePassword
5. 委派攻击      → 非约束/约束/RBCD
6. DCSync        → 复制域控hash → 金票/银票
7. AD CS         → ESC1-8 证书模板滥用
8. 跨域信任      → 子域→父域
9. NTDS提取      → ntds.dit + SYSTEM → secretsdump
```

> 完整命令、ESC1-8详解见 SKILL.ref.md
