---
description: 漏洞链组合利用。单漏洞不足以攻击时，组合多个低危→高危。参考手册见 SKILL.ref.md
---

# 漏洞链组合利用

## 触发条件
单个漏洞无法完成高危利用，需串联多步时触发

## 组合模式速查
```
1. SSRF + 内网未授权        → 外网盲SSRF → 内网探测 → 内网RCE
2. XSS + CSRF              → 反射XSS → 同源伪造 → 管理员操作
3. 文件读取 + 配置泄露      → LFI读配置 → DB凭据 → 外连数据库
4. 低权账户 + 越权          → 注册用户 → IDOR → 管理员数据
5. OAuth misconfig         → 客户端注册缺陷 → token劫持
6. 不出网 + 内存马          → 反序列化 → 不出网利用链 → filter注入
7. K8s SA低权 + RBAC滥用    → 默认SA → 枚举权限 → 特权Pod
8. CI/CD + 仓库泄露         → .git泄露 → CI凭据 → 生产环境
9. 云AK泄露 + IAM提权       → JS/S3中AK → 角色映射 → AssumeRole
10. VPN设备 + 默认口令      → SSL VPN探测 → CVE → 配置导出
```

> 15种完整模式、每步命令、案例见 SKILL.ref.md
