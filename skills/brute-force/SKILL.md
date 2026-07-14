---
description: 凭据爆破。Web/SSH/RDP/DB/Redis/LDAP/SNMP 服务爆破。参考手册见 SKILL.ref.md
---

# 凭据爆破

## 硬规则
1. 爆破须过6-gate（endpoints/JS/info_leaks/lockout 全完成）
2. 爆破前1次错误密码试探 → 观察锁定提示
3. SRC 模式禁止爆破（仅允许手工2-3次测试）
4. 红队模式：检测到锁定立即停止

## 决策树
```
验证码/锁定/频率限制 → 绕过优先，不直接跑密码
Redis/MongoDB → 先测未授权 → 再试默认凭据 → 最后 hydra
Web登录 → 手工2-3次 → 确认无锁定 → 小字典 → 大字典
SSH/RDP → hydra -t 4 低并发
数据库 → 先搜代码/配置文件中的连接串
```

## 字典
```
默认凭据: seclists/Passwords/Default-Credentials/
弱口令:   dirb/common.txt top 100
通用:     rockyou.txt 头1000
专用:     目标行业/地名/年份组合
```

> 命令模板、频率参数见 SKILL.ref.md
