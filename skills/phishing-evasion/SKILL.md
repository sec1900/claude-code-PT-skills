---
description: 钓鱼攻击与免杀。红队授权钓鱼演练专用。参考手册见 SKILL.ref.md
---

# 钓鱼免杀

## 硬规则
1. 仅红队授权场景使用，SRC 禁止任何社工/钓鱼
2. 沙箱测试通过后再投递
3. 载荷先过 Defender/360 免杀再发

## 攻击链
```
1. 邮件伪造  → SPF/DKIM/DMARC检查 → 伪造发件人
2. 载荷免杀  → shellcode加密 → 混淆 → 反沙箱 → 签名
3. 投递格式  → Office宏/HTA/CHM/ISO/LNK/PDF
4. 钓鱼页面  → 登录页克隆 + 凭据捕获 + 重定向
5. C2通信    → HTTPS隧道 → CDN域前置 → 流量伪装
```

## 免杀优先级
```
1. shellcode 混淆加密 (AES/XOR/RC4)
2. API 动态调用 (GetProcAddress)
3. 反沙箱检测 (内存/CPU/进程数/时区)
4. 代码签名伪造/借用
5. 进程注入/unhooking
```

> 免杀矩阵、C2配置见 SKILL.ref.md
