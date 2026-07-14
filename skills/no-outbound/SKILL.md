---
description: 不出网利用。目标无外连时使用。覆盖回显技术、内存马注入。参考手册见 SKILL.ref.md
---

# 不出网利用

## 触发条件
目标无法反弹shell/DNSLOG无回显/ICMP被禁/仅允许入站HTTP

## 利用链速查
```
Shiro       → CommonsBeanutils1 → 内存马
fastjson    → TemplatesImpl → Spring Controller 内存马
log4j       → 绑定RMI/LDAP端口 → 目标回连
Spring      → /actuator/env → Spring Cloud Gateway 内存马
Tomcat      → JSP落地 → filter/servlet 内存马
```

## 回显技术（按优先级）
```
1. 内存马 — filter/servlet/listener/valve 注入
2. 异常回显 — 触发异常在响应中显示输出
3. 线程回显 — hook 当前请求线程写入 response
4. 延时注入 — sleep/benchmark 逐位猜解
5. 文件写入 — 写 webshell → 写静态文件回显
```

> 完整payload、命令模板见 SKILL.ref.md
