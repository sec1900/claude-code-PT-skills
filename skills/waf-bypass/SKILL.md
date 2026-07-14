---
description: WAF绕过。被阿里云/腾讯云/Nginx/Cloudflare/宝塔拦截时触发。参考手册见 SKILL.ref.md
---

# WAF 绕过

## 硬规则
1. 先识别 WAF 类型（whatweb/wafw00f/响应头/拦截页特征），再选策略
2. 绕过优先级：编码 → 分块 → 协议层 → DB 特性，不跳级
3. 国内 WAF 优先用 DB 版本特性绕过

## WAF → 策略速查
```
阿里云(yundun/aliyun)   → 分块传输 + HTTP/2 + Tengine 特性
腾讯云(Tencent)         → 编码矩阵 + multipart 混淆
Cloudflare(cf-ray)      → 源IP直连 + CF-Connecting-IP 伪造
宝塔/BT                 → GET/POST 混用 + HTTP/0.9
Nginx ModSecurity       → 分块重叠 + multipart boundary
长亭 SafeLine           → JSON 嵌套 + unicode 编码
```

> 完整编码矩阵、51项技术分类见 SKILL.ref.md
