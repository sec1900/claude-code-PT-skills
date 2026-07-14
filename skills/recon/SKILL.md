---
description: 信息收集。SRC(宽度优先)和 RedTeam(深度优先)双模式。参考手册见 SKILL.ref.md
---

# 信息收集

## 硬规则

1. 不污染目标：禁注册/提交/写入；用户枚举用只读差异检测
2. 被动先行：R1(SSL/DNS/JS/响应头) → R2(JS深入/泄露) → R3(指纹/nuclei/ffuf) → R4(端口扫描)
3. 端口扫描低速率：--min-rate 500 -T3
4. 敏感路径须校验 body：SPA 站点 200 不等于文件存在，验证 body hash 和特征内容
5. 操作前查 timeline.jsonl：已 done 的跳过
6. 工具容错降级：nmap SYN被拦→-sT -Pn；nuclei 超时→分端口；ffuf 被 ban→降-t
7. 先1后N：批量操作先跑1个验证通过再铺开
8. 失败先诊断：报错后先看 --help、file $(which xxx)，不盲重试
9. 3次未果强制切换下一个目标
10. 所有网络请求走 Kali SSH，不在 Windows 本地跑 curl
11. SRC 禁止：全端口扫描、C段扫描、高频爆破、并发数>2
12. RedTeam 禁止：漏掉全端口和C段

## 流程

### 步骤 0：Scope 确认（禁止跳过，先于一切）
```
1. 读 scope 文件/CSV，提取所有 in-scope 域名
2. 标注 OOS 项
3. 用户确认 scope 无误
⚠️ scope 未确认前禁止子域名枚举、禁止端口扫描、禁止任何网络请求
```

### 步骤 1：场景判断（先做，在扫描前）
```
目标: xxx
场景: SRC(企业/公益) / 红队授权 / CTF
规则: [链接]
边界: 允许xxx / 禁止xxx
→ 用户确认后进入步骤2
```

### 步骤 2：模式选择
```
公司名/根域名 → SRC（宽度优先）
子域名/IP → RedTeam（深度优先）
```

### SRC 模式步骤
```
1. 场景判断 → 用户确认
2. 子域名枚举（先1个验证，再铺开，并发≤2）
3. httpx 批量探活（走 Kali）
4. 存活筛选 + 指纹识别
5. nuclei 必跑（禁止跳过）：
   nuclei -l alive.txt -t ~/nuclei-templates/ -es info -timeout 10 -rl 2
6. 敏感路径探测（校验 body）
7. JS/API 信息泄露提取
8. 结果汇总 → 交 web-exploit
```

### RedTeam 模式步骤
```
1. 场景判断 → 用户确认
2. 全端口扫描（低速率）
3. 多端口服务识别 + 差异对比
4. 子域名枚举 + 探活
5. C段扫描
6. 指纹 + nuclei + ffuf
7. 结果汇总 → 交 web-exploit
```

## SRC 禁止（违反任一条 → 停止回退）
```
- scope 未确认就枚举子域名
- 对 OOS 资产做任何扫描/探测
- nuclei 未跑就进入 web-exploit
- 子域名枚举超过 scope 范围（如 crt.sh 拉全量后不过滤）
- Cloudflare 后资产不做源 IP 发现（censys/shodan/securitytrails）
```

> 命令模板、字典路径、参考表见 SKILL.ref.md
