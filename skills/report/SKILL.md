---
description: 渗透测试报告生成。汇总所有阶段数据、漏洞详情、攻击链、证据、修复建议。参考手册见 SKILL.ref.md
---

# 报告生成

## 硬规则
1. 先汇集所有数据（timeline/credentials/vulns/evidence），再动笔
2. 每个漏洞必须有：标题、URL、复现步骤、请求/响应证据、危害说明、修复建议
3. 不套模板，不删减。个人使用，越详细越好

## 报告结构
```
1. 概述         — 目标/范围/时间/方法论
2. 资产清单     — 存活子域名/端口/技术栈/WAF
3. 漏洞详情     — 按严重度排序，含复现+截图+修复
4. 攻击链       — 漏洞组合利用路径
5. 附录         — 原始扫描/timeline导出/工具输出
```

## 数据来源
```
recon        → targets/ + vulns/
web-exploit  → credentials/ + vulns/
post-exploit → credentials/found.json + 内网信息
evidence/    → 截图 + curl 数据包
```

> 详细模板、奖金计算、补天/火线格式见 SKILL.ref.md
