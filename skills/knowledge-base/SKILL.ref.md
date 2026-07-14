---
description: 红队渗透测试知识库索引。当需要查阅某个领域的深度知识时，引导agent阅读相关目录下的具体文件。
---

# 红队知识库（novecento）

> 本文件是知识库索引。具体攻击方法论见各 skill 的 SKILL.md：@recon.md / @web-exploit.md / @waf-bypass.md / @chain-attack.md / @post-exploit.md / @no-outbound.md / @k8s-attack.md / @ad-attack.md / @cloud-attack.md / @network-device.md / @phishing-evasion.md。

## 路径配置

==知识库路径:==
- Kali: `/mnt/share/novecento`
- Kali skills 子目录: `/mnt/share/novecento/skills/`
- Windows: `\\<NAS_IP>\share\novecento`

==私有 POC 库路径:==
- Kali: `/mnt/share/poc`
- Windows: `\\<NAS_IP>\share\poc`
- 格式: nuclei yaml 模板，按厂商分目录（1901 个模板，22 个厂商）
- 覆盖: 大华/海康/泛微/用友/致远/万户/信湖/红帆/宏景/金和/蓝凌/畅捷通/JeeCG 等国内 OA/ERP/安防

Agent 在 Kali 下直接使用 `/mnt/share/novecento` 路径读取。Windows 下由用户告知路径后替换。

Skills 子目录包含按漏洞类型分类的利用入口（`skills/{类型}/SKILL.md`），详见下方「漏洞类型 Skills 索引」章节。

## 知识库结构

```
novecento/
├── 01-信息收集/          (29篇)
│   ├── OSINT与社工/
│   ├── 内网/
│   └── 外网/
├── 02-外围打点/          (37篇)
│   ├── checklist/
│   ├── Web漏洞/
│   ├── 绕waf/
│   └── 供应链批量挖掘.md
├── 03-漏洞利用/          (39篇)
│   ├── 代码审计/
│   └── 组件漏洞/
├── 04-后渗透/            (75篇)
│   ├── Windows安全/ 域渗透/ 提权/ 横向移动/ 权限维持/ 凭据获取/
│   ├── 不出网利用.md
│   ├── 内网对抗姿势.md
│   └── OA后渗透思路.md
├── 05-免杀与Webshell/    (10篇)
├── 06-工具与命令/        (78篇)
│   ├── C2/ 代理&隧道/ 反弹shell/ 扫描器/ 爆破&字典/
│   ├── 数据库相关/ 文件传输/ 钓鱼/
│   └── 各类工具速查
├── 07-红队基建/          (5篇)
│   ├── ARL资产灯塔 / C2搭建 / CS域前置 / dnslog / 流量隐藏
├── 08-应急响应/          (9篇)
├── 09-靶场笔记/          (8篇)
├── 10-杂项/             (14篇)
└── 11-实战经验/          (10篇) ← 最精华，来自真实渗透的踩坑和复盘
    ├── C2反制实战复盘.md
    ├── C2反制方法论.md
    ├── Nginx-WAF绕过实战.md
    ├── Stored-XSS实战投递.md
    ├── ThinkPHP实战踩坑.md
    ├── 多IP多端口对比分析.md
    ├── 宝塔面板渗透.md
    ├── 漏洞链组合利用.md
    ├── 红队攻击链决策树.md
    └── 验证码识别与爆破.md
```

## Skill → 知识库 映射

当使用某个 skill 时，agent 应同时查阅对应的知识库目录获取更深入的内容：

| Skill | 知识库路径 | 关键文件 |
|---|---|---|
| `recon` | `01-信息收集/` | 外网/、内网/、OSINT与社工/ |
| `web-exploit` | `02-外围打点/Web漏洞/` | 相关漏洞类型文件 |
| `waf-bypass` | `02-外围打点/绕waf/`、`11-实战经验/Nginx-WAF绕过实战.md` | WAF绕过技巧 |
| `chain-attack` | `11-实战经验/漏洞链组合利用.md`、`11-实战经验/红队攻击链决策树.md` | 漏洞链方法论 |
| `brute-force` | `06-工具与命令/爆破工具&字典/`、`11-实战经验/验证码识别与爆破.md` | hydra/crackmapexec/kerbrute/字典策略 |
| `post-exploit` | `04-后渗透/`、`11-实战经验/C2反制实战复盘.md`、`11-实战经验/C2反制方法论.md` | 提权/横向/权限维持/凭据获取/C2反制 |
| `no-outbound` | `04-后渗透/不出网利用.md`、skills 目录 | 内存马注入/回显技术/各框架不出网链 |
| `k8s-attack` | `04-后渗透/` | K8s RBAC/escalation/etcd/Admission Controller |
| `phishing-evasion` | `05-免杀与Webshell/`、`06-工具与命令/钓鱼/` | 免杀/样本投递/C2流量伪装/邮件绕过 |
| `baidu-src` | —（百度 SRC 合规规则，不涉及具体攻击技术） | — |
| `ad-attack` | `04-后渗透/域渗透/` | Kerberoasting/DCSync/委派/AD CS/跨域 |
| `cloud-attack` | `04-后渗透/` | AWS IAM提权/S3/Azure AD/阿里云 RAM |
| `network-device` | `02-外围打点/checklist/`、`06-工具与命令/扫描器/` | VPN漏洞/防火墙/路由器/交换机/SNMP/默认凭据 |
| `environment` | `10-杂项/渗透环境/`、`07-红队基建/kali配置&错误处理.md` | Kali配置/工具安装/网络问题 |
| `report` | `11-实战经验/` | 各复盘报告的写法和结构 |

| APK 分析 | `02-外围打点/`、`11-实战经验/` | APK→C2 地址提取、加固检测、Frida 脱壳、UniApp JS 层分析 |
| 免杀需求 | `05-免杀与Webshell/` | Webshell/、免杀/ |
| 隧道/代理 | `06-工具与命令/代理&隧道工具/` | 代理&隧道工具/ |
| 反弹shell | `06-工具与命令/反弹shell/` | 反弹shell/ |
| 爆破需求 | `06-工具与命令/爆破工具&字典/`、`11-实战经验/验证码识别与爆破.md` | 爆破工具 |
| 数据库操作 | `06-工具与命令/数据库相关/` | 数据库相关/ |
| 域渗透 | `04-后渗透/域渗透/` | 域渗透/ |
| 应急/查杀 | `08-应急响应/` | linux/、windows/、内存马查杀 |

## 降级模式

当 `/mnt/share/novecento` 不可用时（未挂载/路径不存在），agent 自动进入降级模式：

1. 使用各 skill 内置的决策树和检查清单
2. 依赖 skill 自身的方法论章节
3. 对需要深度参考的领域，使用搜索引擎 + 官方文档

降级模式下内置知识覆盖：
- 红队攻击链决策树 → `web-exploit.md`（搁置判断 + 转向规则章节）
- 漏洞链组合模式（7 种） → `chain-attack.md`
- ThinkPHP 攻击决策树 → `web-exploit.md`（P1 CVE匹配 + P3 数组注入章节）
- WAF 绕过矩阵 → `waf-bypass.md`
- 后利用标准操作 → `post-exploit.md`
- 侦察并行化策略 → `recon.md`

## Agent 使用指令

遇到任何技术问题时，按以下优先级查找知识：

```
优先级 1: 私有 POC 库（/mnt/share/poc/）
  → 指纹识别出厂商后，先查 poc/{厂商}/ 目录是否有对应 nuclei 模板
  → 有 → 直接 nuclei -u TARGET -t /mnt/share/poc/{厂商}/
  → 覆盖国内冷门厂商，这是公开 nuclei 模板库没有的

优先级 2: 知识库 skills/ 专项 SKILL.md（/mnt/share/novecento/skills/）
  → 识别到漏洞类型后，读取 skills/{类型}/SKILL.md + references/
  → 77 个漏洞类型覆盖通用攻击方法论

优先级 3: 知识库文章目录（01-11）
  → 需要更深入的原理、工具用法、案例分析时
  → 先 ls 对应目录看有哪些文件，再读取最相关的

优先级 4: 联网搜索
  → 知识库和 POC 库都没覆盖的新漏洞
  → 新版本框架的新特性/新绕过
  → 搜索时优先查: 官方文档 > HackerOne 报告 > 安全博客 > GitHub PoC
```

### 指纹 → POC 匹配逻辑

指纹识别不限定具体工具（httpx/whatweb/EHole 或未来的新工具都可以），关键是拿到技术栈信息后做匹配：

```
拿到指纹结果后：
1. 提取厂商/产品关键词（如"用友 NC"、"泛微 OA"、"致远 A8"）
2. ls /mnt/share/poc/ 看有没有匹配的厂商目录
3. 有 → nuclei -u TARGET -t /mnt/share/poc/{厂商}/
4. 同时查 novecento/skills/ 和 novecento/03-漏洞利用/组件漏洞/ 获取利用方法论
5. 都没有 → 走黑盒测试 checklist（novecento/02-外围打点/checklist/）
```

### POC 库厂商目录速查

```
/mnt/share/poc/
├── changjietong/  # 畅捷通
├── dahua/         # 大华安防
├── fanwei/        # 泛微 OA
├── hanwang/       # 汉王
├── hikvision/     # 海康威视
├── hongfan/       # 红帆
├── hongjing/      # 宏景
├── jboss/         # JBoss
├── jeecg/         # JeeCG-Boot
├── jinhe/         # 金和
├── lanlin/        # 蓝凌 OA
├── meite/         # 美特
├── springboot/    # Spring Boot
├── swagger/       # Swagger
├── tomcat/        # Tomcat
├── uncategorized/ # 未分类
├── vue/           # Vue 前端
├── wanhu/         # 万户 OA
├── weblogic/      # WebLogic
├── xinhu/         # 信湖 OA
├── yongyou/       # 用友
└── zhiyuan/       # 致远 OA
```

==POC 库由用户自行维护和更新。agent 不修改 POC 库内容，只读取和使用。==

## 漏洞类型 Skills 索引

遇到具体漏洞时，读取知识库 skills 子目录下对应的 `SKILL.md` 作为利用参考：

```
novecento/skills/{漏洞类型}/SKILL.md       ← 入口，方法论+检查清单
novecento/skills/{漏洞类型}/references/    ← 参考资料
novecento/skills/{漏洞类型}/scripts/       ← 可用脚本
```

常见映射示例：
- SQL 注入 → `skills/injection/SKILL.md`
- CORS → `skills/cors/SKILL.md`
- 文件上传 → `skills/upload/SKILL.md`
- 反序列化 → `skills/deserialization/SKILL.md`
- SSRF → `skills/ssrf/SKILL.md`
- 请求走私 → `skills/request_smuggling/SKILL.md`
- WAF 绕过 → `skills/waf_bypass/SKILL.md`

当前可用的漏洞类型（77个）：

```
account_takeover    api_key_leaks       api_security        auth_bypass
broken_access_control brute_force_rate_limit business_logic  clickjacking
client_side_path_traversal cloud_security cors              crlf_injection
csrf                css_injection       csv_injection       denial_of_service
dependency_confusion deserialization    dns_rebinding       dom_clobbering
domain_pentest      encoding_transformations external_variable_modification
file_inclusion      google_web_toolkit  hidden_parameters   http_parameter_pollution
idor                info_disclosure     injection           insecure_management_interface
insecure_randomness insecure_source_code_management java_rmi jwt_attack
latex_injection     ldap_injection      linux_privesc       middleware_exploit
misconfiguration    nosql_injection     oauth_misconfiguration open_redirect
orm_leak            password_attack     phishing            prompt_injection
prototype_pollution race_condition      recon               regular_expression
request_smuggling   reverse_proxy_misconfigurations reverse_shell
saml_injection      server_side_include_injection src_redteam_playbook
ssrf                ssti                tabnabbing          traffic_analysis
type_juggling       upload              virtual_hosts       waf_bypass
web_cache_deception websockets          windows_persistence windows_privesc
xpath_injection     xs_leak             xslt_injection      xss
xxe                 zip_slip
```

在渗透过程中识别到目标存在某类漏洞时，**自动读取对应 SKILL.md**，将其中的检查清单和利用方法应用到当前目标。

## 路径切换

```bash
# Kali 环境（默认）
KB="/mnt/share/novecento"

# Windows 环境（用户需告知具体路径后替换）
# KB="D:/Obsidian/novecento"
```
