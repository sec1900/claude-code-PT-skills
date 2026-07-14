# Claude Code 渗透测试技能包

为 [Claude Code](https://claude.ai/code) 设计的红队/渗透测试/Bug Bounty 工作流技能集合。提供 15+ 个专业 skill 模块，覆盖从信息收集到后渗透的完整攻击链。

## 安装

将本仓库克隆到 Claude Code 项目的 `.claude/` 目录下：

```bash
git clone https://github.com/YOUR_USERNAME/claude-code-PT-skills.git .claude
```

或者作为子模块引入已有项目：

```bash
git submodule add https://github.com/YOUR_USERNAME/claude-code-PT-skills.git .claude
```

安装后需根据你的环境修改以下占位符：
- `<KALI_IP>` — Kali Linux 渗透机的 SSH 地址
- `<PROXY_HOST>` / `<PROXY_PORT>` — 代理服务器地址和端口
- `<NAS_IP>` — 共享存储/文件服务器地址
- `<HOSTNAME>` — Windows 本机的主机名

## 技能列表

### 侦察与信息收集
| 技能 | 描述 |
|------|------|
| `environment` | 环境自检 — OS 检测、Kali SSH 连通、工具版本、代理状态、工作目录初始化 |
| `recon` | 信息收集 — SRC（宽度优先）和 RedTeam（深度优先）双模式，含子域名枚举、端口扫描、指纹识别、JS 分析、敏感路径探测 |

### 漏洞利用
| 技能 | 描述 |
|------|------|
| `web-exploit` | Web 漏洞利用决策引擎 — 按 P0~P9 优先级自动编排攻击流程，含 SQL 注入/XSS/SSRF/文件上传/反序列化等 |
| `chain-attack` | 漏洞链组合利用 — SSRF+内网、XSS+CSRF、LFI+配置泄露等 15 种组合模式 |
| `waf-bypass` | WAF/IDS 绕过 — Header 变形、编码绕过、分块传输、HTTP 走私 |

### 平台攻击
| 技能 | 描述 |
|------|------|
| `ad-attack` | Active Directory 攻击 — Kerberoasting、AS-REP Roasting、ACL 滥用、域提权、横向移动、凭据窃取 |
| `cloud-attack` | 云平台攻击 — AWS/阿里云/Azure 的元数据窃取、AK/SK 利用、IAM 提权、存储桶枚举 |
| `k8s-attack` | Kubernetes 攻击 — ServiceAccount Token 窃取、RBAC 提权、Pod 逃逸、etcd 攻击 |

### 后渗透
| 技能 | 描述 |
|------|------|
| `post-exploit` | 后渗透 — 数据库敏感数据发现、网络服务利用（Redis/MongoDB/SMB/RDP）、SMTP 邮件系统攻击 |

### 辅助
| 技能 | 描述 |
|------|------|
| `brute-force` | 爆破策略 — 多用户+少量密码喷洒、字典生成、协议爆破（SSH/SMB/RDP/Web/Redis） |
| `report` | 报告生成 — 汇集 timeline/credentials/vulns/evidence，生成标准化渗透测试报告 |
| `baidu-src` | 百度 SRC 专项 — BSRC 合规边界、业务系数表、SSRF 靶场、高回报漏洞策略 |
| `no-outbound` | 不出网场景 — 内存马注入、filter 链利用、反序列化不出网利用链 |
| `network-device` | 网络设备 — VPN 设备、路由器、交换机默认口令与 CVE 利用 |
| `phishing-evasion` | 钓鱼规避 — 邮件网关绕过、EDR 规避、宏免杀 |
| `knowledge-base` | 知识库检索 — 本地知识库查询接口，渗透中遇到未知框架/协议时查阅 |

## 工作流

```
environment → recon → web-exploit → post-exploit → report
                  ↘ chain-attack ↗
```

1. **environment** — 启动自检，确认 Kali SSH、工具、代理、字典就绪
2. **recon** — 场景判断（SRC/红队/CTF），执行信息收集
3. **web-exploit** — 按优先级（P0→P9）自动化攻击编排
4. **post-exploit** — 拿到 shell/数据后深入内网
5. **report** — 汇集数据生成报告

## 目录结构

```
.
├── CLAUDE.md                 # 主配置文件
├── README.md
├── LICENSE
└── skills/
    ├── environment/          # 环境自检
    │   ├── SKILL.md          # 技能指令
    │   ├── SKILL.ref.md      # 参考手册（命令模板、字典路径等）
    │   └── scripts/          # 自动化脚本
    ├── recon/                # 信息收集
    │   ├── SKILL.md
    │   ├── SKILL.ref.md
    │   ├── scripts/          # Python 工具脚本（13个）
    │   ├── data/             # 字典/指纹/规则库
    │   └── reference/        # 方法论参考
    ├── web-exploit/          # Web 漏洞利用
    │   ├── SKILL.md
    │   ├── SKILL.ref.md
    │   └── reference/        # 各攻击类型详细方法论（20+篇）
    ├── post-exploit/         # 后渗透
    ├── ad-attack/            # AD 攻击
    ├── cloud-attack/         # 云平台攻击
    ├── k8s-attack/           # K8s 攻击
    ├── chain-attack/         # 漏洞链组合
    ├── waf-bypass/           # WAF 绕过
    ├── brute-force/          # 爆破策略
    ├── report/               # 报告生成
    ├── baidu-src/            # 百度 SRC
    ├── no-outbound/          # 不出网场景
    ├── network-device/       # 网络设备
    ├── phishing-evasion/     # 钓鱼规避
    └── knowledge-base/       # 知识库
```

## 脚本工具

`recon/scripts/` 目录包含以下 Python 工具：

| 脚本 | 用途 |
|------|------|
| `api_probe.py` | 批量 API 未授权访问探测（GET+POST） |
| `cors_check.py` | CORS 错配检测 |
| `finger_match.py` | 指纹匹配（基于 fingerprints_merged_v5.json） |
| `jwt_probe.py` | JWT token 解析与弱点检测 |
| `leak_probe.py` | 信息泄露探测（.git/.env/swagger 等） |
| `mitm_plugin.py` | MITM 代理辅助插件 |
| `openredirect_probe.py` | 开放重定向探测 |
| `passive_tag.py` | 被动标记（基于响应头/body 自动标记攻击面） |
| `playwright_crawler.py` | Playwright 动态爬虫（SPA 站点 API 提取） |
| `priority_filter.py` | 攻击优先级过滤（按 fingerprint 排序） |
| `sensitive_scanner.py` | 敏感信息扫描（密钥/密码/Token 正则匹配） |
| `ssrf_probe.py` | SSRF 批量探测 |
| `timeline.py` | 操作时间线记录（jsonl 格式） |
| `validate_target.py` | target.json 完整性校验 |
| `webpack_extract.py` | webpack 打包文件解析与 API 提取 |

## ⚠️ 法律免责声明

本项目提供的技能、脚本和方法论**仅供以下合法用途使用**：

1. **授权的渗透测试/红队评估** — 已获得目标组织书面授权的安全测试
2. **漏洞悬赏计划（Bug Bounty）** — 在平台规则范围内进行的漏洞发现
3. **学术研究与安全教育培训** — 在隔离的实验环境中进行
4. **CTF 竞赛** — 信息安全技能竞赛

**使用者必须：**
- 获得目标系统所有者的明确书面授权
- 严格遵守当地法律法规及授权范围的限制条件
- 对自己的所有行为承担全部法律责任

**本项目作者不对任何未经授权、非法或滥用行为承担责任。使用本项目即表示你同意自行承担所有风险和责任。**

## 致谢

本项目参考了以下开源项目和方法论：

- [SecLists](https://github.com/danielmiessler/SecLists) — 渗透测试字典集
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — Nuclei 漏洞模板
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload 大全
- [OneForAll](https://github.com/shmilylty/OneForAll) — 子域名收集工具
- [BBScan](https://github.com/lijiejie/BBScan) — 批量漏洞扫描器
- [phpggc](https://github.com/ambionics/phpggc) — PHP 反序列化 Gadget Chain 库
- [wafw00f](https://github.com/EnableSecurity/wafw00f) — WAF 指纹识别
- [dirsearch](https://github.com/maurosoria/dirsearch) — Web 路径扫描器

## License

MIT License — 详见 [LICENSE](LICENSE) 文件。
