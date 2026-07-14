---
description: 运行环境配置与启动自检。在进入 recon 之前调用。自动检测操作系统、工具可用性、字典路径、代理状态、工作目录，支持从中断处恢复。本项目在 Windows 系统上运行 Claude Code，通过 SSH 连接 Kali Linux 执行渗透工具。
---

# 运行环境

## ⚠ 硬规则（无论何时必须遵守）

```
1. Kali SSH = root@<KALI_IP> — 不要猜 IP，不是 <NAS_IP>（那是 NAS）。
2. VPN 内网绕过代理 — tun0 存在时，对 10.0.0.0/8 等私有 IP 用 --noproxy / no_proxy。ffuf 需设环境变量。
3. SSH 复杂脚本用 heredoc — 不要内联 for 循环（引号嵌套会全部失败）。
4. 高风险命令单独发 — nmap/nuclei 不和 curl 放同一批并行调用（超时会取消同批其他任务）。
5. Skill 缺陷写 feedback.jsonl — 不是写 memory，路径: //<HOSTNAME>/share/stcs/feedback.jsonl。
6. 连通性先测再定策略 — 代理可达/直连可达/都不通，分别处理。不默认 --noproxy。
7. 目录结构必须初始化 — meta.json + timeline.jsonl + 全部子目录，否则后续无法持久化。
8. 旧任务数据先确认再清理 — 有 meta.json 时先读内容确认是否同目标，不要盲删。
9. Windows 禁用 grep -P — Windows Git Bash 的 grep 不支持 Perl 正则（-P/-oP）。替代: grep -E（扩展正则）或 Python re 模块。所有命令模板应使用 grep -E，不用 grep -P。Kali SSH 环境下 grep -P 可用。
```

## 架构

```
┌─────────────────────────┐     SSH      ┌──────────────────────┐
│  Windows (本机)          │ ──────────→ │  Kali Linux (工具机)  │
│  - Claude Code 运行      │  kali@IP    │  - nmap/nuclei/ffuf   │
│  - Playwright 浏览器     │             │  - sqlmap/hydra/nikto │
│  - 文件编辑/报告生成     │             │  - ddddocr/python3    │
│  - .claude/skills/ 存放  │             │  - hashcat/john       │
└─────────────────────────┘             └──────────────────────┘
```

## 默认连接配置

```
Kali SSH:  root@<KALI_IP> (RDP/SSH 网段)
Kali Root: root (渗透工具需要 root 权限)
工具路径:  /usr/bin, /usr/local/bin, ~/.local/bin
Shell:     zsh
```

==Kali IP 是 <KALI_IP>，不是 <NAS_IP>（那是 NAS）。不要猜 IP，直接用这个。==

## 启动自检

==每次渗透任务开始前执行。优先用脚本，脚本不可用才手动。==

**一键自检（推荐）：**
```bash
python ${CLAUDE_SKILL_DIR}/scripts/bootstrap_check.py > /tmp/bootstrap_result.json 2>/tmp/bootstrap_errors.log
```
脚本自动检测：Kali SSH、Kali 工具、Burp 代理、Burp MCP、v2rayN、共享目录、指纹库/规则库。输出 JSON + 摘要。

**如果脚本不可用，按以下步骤手动执行。**

### 步骤 0：OS 检测与 SSH 连通性

```bash
uname -s
# Linux → Kali 本地执行模式
# MINGW* → Windows SSH 到 Kali 模式

# Windows 模式 — 检测 SSH 连通性
ssh -o ConnectTimeout=5 -o BatchMode=yes root@<KALI_IP> 'echo OK' 2>&1
```

### 步骤 1：工具可用性

```bash
ssh root@<KALI_IP> 'which nmap nuclei ffuf sqlmap whatweb nikto hydra gobuster httpx subfinder curl openssl dig whois python3 2>&1'
# 额外验证 httpx 是 ProjectDiscovery Go 版，不是 PyPI 的 Python HTTP 库
ssh root@<KALI_IP> 'httpx --version 2>&1 | head -1'  # 预期输出含 projectdiscovery
# 如果输出是 "Usage: httpx [OPTIONS] URL" 或无 projectdiscovery → 是 PyPI 版，需 go install
```
```

### 步骤 2：字典路径

```bash
# Kali 字典
ssh root@<KALI_IP> 'ls /usr/share/wordlists/rockyou.txt /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 2>&1'
# 共享文件夹备选
ls "\\<NAS_IP>\share\SecLists\Discovery\Web-Content\" 2>/dev/null
```

### 步骤 3：网络连通性检测与代理配置

==代理不是干扰，可能是到达目标的唯一路径。先测通再定策略。==

```bash
# 网络拓扑: Kali VM (Hyper-V) → Internal 网卡 → 物理机 v2rayN (SOCKS5/HTTP 同端口)

# 3a. 检测代理环境
env | grep -i proxy

# 3b. proxychains4 配置（nmap 等 socket 工具需要）
if ! command -v proxychains4 >/dev/null 2>&1; then apt install -y proxychains4; fi

# 3c. 目标可达性双路测试
TARGET="<用户提供的目标地址>"
PROXY_CODE=$(curl -sk -o /tmp/.proxy_body -w "%{http_code}" --connect-timeout 8 "$TARGET" 2>/dev/null)
DIRECT_CODE=$(curl -sk --noproxy "*" -o /dev/null -w "%{http_code}" --connect-timeout 8 "$TARGET" 2>/dev/null)
echo "代理: HTTP $PROXY_CODE | 直连: HTTP $DIRECT_CODE"

# 3d. 判定连通性并设定策略
case 情况 in
  proxy_required)     CURL_OPTS="" NMAP_PREFIX="proxychains4" NMAP_SCAN_TYPE="-sT -Pn" ;;
  direct_only|direct) CURL_OPTS="--noproxy '*'" NMAP_PREFIX="" NMAP_SCAN_TYPE="-sS"  ;;
  blocked)            echo "[!] 目标封禁代理出口IP，配直连规则后重试" ;;
  unreachable)        echo "[ERROR] 目标完全不可达" ;;
esac
```

### 步骤 4：工作目录初始化

```bash
OUTDIR="/mnt/share/stcs/output"
mkdir -p "$OUTDIR"/{recon/raw,targets,vulns,credentials,evidence/{screenshots,commands,requests},report}
# 如果共享目录不可写，使用 /tmp
[ ! -w "$OUTDIR" ] && OUTDIR="/tmp/stcs_output" && mkdir -p "$OUTDIR"/{recon/raw,targets,vulns,credentials,evidence,report}
```

### 步骤 5：任务恢复

```bash
if [ -f "$OUTDIR/meta.json" ]; then
  echo "=== 未完成任务，从断点继续 ==="
  tail -5 "$OUTDIR/timeline.jsonl" 2>/dev/null
else
  echo "[新任务] 等待场景判断后初始化 meta.json"
fi
```

### meta.json 格式（由 recon 在场景判断后写入）

```json
{
  "target": "<用户输入的原始目标>",
  "type": "ip|domain|subdomain|company",
  "mode": "redteam|src",
  "scene": "authorized_redteam|enterprise_src|public_src|ctf",
  "connectivity": "proxy_required|direct_only|direct_preferred",
  "phase": 1,
  "started_at": "ISO8601",
  "updated_at": "ISO8601"
}
```

### timeline.jsonl 格式

```json
{"time":"ISO8601","phase":1,"action":"动作标识","target":"目标ID","status":"done|fail|skip","result":"一句话结果","file":"相关文件路径"}
```

写入方式:
```bash
python3 ${CLAUDE_SKILL_DIR}/../recon/scripts/timeline.py --phase 1 --action "nmap_full" --target "$TARGET" --status done --result "$RESULT" --outdir "$OUTDIR"
```

### 环境变量设定

```bash
export EXEC_MODE="local"           # local | ssh
export KALI_IP="<KALI_IP>"
export KB="/mnt/share/novecento"
export OUTDIR="/mnt/share/stcs/output"
export WORDLISTS="/usr/share/wordlists"
export RATE_DEFAULT_DELAY="0.3"
export RATE_MAX_CONCURRENT="30"
```

```bash
# nuclei 未安装:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# httpx 未安装:
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# 或下载预编译: https://github.com/projectdiscovery/httpx/releases

# subfinder 未安装:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# 或下载预编译: https://github.com/projectdiscovery/subfinder/releases

# amass 未安装 (可选):
go install -v github.com/owasp-amass/amass/v4/...@master

# ffuf 未安装:
go install github.com/ffuf/ffuf/v2@latest

# ddddocr 未安装:
pip install ddddocr

# phpggc 未安装:
git clone https://github.com/ambionics/phpggc /tmp/phpggc

# SecLists 未安装:
apt install seclists
```

### 权限问题

```bash
# nmap 需要 root 权限做 SYN scan
# 如果是普通用户: nmap -sT (TCP connect scan 代替)
# 或者: sudo nmap ...

# /tmp 不可写
mkdir -p ~/stcs_tmp && export TMPDIR=~/stcs_tmp
```

### 上次任务恢复

```bash
# 如果 meta.json 存在但不确定状态:
python3 -c "
import json
with open('/mnt/share/stcs/output/meta.json') as f:
    meta = json.load(f)
print(f'当前阶段: {meta.get(\"phase\")}')
print(f'模式: {meta.get(\"mode\")}')
# 检查最後一条 timeline 记录
try:
    with open('/mnt/share/stcs/output/timeline.jsonl') as f:
        lines = f.readlines()
    if lines:
        last = json.loads(lines[-1])
        print(f'最后操作: [{last.get(\"phase\")}] {last.get(\"action\")} @ {last.get(\"time\")}')
        print(f'结果: {last.get(\"result\")}')
except FileNotFoundError:
    print('timeline.jsonl 不存在')
"
# 从对应 Phase 重新开始即可
```

## 使用规则

### 1. 渗透工具一律通过 SSH 在 Kali 上执行

```bash
# 正确：通过SSH在Kali执行nmap
ssh kali@KALI_IP 'nmap -Pn -p- TARGET'

# 正确：通过SSH在Kali执行nuclei
ssh kali@KALI_IP 'nuclei -u http://TARGET -tags thinkphp'

# 错误：在Windows本地执行nmap（可能没装、权限不够）
nmap -Pn -p- TARGET
```

### 2. 浏览器操作与证据截图用本地 Playwright MCP

```
Playwright MCP 在 Windows 本机运行，通过 v2rayN 系统代理访问目标。

用途:
  - 页面截图（登录页、泄露接口响应、漏洞验证）
  - 浏览器交互（填表单、触发 JS）
  - 命令行输出渲染为终端风格截图
```

#### 证据采集

==漏洞确认后进行人工复测时采集证据。不需要在探测阶段每个发现都截图。==

```
证据件:
  - 浏览器截图 → Playwright 访问目标 URL，截图保存 $OUTDIR/evidence/screenshots/
  - 原始数据包 → curl -D- 或 Burp 导出请求/响应，保存 $OUTDIR/evidence/requests/

命名: {描述}.png / {描述}.txt（如 login_page.png、info_leak_xvslid.txt）
```

### 3. 文件操作在本地

```bash
# 报告、脚本、skills 文件都在 Windows 本地编辑
# 路径格式：\\<NAS_IP>\share\headdump\
# 或通过 UNC 路径：//<NAS_IP>/share/headdump/
```

### 4. 脚本执行优先用 Kali 已有工具

```
优先级：
1. Kali 自带工具（nmap/nikto/nuclei/ffuf/sqlmap/hydra/wpscan/whatweb）
2. Kali 上的 Python + pip 包（ddddocr/requests）
3. 万不得已才自己写脚本

不要写脚本去做工具已经能做的事。
```

### 5. Bash vs Python 选择规则

```
简单命令用 bash:
  nmap / curl / dig / whatweb / nuclei / ffuf 等单条工具调用
  简单的 for 循环 + 单条命令

复杂逻辑用 Python (heredoc 传给 Kali):
  需要 JSON 解析、正则提取、条件判断
  需要 HTTP 请求 + body 内容校验
  涉及字符串处理（cut/awk/sed 在 zsh 上可能不兼容）
  多层嵌套引号（bash 单双引号嵌套极易出错）

传 Python 到 Kali 的标准写法:
  cat << 'SCRIPT' | ssh kali@$KALI_IP 'python3'
  import os
  # ... python code ...
  SCRIPT

注意: Kali 默认 shell 是 zsh，部分 coreutils (cut/tr/awk) 可能缺失或行为不同。
遇到 "command not found" 时不要反复调试 bash，直接改用 Python。
```

### 6. SSH 常见坑

```bash
# 1. 引号嵌套：复杂脚本不要内联传递，用 heredoc 或 scp
#    错误: ssh root@<KALI_IP> 'for x in $LIST; do echo "$x"; done'  ← 引号地狱
#    正确: cat << 'SCRIPT' | ssh root@<KALI_IP> 'bash'
#          for x in a b c; do echo "$x"; done
#          SCRIPT
#    或者: scp script.sh root@<KALI_IP>:/tmp/ && ssh root@<KALI_IP> 'bash /tmp/script.sh'

# 2. zsh 环境差异：Kali 默认 zsh，部分 coreutils 行为不同
#    遇到 "command not found" → 改用 Python 或显式 bash

# 3. 代理变量在 SSH session 中自动生效（.zshrc 里 export 了）
#    遵循启动自检的 CONNECTIVITY 决策，不要手动清除
```

### 7. SSH 并行执行与分组

==快慢分开，别混。一个慢命令超时会导致同批其他命令被 Claude Code 取消。==

```
并行安全分组原则：

同类快速命令 → 放一个 SSH 里用 & + wait 并行:
  ssh root@kali 'bash -c "
    curl -sk URL1 > /tmp/r1.txt &
    curl -sk URL2 > /tmp/r2.txt &
    curl -sk URL3 > /tmp/r3.txt &
    wait
    cat /tmp/r1.txt; echo \"---\"; cat /tmp/r2.txt; echo \"---\"; cat /tmp/r3.txt
  "'

耗时不确定的命令 → 单独一个 SSH，不和快速命令混:
  ✗ 错误: 同时发 nmap(可能5分钟) 和 curl(1秒) → nmap 超时 curl 被取消
  ✓ 正确: nmap 独立一个 SSH 调用，curl 批量另一个

有依赖的命令 → 串行（先 nmap 出端口，再根据端口 curl）

Claude Code 多 tool call 并行的限制:
  同一个 message 里的多个 Bash 调用是并行的
  其中一个失败/超时 → 同批其他调用可能被取消
  所以: 高风险命令(nmap全端口/nuclei大范围)永远单独发，不和其他调用同批
```

### 8. 长时间任务用后台执行

```bash
# 在 Kali 上后台运行扫描
ssh kali@IP 'nohup nuclei -u http://TARGET -o /tmp/result.txt 2>&1 &'

# 检查结果
ssh kali@IP 'cat /tmp/result.txt'
```

## Kali 已确认可用工具

| 工具 | 用途 | 命令示例 |
|---|---|---|
| nmap | 端口扫描/服务识别/脚本扫描 | `nmap -Pn -p- -T4 TARGET` |
| nuclei | 自动化漏洞扫描 | `nuclei -u URL -tags thinkphp` |
| ffuf | 目录爆破/参数fuzzing | `ffuf -u URL/FUZZ -w wordlist` |
| nikto | Web漏洞扫描 | `nikto -h URL` |
| sqlmap | SQL注入自动化 | `sqlmap -u URL --batch` |
| hydra | 密码爆破 | `hydra -l admin -P list ssh://TARGET` |
| wpscan | WordPress扫描 | `wpscan --url URL` |
| whatweb | Web指纹识别 | `whatweb -a 3 URL` |
| gobuster | 目录爆破 | `gobuster dir -u URL -w list` |
| ddddocr | 验证码OCR识别 | Python: `ddddocr.DdddOcr()` |
| php | PHP脚本/PHAR生成 | `php -d phar.readonly=0 phpggc ...` |
| phpggc | PHP反序列化链生成 | `/tmp/phpggc/phpggc ThinkPHP/RCE3 system id` |
| httpx | HTTP批量探活/指纹 | `httpx -l urls.txt -status-code -title -tech-detect` |
| subfinder | 子域名枚举 | `subfinder -d example.com -all -o subs.txt` |

## 字典路径（Kali）

```
/usr/share/wordlists/rockyou.txt          # 1400万密码
/usr/share/wordlists/dirb/common.txt       # 目录爆破（4600条）
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  # 目录爆破（22万条）
/usr/share/seclists/                       # SecLists全套（如已安装）
```

## 知识库路径

==知识库在两个系统上路径不同，根据当前系统选择正确路径：==

| 系统 | 知识库路径 | headdump 路径 |
|---|---|---|
| Windows | `\\<NAS_IP>\share\novecento` | `\\<NAS_IP>\share\headdump` |
| Windows (skills) | `\\<NAS_IP>\share\novecento\skills\` | — |
| Kali | `/mnt/share/novecento` | `/mnt/share/headdump` |
| Kali (skills) | `/mnt/share/novecento/skills/` | — |

知识库可用时，环境配置问题查阅 `10-杂项/渗透环境/`、`07-红队基建/kali配置&错误处理.md`。
不可用时，使用本章节的"常见问题修复"处理。

> 环境就绪后，下一步: @recon.md（信息收集与场景判断）。

## Skill 反馈回写（强制）

==发现 skill 缺陷时，必须写 feedback.jsonl。不要用 memory 系统替代——memory 是给用户偏好用的，feedback.jsonl 是给 skill 迭代用的。两者用途不同。==

### 判断是否启用

```bash
# 当前工作目录包含 "stcs" → 开发模式，跳过反馈
# 否则 → 项目模式，启用反馈
[[ "$(pwd)" == *stcs* ]] && FEEDBACK_ENABLED=false || FEEDBACK_ENABLED=true
```

### 反馈路径（固定，所有项目写同一个文件）

```
Windows: //<HOSTNAME>/share/stcs/feedback.jsonl
Kali:    /mnt/share/stcs/feedback.jsonl
```

### 触发条件（满足任一则写入）

```
1. 用户主动纠正 — 用户说"不对"、"别xxx"、"换思路"、"应该是xxx"
   → 说明 skill 的默认路径/默认行为不符合用户预期或实战需求

2. skill 内置命令/逻辑有误 — 同一步骤因 skill 自身问题重试 2+ 次仍失败
   → 典型: 命令模板用了 grep -P（Windows 不兼容）、SSH 引号嵌套写错、
           硬编码了错误的路径/参数、工具名写错
   → 不包括: 网络超时、目标端口关闭、WAF 拦截（这些是目标侧正常情况）

3. skill 未覆盖当前场景 — 按 skill 流程走不通，绕了一圈才发现根本不在 skill 覆盖范围
   → 典型: 遇到新框架/新漏洞类型、目标环境不在 skill 假设范围内

4. skill 策略导致负面后果 — skill 的默认顺序/默认参数导致目标封禁/告警/数据丢失
   → 典型: recon 第一步就全端口高速扫描触发 IDS、
          默认 --min-rate 太高导致 IP 被封、
          爆破默认并发太大触发账户锁定
```

### 写入方式（用 Write 工具，不用 Bash echo）

==用 Write/Edit 工具追加到 feedback.jsonl，不要用 Bash echo（路径转义容易出错）。也不要写成 memory 文件——memory 是另一套系统，用途不同。==

每条一行 JSON：
```json
{"time":"2026-05-19T10:56:00Z","skill":"recon","issue":"第一步就跑nmap -p- --min-rate 5000触发IDS封禁IP"}
{"time":"2026-05-18T23:06:00Z","skill":"environment","issue":"工具检测for循环SSH引号嵌套失败全部MISSING"}
```

### 不记录

```
- 目标侧的正常响应（端口关闭、密码错误、WAF 拦截）
- 网络超时重试后成功
- 工具输出结果为空（可能就是没有漏洞）
```
