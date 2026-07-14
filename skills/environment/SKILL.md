---
description: 环境自检。任何渗透任务第1步。检测 OS、Kali SSH、工具版本、代理、字典。参考手册见 SKILL.ref.md
---

# 环境自检

## 硬规则

1. Kali SSH = root@<KALI_IP>，不猜 IP
2. Windows 用 `python`，Kali 用 `python3`
3. 高风险命令(nmap/nuclei)单独发，不和 curl 混批
4. SSH 复杂脚本用 heredoc，不内联 for 循环
5. Windows 禁用 grep -P，用 grep -E 或 Python re
6. 网络请求一律走 Kali SSH

## 启动自检（按顺序执行）

### 0. OS 检测 + SSH 连通
```bash
uname -s
ssh -o ConnectTimeout=5 -o BatchMode=yes root@<KALI_IP> 'echo OK'
```

### 1. Kali 工具 + httpx 版本验证
```bash
ssh root@<KALI_IP> 'for t in nmap nuclei ffuf sqlmap whatweb nikto hydra gobuster httpx curl openssl dig python3; do command -v $t >/dev/null 2>&1 && echo "OK $t" || echo "MISS $t"; done'
ssh root@<KALI_IP> 'httpx --version 2>&1 | head -1'  # 必须含 projectdiscovery
# ⚠️ 不含 projectdiscovery → 立即安装，装完前禁止继续：
# ssh root@<KALI_IP> 'curl -sL "https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip" -o /tmp/httpx.zip && unzip -o /tmp/httpx.zip -d /tmp/httpx_extract && mv /tmp/httpx_extract/httpx /usr/local/bin/httpx-go && chmod +x /usr/local/bin/httpx-go'
```

### 2. 字典 + 代理 + VPN
```bash
ssh root@<KALI_IP> 'ls /usr/share/wordlists/rockyou.txt /usr/share/seclists/ 2>&1'
ssh root@<KALI_IP> 'env | grep -i proxy; ip addr show tun0 2>&1'
```

### 3. 目标连通性
```bash
ssh root@<KALI_IP> 'curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 "<目标URL>"'
```

### 4. 输出总结
```
Kali SSH: OK/FAIL | 缺工具: xxx | httpx版本: Go/PyPI | 代理: xxx | VPN: up/down | 目标: 可达/不可达
```

> 缺工具安装命令见 SKILL.ref.md；详细手动步骤见 SKILL.ref.md
