---
description: 网络设备与VPN攻击。SSL VPN/防火墙/路由器/交换机。参考手册见 SKILL.ref.md
---

# 网络设备与 VPN 攻击

## 触发条件
recon 发现非标准Web端口(8443/10443/4443)或VPN登录页时触发

## 目标 → 策略
```
SSL VPN (Pulse/Ivanti/Array/Fortinet/深信服/天融信)
  → 版本识别 → CVE搜索 → 未授权文件读取 → RCE

防火墙 (深信服/H3C/华为/思科/PaloAlto)
  → 管理口探测 → 默认口令 → CVE利用

路由器/交换机
  → SNMP public/private → 配置读取 → telnet/ssh弱口令
```

## 快速检测
```bash
whatweb -a 3 <URL>
nuclei -t network/ -u <URL>
curl -sk <URL> | grep -iE "vpn|firewall|gateway|管理"
```

> 设备指纹库、CVE列表见 SKILL.ref.md
