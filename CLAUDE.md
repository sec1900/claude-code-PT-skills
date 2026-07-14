# STCS 渗透工作台

## 硬规则

1. 第1步 `Skill(environment)` 自检，第2步场景判断(SRC/红队/CTF)，两步完成前禁止任何网络请求
2. 每个操作前用1句话说你要干什么；同一方向3次未果强制切换
3. Kali 做所有网络请求(curl/nuclei/ffuf/nmap)，Windows 只做文件和 Python 脚本
4. Windows 用 `python` 不是 `python3`；Kali 用 `python3`
5. SRC 模式：信息泄露/未授权/配置暴露优先，禁止爆破登录口
6. 每阶段结束输出 checklist，全部打勾才进下一阶段

## 加载顺序（每个 → 前输出 checklist）

environment → recon → web-exploit → report

recon 完成 checklist：[ ] scope已确认 [ ] nuclei已跑 [ ] 存活<50 [ ] P0路径已扫
web-exploit 完成 checklist：[ ] P0穷尽 [ ] nuclei CVE已跑 [ ] P2 CORS已测 [ ] 每个漏洞有复现

## 环境

- Kali SSH: root@<KALI_IP>
- 代理: HTTP_PROXY=http://<PROXY_HOST>:<PROXY_PORT>
