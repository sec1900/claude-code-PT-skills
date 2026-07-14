#!/usr/bin/env python3
"""
环境自检脚本 — 一次性检查所有环境依赖，输出 JSON 摘要

用法:
  python bootstrap_check.py

输出: bootstrap_result.json（agent 读这个文件就够了）
"""
import os, sys, json, subprocess, socket, time
from datetime import datetime, timezone

RESULT = {
    "time": datetime.now(timezone.utc).isoformat(),
    "platform": sys.platform,
    "ok": True,
    "issues": [],
    "summary": {},
}


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def check_port(host, port, timeout=2):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except:
        return False


def check_tool(name, cmd=None):
    if cmd is None:
        cmd = f"which {name}" if sys.platform != "win32" else f"where {name}"
    code, out, _ = run(cmd)
    return code == 0


# === 1. SSH to Kali ===
kali_ip = "<KALI_IP>"
kali_user = "root"

ssh_ok = False
code, out, err = run(f'ssh -o ConnectTimeout=3 -o BatchMode=yes {kali_user}@{kali_ip} "echo OK"', timeout=5)
if code == 0 and "OK" in out:
    ssh_ok = True
    RESULT["summary"]["kali_ssh"] = f"{kali_user}@{kali_ip} OK"
else:
    # try kali user
    code2, out2, _ = run(f'ssh -o ConnectTimeout=3 -o BatchMode=yes kali@{kali_ip} "echo OK"', timeout=5)
    if code2 == 0 and "OK" in out2:
        ssh_ok = True
        kali_user = "kali"
        RESULT["summary"]["kali_ssh"] = f"kali@{kali_ip} OK"
    else:
        RESULT["issues"].append(f"SSH to Kali ({kali_ip}) FAILED")
        RESULT["summary"]["kali_ssh"] = "FAILED"

# === 2. Kali tools ===
if ssh_ok:
    tools_to_check = "nmap nuclei ffuf sqlmap whatweb nikto hydra gobuster wpscan hashcat john curl openssl dig whois php python3 httpx subfinder katana"
    code, out, _ = run(
        f'ssh -o ConnectTimeout=3 {kali_user}@{kali_ip} \'for t in {tools_to_check}; do command -v $t >/dev/null 2>&1 && echo "OK $t" || echo "MISSING $t"; done\'',
        timeout=15
    )
    tools_ok = []
    tools_missing = []
    for line in out.split("\n"):
        if line.startswith("OK "):
            tools_ok.append(line[3:])
        elif line.startswith("MISSING "):
            tools_missing.append(line[8:])
    RESULT["summary"]["kali_tools_ok"] = tools_ok
    RESULT["summary"]["kali_tools_missing"] = tools_missing
    if tools_missing:
        RESULT["issues"].append(f"Kali missing tools: {', '.join(tools_missing)}")

    # Python packages
    code, out, _ = run(
        f'ssh -o ConnectTimeout=3 {kali_user}@{kali_ip} \'python3 -c "import ddddocr; print(1)" 2>/dev/null && echo "OK ddddocr" || echo "MISSING ddddocr"; python3 -c "import requests; print(1)" 2>/dev/null && echo "OK requests" || echo "MISSING requests"\'',
        timeout=10
    )
    RESULT["summary"]["kali_python_packages"] = out.replace("\n1", "").strip()

    # Dictionaries
    code, out, _ = run(
        f'ssh -o ConnectTimeout=3 {kali_user}@{kali_ip} \'[ -f /usr/share/wordlists/rockyou.txt ] && echo "OK rockyou" || echo "MISSING rockyou"; [ -f /usr/share/wordlists/dirb/common.txt ] && echo "OK dirb" || echo "MISSING dirb"; [ -d /usr/share/seclists ] && echo "OK seclists" || echo "MISSING seclists"\'',
        timeout=5
    )
    RESULT["summary"]["kali_dictionaries"] = out.strip()

    # Proxy env on Kali
    code, out, _ = run(
        f'ssh -o ConnectTimeout=3 {kali_user}@{kali_ip} \'env | grep -i proxy || echo "NO_PROXY"\'',
        timeout=5
    )
    RESULT["summary"]["kali_proxy_env"] = out.strip()

# === 3. Burp Suite (localhost:8080) ===
burp_running = check_port("127.0.0.1", 8080)
RESULT["summary"]["burp_proxy"] = "RUNNING (127.0.0.1:8080)" if burp_running else "NOT RUNNING"

# === 4. Burp MCP (localhost:9876) ===
burp_mcp = check_port("127.0.0.1", 9876)
RESULT["summary"]["burp_mcp"] = "RUNNING (127.0.0.1:9876)" if burp_mcp else "NOT RUNNING"

# === 5. Windows tools ===
win_tools = {}
for name, cmd in [
    ("katana", 'where katana 2>nul || dir /b "%USERPROFILE%\\.local\\bin\\katana.exe" 2>nul'),
    ("java", "java -version"),
    ("python", "python --version"),
    ("mitmproxy", "mitmdump --version"),
]:
    code, out, err = run(cmd, timeout=5)
    win_tools[name] = "OK" if code == 0 else "MISSING"
RESULT["summary"]["windows_tools"] = win_tools

# === 6. Share directory ===
share_paths = {
    "poc": "//<HOSTNAME>/share/poc" if sys.platform == "win32" else "/mnt/share/poc",
    "novecento": "//<HOSTNAME>/share/novecento" if sys.platform == "win32" else "/mnt/share/novecento",
    "stcs": "//<HOSTNAME>/share/stcs" if sys.platform == "win32" else "/mnt/share/stcs",
    "tools": "//<HOSTNAME>/share/tools" if sys.platform == "win32" else "/mnt/share/tools",
}
share_status = {}
for name, path in share_paths.items():
    share_status[name] = "OK" if os.path.isdir(path) else "MISSING"
RESULT["summary"]["share_dirs"] = share_status

# === 7. finger.json & yakit_rules.json ===
data_files = {}
for name, rel_path in [
    ("finger.json", ".claude/skills/recon/data/finger.json"),
    ("yakit_rules.json", ".claude/skills/recon/data/yakit_rules.json"),
]:
    full = os.path.join("//<HOSTNAME>/share/stcs", rel_path) if sys.platform == "win32" else os.path.join("/mnt/share/stcs", rel_path)
    if os.path.isfile(full):
        size = os.path.getsize(full)
        data_files[name] = f"OK ({size // 1024}KB)"
    else:
        data_files[name] = "MISSING"
RESULT["summary"]["data_files"] = data_files

# === 8. v2rayN proxy (物理机 <PROXY_HOST>:16666) ===
v2ray_ok = check_port("<PROXY_HOST>", 16666, timeout=2)
RESULT["summary"]["v2rayn_proxy"] = "RUNNING" if v2ray_ok else "NOT RUNNING"

# === Overall ===
if RESULT["issues"]:
    RESULT["ok"] = False

# === Output ===
# Print summary to stderr
print("=== 环境自检摘要 ===", file=sys.stderr)
print(f"  Kali SSH:      {RESULT['summary'].get('kali_ssh', 'N/A')}", file=sys.stderr)
if ssh_ok:
    missing = RESULT["summary"].get("kali_tools_missing", [])
    ok_count = len(RESULT["summary"].get("kali_tools_ok", []))
    print(f"  Kali Tools:    {ok_count} OK, {len(missing)} missing{': ' + ', '.join(missing) if missing else ''}", file=sys.stderr)
print(f"  Burp Proxy:    {RESULT['summary']['burp_proxy']}", file=sys.stderr)
print(f"  Burp MCP:      {RESULT['summary']['burp_mcp']}", file=sys.stderr)
print(f"  v2rayN:        {RESULT['summary']['v2rayn_proxy']}", file=sys.stderr)
print(f"  Share Dirs:    {RESULT['summary']['share_dirs']}", file=sys.stderr)
if RESULT["issues"]:
    print(f"  Issues:        {RESULT['issues']}", file=sys.stderr)
print(f"  Overall:       {'ALL OK' if RESULT['ok'] else 'HAS ISSUES'}", file=sys.stderr)

# Write JSON to stdout
print(json.dumps(RESULT, ensure_ascii=False, indent=2))
