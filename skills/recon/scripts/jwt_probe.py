#!/usr/bin/env python3
"""
JWT 批量分析 — 封装 jwt_tool 标准 Playbook，输入 token 列表逐个检测

依赖: Kali 上的 jwt_tool（/usr/bin/jwt_tool 或 pip install jwt_tool）

用法:
  python3 jwt_probe.py /tmp/jwts.txt
  python3 jwt_probe.py -t eyJhbGciOiJIUzI1NiIs...
  python3 jwt_probe.py -f /tmp/jwts.txt --wordlist /usr/share/wordlists/rockyou_top100.txt

输入:
  -f 文件，每行一个 JWT
  -t 单个 JWT
  --wordlist 自定义弱密钥字典（默认用内嵌 top 50）

输出: 每个 JWT 的检测结果 + 可利用性判定
"""

import sys, os, json, subprocess, base64, tempfile

JWT_TOOL = None
for path in ["/usr/bin/jwt_tool", "/usr/local/bin/jwt_tool",
             os.path.expanduser("~/.local/bin/jwt_tool")]:
    if os.path.exists(path):
        JWT_TOOL = path
        break

# 内嵌弱密钥（无外部字典时使用）
DEFAULT_WEAK_KEYS = [
    "secret", "password", "secretkey", "secret123", "key",
    "private", "changeme", "admin", "test", "123456",
    "12345678", "123456789", "qwerty", "iloveyou", "monkey",
    "dragon", "master", "hello", "shadow", "sunshine",
    "princess", "football", "baseball", "welcome", "jesus",
    "trustno1", "superman", "batman", "access", "passw0rd",
    "p@ssword", "p@ssw0rd", "letmein", "whatever", "hello123",
    "abc123", "111111", "000000", "1qaz2wsx", "pass",
    "jwt_secret", "jwt", "token_secret", "auth_secret",
    "my_secret", "api_secret", "app_secret", "default",
    "development", "dev", "staging", "production",
]


def decode_jwt(token):
    """基础解码 JWT header + payload（不做签名验证）"""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None
    header_b64 = parts[0]
    payload_b64 = parts[1]
    # 补齐 padding
    for b64 in [header_b64, payload_b64]:
        padding = 4 - len(b64) % 4
        if padding != 4:
            b64 = b64 + "=" * padding
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)))
    except:
        header = None
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4)))
    except:
        payload = None
    return header, payload


def check_alg_none(token):
    """检测 alg:none 绕过"""
    header, payload = decode_jwt(token)
    if not header:
        return False, "decode failed"

    alg = header.get("alg", "").lower()

    # 构造 alg:none token
    import base64 as b64
    none_header = b64.urlsafe_b64encode(
        json.dumps({**header, "alg": "none"}).encode()
    ).rstrip(b"=").decode()
    none_token = none_header + "." + token.split(".")[1] + "."

    return alg in ("none", "None", "NONE"), none_token


def run_jwt_tool(token, mode, wordlist=None, timeout=15):
    """调用 jwt_tool 执行指定模式"""
    if not JWT_TOOL:
        return "", "jwt_tool not found"
    cmd = [JWT_TOOL, token, mode]
    if wordlist:
        cmd.extend(["-C", wordlist])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr, None
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except Exception as e:
        return "", str(e)


def probe_jwt(token, wordlist=None, tmp_dir="/tmp"):
    """对单个 JWT 执行全套检测"""
    header, payload = decode_jwt(token)
    result = {
        "token_preview": token[:40] + ("..." if len(token) > 40 else ""),
        "alg": header.get("alg") if header else "?",
        "claims": list(payload.keys()) if payload else [],
        "sensitive_claims": [],
        "alg_none_exploitable": False,
        "expired": False,
        "weak_key_found": None,
        "issues": [],
    }

    # 1. 敏感 claims 检测
    sensitive = ["password", "secret", "api_key", "admin", "role", "permissions",
                 "user_id", "email", "phone", "credit", "balance", "subscription",
                 "is_admin", "is_staff", "superuser", "scope", "authorities"]
    if payload:
        for k in payload:
            if any(s.lower() in k.lower() for s in sensitive):
                result["sensitive_claims"].append(k)

    # 2. alg:none 检测
    exploitable, none_token = check_alg_none(token)
    if exploitable:
        result["alg_none_exploitable"] = True
        result["issues"].append("alg:none accepted — can forge any payload")

    # 3. 过期检测
    if payload:
        import time
        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            result["expired"] = True

    # 4. 弱密钥爆破（调用 jwt_tool -C）
    if JWT_TOOL:
        # 用 jwt_tool 的 Playbook 模式
        output, err = run_jwt_tool(token, "-t", timeout=120)
        if output:
            # 解析 jwt_tool 输出找弱密钥
            for line in output.split("\n"):
                if "Successfully" in line or "SIGNATURE VERIFIED" in line:
                    result["weak_key_found"] = "found (see raw output)"
                    result["issues"].append("weak HMAC key cracked by jwt_tool")
                    break

        # 用内嵌弱字典速测
        wf = os.path.join(tmp_dir, "jwt_weak_keys.txt")
        if wordlist and os.path.exists(wordlist):
            wf = wordlist
        else:
            with open(wf, "w") as f:
                f.write("\n".join(DEFAULT_WEAK_KEYS))

        crack_out, _ = run_jwt_tool(token, "-C", wordlist=wf, timeout=30)
        if crack_out and "Successfully" in crack_out:
            result["weak_key_found"] = "found (see raw output)"
            result["issues"].append("weak HMAC key found in default wordlist")

        if not wordlist:
            try:
                os.remove(wf)
            except:
                pass

    # 5. 综合判定
    if result["alg_none_exploitable"]:
        result["severity"] = "critical"
    elif result["weak_key_found"]:
        result["severity"] = "high"
    elif result["sensitive_claims"]:
        result["severity"] = "info"
    else:
        result["severity"] = "none"

    return result


def main():
    tokens = []
    wordlist = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "-f" and i + 1 < len(args):
            with open(args[i + 1]) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        tokens.append(line)
            i += 2
        elif args[i] == "-t" and i + 1 < len(args):
            tokens.append(args[i + 1])
            i += 2
        elif args[i] == "--wordlist" and i + 1 < len(args):
            wordlist = args[i + 1]
            i += 2
        else:
            i += 1

    if not tokens:
        print("用法: python3 jwt_probe.py -f <jwts.txt> | -t <JWT>")
        print("      python3 jwt_probe.py -f /tmp/jwts.txt --wordlist /usr/share/wordlists/rockyou.txt")
        sys.exit(1)

    if not JWT_TOOL:
        print("[WARN] jwt_tool 未找到，仅做基础解码+alg:none检测")
        print("[INFO] 安装: pip install jwt_tool 或 apt install jwt-tool")

    print("=" * 90)
    print("JWT Probe — %d tokens" % len(tokens))
    print("=" * 90)

    stats = {"critical": 0, "high": 0, "info": 0, "none": 0}

    for token in tokens:
        r = probe_jwt(token, wordlist=wordlist)
        stats[r["severity"]] += 1

        tag = r["severity"].upper()
        print("\n[%s] %s | alg=%s" % (tag, r["token_preview"], r["alg"]))

        if r["claims"]:
            print("  Claims: %s" % ", ".join(r["claims"][:12]))
        if r["sensitive_claims"]:
            print("  Sensitive claims: %s" % ", ".join(r["sensitive_claims"]))
        if r["expired"]:
            print("  [EXPIRED]")
        for issue in r["issues"]:
            print("  [ISSUE] %s" % issue)

    print("\n" + "=" * 90)
    print("Summary: CRITICAL=%d  HIGH=%d  INFO=%d  NONE=%d  TOTAL=%d" % (
        stats["critical"], stats["high"], stats["info"], stats["none"], len(tokens)))


if __name__ == "__main__":
    main()
