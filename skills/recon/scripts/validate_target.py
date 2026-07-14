#!/usr/bin/env python3
"""
target 文件完整性校验 — 进入 web-exploit 前必跑，避免打到一半发现 recon 漏了关键字段

用法:
  python3 validate_target.py $OUTDIR/targets/ace.baidu.com.json
  python3 validate_target.py $OUTDIR/targets/ --all

输出: 通过/缺失/告警三级，按攻击优先级标注影响
"""

import sys, os, json


# 字段定义: (json_path, description, required_for)
# required_for: "always" | "pN" (攻击优先级编号)
FIELDS = [
    # === 基础信息（always） ===
    ("id", "目标唯一标识", "always"),
    ("url", "目标 URL", "always"),
    ("port", "端口号", "always"),
    ("framework", "框架/语言", "always"),
    ("server", "Web 服务器", "always"),
    ("cdn", "是否经过 CDN", "always"),
    ("waf", "WAF 类型", "always"),

    # === 端点枚举 ===
    ("endpoints", "端点枚举结果", "P0(P0未授权API)"),
    ("endpoints.no_auth", "无认证端点列表", "P0(P0未授权API)"),
    ("endpoints.need_auth", "需认证端点列表", "P3(注入)/P4(上传)/P5(XSS)"),
    ("endpoints.error_leaks", "报错泄露端点", "P3(注入)"),

    # === 信息泄露 ===
    ("info_leaks", "信息泄露发现", "P0(未授权API)/P1(CVE辅助)"),

    # === JS 分析 ===
    ("js_intel", "JS 情报(API/密钥/加密算法)", "P0(未授权API)/P3.5(JWT)/P5(XSS)"),
    ("js_intel.files", "已分析的 JS 文件列表", "P0"),
    ("js_intel.hardcoded", "硬编码的密钥/密码/Token", "P0/P6(爆破)"),

    # === 认证 ===
    ("auth", "认证信息", "P6(登录爆破)/P8(逻辑漏洞)"),
    ("auth.type", "认证方式", "P6"),
    ("auth.login_url", "登录接口 URL", "P6"),
    ("auth.lockout", "锁定策略探测结果", "P6"),
    ("auth.lockout.threshold", "锁定阈值", "P6"),
    ("auth.lockout.cooldown_sec", "冷却时间(秒)", "P6"),

    # === 速率 ===
    ("rate_profile", "速率限制档案", "P6(爆破)/P5.5(并发竞争)"),
    ("rate_profile.max_concurrent", "最大并发数", "P6"),
    ("rate_profile.delay", "安全延迟(秒)", "P6"),

    # === 攻击覆盖追踪 ===
    ("attack_status", "攻击覆盖清单", "always"),
]


EXPECTED_ATTACK_PATHS = [
    # 20 条核心路径，与 web-exploit 攻击章节一一对应
    "P0_unauth_api", "P0_info_leak",
    "P1_cve",
    "P2_cors",
    "P3_injection", "P3_method_abuse", "P3_ssrf", "P3_jwt", "P3_openredirect",
    "P3.6_oauth_saml", "P3.7_session", "P3.8_protocol", "P3_idor",
    "P4_upload_lfi",
    "P5_xss_client", "P5_race",
    "P6_brute", "P7_port_services", "P8_biz_logic", "P9_supply_chain",
]


def dot_get(obj, path):
    """按点号路径读取嵌套字段"""
    parts = path.split(".")
    for p in parts:
        if isinstance(obj, dict):
            obj = obj.get(p)
        else:
            return None
    return obj


def validate_single(target_path):
    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = {"pass": [], "missing": [], "warn": []}

    for path, desc, required in FIELDS:
        val = dot_get(data, path)

        if val is None or (isinstance(val, str) and val.strip() == ""):
            results["missing"].append({"field": path, "desc": desc, "required_for": required})
        elif isinstance(val, list) and len(val) == 0:
            results["warn"].append({"field": path, "desc": desc, "required_for": required,
                                     "note": "列表为空，可能是未采集或确实无发现"})
        elif isinstance(val, dict) and len(val) == 0:
            results["warn"].append({"field": path, "desc": desc, "required_for": required,
                                     "note": "对象为空，可能未采集"})
        else:
            results["pass"].append({"field": path, "desc": desc})

    # 检查 attack_status 覆盖完整性
    attack_status = data.get("attack_status", {})
    for path_key in EXPECTED_ATTACK_PATHS:
        if path_key not in attack_status:
            results["missing"].append({
                "field": "attack_status." + path_key,
                "desc": "攻击路径 " + path_key + " 未记录",
                "required_for": "always"
            })
        else:
            state = attack_status[path_key]
            if state == "pending":
                results["warn"].append({
                    "field": "attack_status." + path_key,
                    "desc": "攻击路径 " + path_key,
                    "required_for": "always",
                    "note": "状态为 pending，仍未测试"
                })
            elif state == "incomplete":
                results["warn"].append({
                    "field": "attack_status." + path_key,
                    "desc": "攻击路径 " + path_key,
                    "required_for": "always",
                    "note": "状态为 incomplete，测试未完成，切换目标前应补完或确认"
                })

    return results, data


def main():
    targets = []
    if len(sys.argv) < 2:
        print("用法: python3 validate_target.py <target.json>")
        print("      python3 validate_target.py <targets_dir/> --all")
        sys.exit(1)

    target_path = sys.argv[1]
    all_flag = "--all" in sys.argv

    if all_flag and os.path.isdir(target_path):
        for f in os.listdir(target_path):
            if f.endswith(".json"):
                targets.append(os.path.join(target_path, f))
    else:
        targets.append(target_path)

    for tp in targets:
        if not os.path.exists(tp):
            print("[SKIP] %s — 文件不存在" % tp)
            continue

        results, data = validate_single(tp)
        target_id = data.get("id", os.path.basename(tp))

        n_pass = len(results["pass"])
        n_miss = len(results["missing"])
        n_warn = len(results["warn"])

        print("\n" + "=" * 80)
        print("Target: %s | %s" % (target_id, data.get("url", "?")))
        print("Status: %d 通过 | %d 缺失 | %d 告警" % (n_pass, n_miss, n_warn))
        print("=" * 80)

        if results["missing"]:
            print("\n  缺失 — 影响以下攻击路径:")
            by_attack = {}
            for m in results["missing"]:
                req = m["required_for"]
                if req not in by_attack:
                    by_attack[req] = []
                by_attack[req].append(m)

            for attack, items in sorted(by_attack.items()):
                fields_str = ", ".join(i["desc"] for i in items)
                print("  [%s] %s" % (attack, fields_str))

        if results["warn"]:
            print("\n  告警 — 字段存在但可能未采集:")
            for w in results["warn"]:
                print("  [%s] %s — %s" % (w["required_for"], w["desc"], w["note"]))

        if n_miss == 0:
            impact = []
            if n_warn > 0:
                for w in results["warn"]:
                    if w["required_for"].startswith("P6"):
                        impact.append("爆破前需确认 %s" % w["desc"])
                if not impact:
                    impact.append("告警项不影响大部分攻击路径")
            else:
                impact.append("全部字段完整，可进入 web-exploit")

            print("\n  %s" % " ".join(impact))


if __name__ == "__main__":
    main()
