#!/usr/bin/env python3
"""
timeline 追加助手 — 统一格式写入 timeline.jsonl

用法:
  python3 timeline.py --phase recon --action "httpx alive scan done" --result "200 alive, 30 dead" --target ace.baidu.com
  python3 timeline.py --phase exploit --action "P2 CORS check done" --result "3 reflect, 0 exploitable"

输出: 自动补时间戳，追加到 $OUTDIR/timeline.jsonl
"""

import sys, os, json
from datetime import datetime, timezone

OUTDIR = os.environ.get("OUTDIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "output"))


def main():
    phase = ""
    action = ""
    result = ""
    target = ""
    status = "done"
    file_path = ""

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--phase" and i + 1 < len(args):
            phase = args[i + 1]
            i += 2
        elif args[i] == "--action" and i + 1 < len(args):
            action = args[i + 1]
            i += 2
        elif args[i] == "--result" and i + 1 < len(args):
            result = args[i + 1]
            i += 2
        elif args[i] == "--target" and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        elif args[i] == "--status" and i + 1 < len(args):
            status = args[i + 1]
            i += 2
        elif args[i] == "--file" and i + 1 < len(args):
            file_path = args[i + 1]
            i += 2
        elif args[i] == "--outdir" and i + 1 < len(args):
            global OUTDIR
            OUTDIR = args[i + 1]
            i += 2
        else:
            i += 1

    if not phase or not action:
        print("用法: python3 timeline.py --phase <phase> --action <action> [--result <result>] [--target <target>] [--status <done|fail|skip>] [--file <path>] [--outdir <dir>]")
        print("")
        print("示例:")
        print("  python3 timeline.py --phase recon --action 'httpx done' --result '200 alive' --target example.com")
        print("  python3 timeline.py --phase exploit --action 'nuclei done' --result '2 critical, 5 high' --status done")
        sys.exit(1)

    entry = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "action": action,
        "status": status,
        "result": result,
    }
    if target:
        entry["target"] = target
    if file_path:
        entry["file"] = file_path

    os.makedirs(OUTDIR, exist_ok=True)
    timeline_path = os.path.join(OUTDIR, "timeline.jsonl")

    with open(timeline_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print("[timeline] %s | %s | %s | %s" % (entry["time"], phase, action, result[:60]))
    print("  → %s" % timeline_path)


if __name__ == "__main__":
    main()
