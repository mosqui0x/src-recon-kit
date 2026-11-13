#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leak_path_fleet.py —— 批量探测高确定性信息泄露路径

Author : Mosqui（蚊子）  https://github.com/mosqui0x
Project: src-recon-kit
Version: 1.0
Date   : 2026-11

用途：给一批站点，逐个请求常见的「本不该存在」的文件，命中后人工复核。
路径：phpinfo 变体 / .git/config / .env / .svn/entries / .DS_Store / Apache server-status
原则：只读 GET，不下载大文件，不改动目标数据。

用法：
    python leak_path_fleet.py -i targets.txt -o hits.jsonl
    python leak_path_fleet.py -i targets.txt -o hits.jsonl --rate 10 --threads 8

输入格式：每行一个根地址，http(s):// 开头，例如
    https://example.com
    http://example.org

输出：JSONL，每行一条命中记录。
"""

import argparse
import json
import queue
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/phpinfo2.php",
    "/.git/config",
    "/.env",
    "/.svn/entries",
    "/.DS_Store",
    "/server-status",
]


def judge(path, code, body):
    """按路径类型分别判定，避免把 404 页当成命中。"""
    low = body[:200000].lower()

    if path.startswith("/phpinfo") or path == "/info.php":
        if code == 200 and (b"php version" in low or b"phpinfo()" in low):
            if b"phpinfo" in low or b"php.ini" in low:
                return True, "phpinfo 页面"
        return False, ""

    if path == "/.git/config":
        if code == 200 and b"[core]" in low and b"repositoryformatversion" in low:
            return True, "git config"
        return False, ""

    if path == "/.env":
        if code == 200 and (b"app_key=" in low or b"db_password=" in low
                            or b"database_password=" in low or b"secret_key=" in low):
            return True, "env 配置"
        return False, ""

    if path == "/.svn/entries":
        # 注意：现代 SPA 会把任意路径回落到 404 页，这里必须校验 svn 特征
        if code == 200 and (b"dir" in low[:2000] or b"svn:" in low):
            return True, "svn entries"
        return False, ""

    if path == "/.DS_Store":
        if code == 200 and body[:4] == b"Bud1":
            return True, "DS_Store"
        return False, ""

    if path == "/server-status":
        if code == 200 and b"apache server status" in low:
            return True, "apache status"
        return False, ""

    return False, ""


def fetch(url, limit=200000, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.read(limit)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(limit)
        except Exception:
            return e.code, b""
    except Exception:
        return None, b""


def load_targets(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if not s.startswith("http"):
                s = "https://" + s
            out.append(s.rstrip("/"))
    return out


def main():
    ap = argparse.ArgumentParser(description="批量信息泄露路径探测（只读）")
    ap.add_argument("-i", "--input", required=True, help="目标列表，每行一个根地址")
    ap.add_argument("-o", "--output", default="hits.jsonl", help="命中记录输出文件")
    ap.add_argument("--rate", type=float, default=10.0, help="全局每秒请求上限，默认 10")
    ap.add_argument("--threads", type=int, default=8, help="并发线程数，默认 8")
    ap.add_argument("--timeout", type=float, default=12.0, help="单请求超时秒数")
    args = ap.parse_args()

    if args.rate <= 0 or args.threads <= 0:
        sys.exit("rate / threads 必须大于 0")

    targets = load_targets(args.input)
    if not targets:
        sys.exit("目标列表为空")

    q = queue.Queue()
    for t in targets:
        q.put(t)

    lock = threading.Lock()
    interval = 1.0 / args.rate
    last = [0.0]
    stats = {"done": 0, "hit": 0}
    t0 = time.time()

    def slot():
        with lock:
            now = time.time()
            wait = last[0] + interval - now
            if wait > 0:
                time.sleep(wait)
                now = last[0] + interval
            last[0] = now

    def worker():
        while True:
            try:
                root = q.get_nowait()
            except queue.Empty:
                return
            try:
                for p in PATHS:
                    slot()
                    code, body = fetch(root + p, timeout=args.timeout)
                    if code is None:
                        continue
                    hit, why = judge(p, code, body)
                    if hit:
                        rec = {"url": root + p, "path": p, "code": code,
                               "len": len(body), "why": why}
                        with lock:
                            stats["hit"] += 1
                            with open(args.output, "a", encoding="utf-8") as fo:
                                fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        print("[HIT] %s  %s  (%d 字节)" % (root + p, why, len(body)),
                              flush=True)
            finally:
                with lock:
                    stats["done"] += 1
                    if stats["done"] % 50 == 0:
                        print("进度 %d/%d 命中 %d 用时 %.0fs"
                              % (stats["done"], len(targets), stats["hit"],
                                 time.time() - t0), flush=True)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(args.threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print()
    print("=" * 56)
    print("完成：站点 %d，请求 %d，命中 %d，用时 %.1fs"
          % (len(targets), len(targets) * len(PATHS), stats["hit"],
             time.time() - t0))
    print("命中文件：%s" % args.output)


if __name__ == "__main__":
    main()
