#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
swagger_fleet.py —— 批量探测 OpenAPI / Swagger 文档是否对外暴露

Author : Mosqui（蚊子）  https://github.com/mosqui0x
Project: src-recon-kit
Version: 1.0
Date   : 2026-11

用途：一堆站点里找 `/v2/api-docs`、`/v3/api-docs`、`/openapi.json` 这类文档端点。
文档一旦能匿名读出来，接口清单就等于白送，后面鉴权问题一眼就能定位。

原则：只读 GET，只取前 400KB 判断特征，不批量拉业务数据。

用法：
    python swagger_fleet.py -i targets.txt -o swagger_hits.jsonl
    python swagger_fleet.py -i targets.txt -o swagger_hits.jsonl --threads 6

输入：每行一个根地址（http(s)://...），也接受纯域名（自动补 https://）
输出：JSONL，命中一条打一行。
"""

import argparse
import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

PATHS = [
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-resources",
    "/openapi.json",
    "/doc.html",
    "/swagger-ui.html",
    "/api-docs",
]

lock = threading.Lock()
hits = []


def fetch(url, timeout=8, limit=400000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, dict(r.headers), r.read(limit)
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), b""
        except Exception:
            return e.code, {}, b""
    except Exception:
        return None, {}, b""


def judge(status, headers, body):
    """返回命中类型，None 表示不算命中。"""
    if status != 200:
        return None
    low = body[:4000].lower()
    ctype = (headers.get("Content-Type") or "").lower()
    if b'"swagger"' in low or b'"openapi"' in low or b'"swaggerversion"' in low:
        return "swagger-json"
    if b"swagger-resources" in low or b"swagger ui" in low:
        return "swagger-ui"
    # 只凭 api-docs 字样 + json 内容类型当作疑似，需要人工确认
    if b"api-docs" in low and "json" in ctype:
        return "maybe"
    return None


def work(base, sem, delay, timeout):
    base = base.rstrip("/")
    for p in PATHS:
        with sem:
            status, headers, body = fetch(base + p, timeout=timeout)
            time.sleep(delay)
        if status is None:
            continue
        kind = judge(status, headers, body)
        if kind:
            rec = {
                "root": base,
                "url": base + p,
                "path": p,
                "kind": kind,
                "len": len(body),
                "server": headers.get("Server"),
            }
            with lock:
                hits.append(rec)
                print("[HIT] %s %s %s len=%d" % (base, p, kind, len(body)), flush=True)
            return  # 每站命中一条即可，减少无谓请求


def main():
    ap = argparse.ArgumentParser(description="批量 OpenAPI 文档暴露探测（只读）")
    ap.add_argument("-i", "--input", required=True, help="目标列表文件")
    ap.add_argument("-o", "--output", default="swagger_hits.jsonl", help="输出文件")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.05, help="每请求之间间隔秒数")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    targets = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if not s.startswith("http"):
                s = "https://" + s
            targets.append(s.rstrip("/"))
    if not targets:
        sys.exit("目标列表为空")

    print("目标数：%d" % len(targets), flush=True)
    t0 = time.time()
    sem = threading.Semaphore(args.threads)
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        list(ex.map(lambda b: work(b, sem, args.delay, args.timeout), targets))

    with open(args.output, "w", encoding="utf-8") as f:
        for h in hits:
            f.write(json.dumps(h, ensure_ascii=False) + "\n")

    print("完成 %.1fs  命中 %d  输出 %s"
          % (time.time() - t0, len(hits), args.output))


if __name__ == "__main__":
    main()
