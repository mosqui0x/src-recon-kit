#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phpinfo_check.py —— 单目标 phpinfo.php 泄露取证

Author : Mosqui（蚊子）  https://github.com/mosqui0x
Project: src-recon-kit
Version: 1.0
Date   : 2026-11

用途：给一个具体地址，判断是不是真的 phpinfo 页面，并把泄露的关键字段抓出来。
输出分 5 段，可以直接贴进报告，也可以整屏截图当证据。

原则：只读 GET，一次请求，不探测其他路径、不尝试利用。

用法：
    python phpinfo_check.py -u http://example.com/phpinfo.php
    python phpinfo_check.py -u https://example.com/info.php --save out.txt
"""

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def strip_tags(s):
    return re.sub(r"<[^>]+>", "", s).strip()


def pick(body, key):
    """phpinfo 的字段值在 <td class="v">...</td> 里。"""
    m = re.search(re.escape(key) + r"</td><td class=\"v\">(.*?)</td>", body, re.S)
    if m:
        return strip_tags(m.group(1))
    m = re.search(re.escape(key) + r".{0,80}?<td[^>]*>(.*?)</td>", body, re.S)
    if m:
        return strip_tags(m.group(1))
    return "未取到"


ROWS = [
    ("PHP 版本", "PHP Version "),
    ("Server API", "Server API "),
    ("配置文件", "Loaded Configuration File"),
    ("服务器系统", "System "),
    ("站点根目录", "DOCUMENT_ROOT"),
    ("open_basedir", "open_basedir"),
    ("上传临时目录", "upload_tmp_dir"),
    ("服务器地址", "SERVER_ADDR"),
    ("主机名相关", "HTTP_HOST"),
]


def run(url):
    lines = []
    p = lines.append

    p("=" * 70)
    p("[1] 目标与请求方式")
    p("=" * 70)
    p("URL   : %s" % url)
    p("方法  : GET（无登录、无 Cookie、无凭证）")
    p("")

    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as r:
            raw = r.read(200000)
            body = raw.decode("utf-8", "ignore")
            status = r.status
            headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        p("[2] HTTP 响应")
        p("STATUS : %s（未取到正文，非 200 一般不成立）" % e.code)
        return "\n".join(lines), False
    except Exception as e:
        p("[2] HTTP 响应")
        p("请求失败：%s" % type(e).__name__)
        return "\n".join(lines), False

    p("=" * 70)
    p("[2] HTTP 响应")
    p("=" * 70)
    for k in ("Server", "Content-Type", "X-Powered-By"):
        if headers.get(k):
            p("%-14s %s" % (k + ":", headers[k]))
    p("STATUS         : %s" % status)
    p("BODY           : %d 字节" % len(raw))
    p("")

    p("=" * 70)
    p("[3] 页面内直接泄露的敏感信息")
    p("=" * 70)
    for label, key in ROWS:
        p("%-14s %s" % (label + ":", pick(body, key)))
    p("")

    p("=" * 70)
    p("[4] 页面特征确认（排除伪造页 / SPA 回落）")
    p("=" * 70)
    checks = [
        ("phpinfo 关键字", "phpinfo" in body.lower()),
        ("PHP Version 文本", "PHP Version" in body),
        ("php.ini 路径", "php.ini" in body),
        ("配置分节结构", "Core" in body and "Environment" in body),
    ]
    ok_all = True
    for name, ok in checks:
        p("%-18s %s" % (name + ":", "命中" if ok else "无"))
        ok_all = ok_all and ok
    p("")

    p("=" * 70)
    p("[5] 结论")
    p("=" * 70)
    if ok_all:
        p("确认是真 phpinfo 页面：公网无鉴权可读，输出 PHP 版本、")
        p("配置文件路径、服务器系统、站点绝对路径、内网地址等服务器内部信息。")
    else:
        p("特征不足，不判定为 phpinfo 泄露。可能被 WAF 拦截、被 SPA 回落到首页，")
        p("或本身就是伪造页。建议换路径或人工打开浏览器确认。")
    p("")
    p("本次仅做一次只读 GET，未探测其他端口，未尝试利用暴露的路径。")
    return "\n".join(lines), ok_all


def main():
    ap = argparse.ArgumentParser(description="phpinfo 泄露单目标取证")
    ap.add_argument("-u", "--url", required=True, help="完整地址，含 /phpinfo.php")
    ap.add_argument("--save", help="把输出另存为文本文件")
    args = ap.parse_args()

    text, ok = run(args.url)
    print(text)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("\n已保存：%s" % args.save)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
