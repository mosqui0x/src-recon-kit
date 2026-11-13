#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
git_leak_check.py —— 判断目标站点的 .git 目录是否可被完整读取

Author : Mosqui（蚊子）  https://github.com/mosqui0x
Project: src-recon-kit
Version: 1.0
Date   : 2026-11

用途：确认 /.git/config 不只是 404 页伪装，而是真能拿到 git 仓库数据。
会顺着 HEAD -> refs -> commit object -> tree object -> blob 走一遍，
输出每一步的状态码。走到 blob 能解压出源码内容，才算「可完整还原」。

原则：只读 GET，只取必要对象，不遍历全仓库、不批量下载源码文件。

用法：
    python git_leak_check.py -u https://example.com
    python git_leak_check.py -u https://example.com --save out.txt

注意：只对你有授权的目标使用。
"""

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request
import zlib

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def fetch(base, path, timeout=10):
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""


def inflate(raw):
    """git object 是 zlib 流，解开后头部是 '<type> <size>\\x00'。"""
    try:
        return zlib.decompress(raw).split(b"\x00", 1)[1]
    except Exception:
        return None


def parse_tree(raw):
    """tree 对象：<mode> <name>\\x00<20 字节 sha> 依次排列。"""
    out, i = [], 0
    while i < len(raw):
        sp = raw.find(b" ", i)
        if sp < 0:
            break
        nul = raw.find(b"\x00", sp)
        if nul < 0:
            break
        name = raw[sp + 1:nul].decode("utf-8", "ignore")
        sha = raw[nul + 1:nul + 21].hex()
        out.append((name, sha))
        i = nul + 21
    return out


def run(base):
    lines = []
    p = lines.append

    p("=" * 70)
    p("[1] 目标 %s" % base)
    p("=" * 70)

    code, body = fetch(base, "/.git/config")
    txt = body.decode("utf-8", "ignore")
    real_cfg = code == 200 and "[core]" in txt and "repositoryformatversion" in txt
    p("[.] /.git/config -> HTTP %s  %d 字节  %s"
      % (code, len(body), "真 git config" if real_cfg else "不像 git config"))
    if real_cfg:
        m = re.search(r"url\s*=\s*(.+)", txt)
        if m:
            p("    远程地址: %s" % m.group(1).strip())
    if not real_cfg:
        p("")
        p("结论：/.git/config 拿不到有效内容，多半是 WAF 或 SPA 回落，不构成泄露。")
        return "\n".join(lines), False

    code, body = fetch(base, "/.git/HEAD")
    head = body.decode("utf-8", "ignore").strip()
    p("[.] /.git/HEAD   -> HTTP %s  %s" % (code, head[:80]))

    # 从 HEAD 找 commit sha
    sha = None
    m = re.search(r"ref:\s*(refs/\w+/[\w\-\.]+)", head)
    if m:
        ref = m.group(1)
        code, body = fetch(base, "/.git/" + ref)
        s = body.decode("utf-8", "ignore").strip()
        if re.fullmatch(r"[0-9a-f]{40}", s):
            sha = s
            p("[.] /.git/%-24s -> HTTP %s  %s" % (ref, code, s[:12]))
    if not sha and re.fullmatch(r"[0-9a-f]{40}", head):
        sha = head

    if not sha:
        code, body = fetch(base, "/.git/logs/HEAD")
        arr = re.findall(rb"[0-9a-f]{40}", body)
        if arr:
            sha = arr[-1].decode()
            p("[.] /.git/logs/HEAD -> HTTP %s  取到最近 commit %s"
              % (code, sha[:12]))

    if not sha:
        p("")
        p("结论：拿得到 config，但定位不到 commit，源码还原性不确定。")
        return "\n".join(lines), False

    # commit object
    code, body = fetch(base, "/.git/objects/%s/%s" % (sha[:2], sha[2:]))
    commit = inflate(body)
    if commit is None:
        p("[.] commit 对象 -> HTTP %s  解压失败，可能被拦截或不是 git object" % code)
        return "\n".join(lines), False
    p("[.] commit 对象 -> HTTP %s  解压成功 %d 字节" % (code, len(commit)))
    for l in commit.decode("utf-8", "ignore").splitlines()[:4]:
        if l.strip():
            p("    | " + l.strip()[:90])

    mt = re.search(rb"tree ([0-9a-f]{40})", commit)
    if not mt:
        p("commit 里没有 tree 指针，无法继续。")
        return "\n".join(lines), False

    tree_sha = mt.group(1).decode()
    code, body = fetch(base, "/.git/objects/%s/%s" % (tree_sha[:2], tree_sha[2:]))
    treeraw = inflate(body)
    if treeraw is None:
        p("[.] tree 对象 -> HTTP %s  解压失败" % code)
        return "\n".join(lines), False
    entries = parse_tree(treeraw)
    p("[.] tree 对象   -> HTTP %s  根目录条目 %d 个" % (code, len(entries)))
    names = [n for n, _ in entries][:12]
    p("    条目: %s" % (" ".join(names) + (" ..." if len(entries) > 12 else "")))

    # 找一个源码类型的 blob
    picked = None
    for name, s in entries:
        if name.endswith((".php", ".js", ".html", ".env", ".json", ".sql", ".txt")):
            picked = (name, s)
            break

    if picked:
        name, s = picked
        code, body = fetch(base, "/.git/objects/%s/%s" % (s[:2], s[2:]))
        blob = inflate(body)
        if blob is not None:
            p("[.] blob %-16s -> HTTP %s  还原 %d 字符，前 3 行:"
              % (name, code, len(blob)))
            shown = 0
            for l in blob.decode("utf-8", "ignore").splitlines():
                if l.strip():
                    p("    | " + l.strip()[:88])
                    shown += 1
                if shown >= 3:
                    break

    p("")
    p("=" * 70)
    p("结论：.git 目录可读，config / HEAD / 引用 / commit / tree%s 全部拿到，"
      % (" / blob" if picked else ""))
    p("      攻击者可离线还原整站源码，属于源码泄露，建议立即下线 .git 目录。")
    p("=" * 70)
    return "\n".join(lines), True


def main():
    ap = argparse.ArgumentParser(description=".git 目录泄露完整性校验")
    ap.add_argument("-u", "--url", required=True, help="目标根地址，如 https://example.com")
    ap.add_argument("--save", help="输出另存为文本")
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
