#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 反编译侦察：提取 dex + Flutter libapp.so 的字符串，输出敏感信息。
用法: python apk_strings.py app.apk [输出前缀]
输出: <前缀>_strings.txt (全部字符串), <前缀>_hits.txt (敏感命中)
"""
import zipfile
import re
import sys
import os


def extract_zip(zf, names):
    """解包所有 dex 和 libapp.so 返回字节"""
    chunks = []
    for n in names:
        try:
            chunks.append((n, zf.read(n)))
        except Exception:
            pass
    return chunks


def get_strings(data):
    return [s.decode('ascii', 'ignore') for s in re.findall(rb'[\x20-\x7e]{6,}', data)]


def main():
    if len(sys.argv) < 2:
        print("用法: python apk_strings.py app.apk [前缀]")
        sys.exit(1)
    apk = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(os.path.basename(apk))[0]

    zf = zipfile.ZipFile(apk)
    names = zf.namelist()
    print(f"[*] {apk}: {len(names)} 文件")

    # 目标文件: dex + Flutter libapp.so
    targets = [n for n in names if n.endswith('.dex') or 'libapp.so' in n]
    if not targets:
        print("[!] 无 dex/libapp.so，可能是网页壳")
        return
    for t in targets:
        print(f"  [+] 提取: {t}")

    all_strs = []
    for name, data in extract_zip(zf, targets):
        strs = get_strings(data)
        print(f"  {name}: {len(strs)} 字符串")
        all_strs.extend(strs)

    uniq = list(dict.fromkeys(all_strs))
    with open(f"{prefix}_strings.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(uniq))
    print(f"[+] 全部字符串 -> {prefix}_strings.txt ({len(uniq)})")

    # 敏感过滤
    kw = re.compile(
        r'(https?://|\.com\.cn|\.cpic\.|\bgitee\.com|\bgithub\.com|'
        r'\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(:\d+)?|'
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}|'
        r'secret|api[_-]?key|app[_-]?secret|BEGIN (RSA|PRIVATE)|'
        r'/api/|/rest/|/policy/)', re.I)
    hits = [s for s in uniq if kw.search(s) and len(s) < 300]
    with open(f"{prefix}_hits.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(hits))
    print(f"[+] 敏感命中 -> {prefix}_hits.txt ({len(hits)})")
    print("\n=== 命中预览（前 40 条）===")
    for h in hits[:40]:
        print(" ", h[:160])


if __name__ == '__main__':
    main()
