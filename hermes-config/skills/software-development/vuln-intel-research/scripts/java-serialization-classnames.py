#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Java 序列化流提取类名(+SUID) — 0day 载荷版本分析用

用法:
    python java-serialization-classnames.py value.txt [--b64]
      --b64  输入是 base64 文本 (常见于 value.txt 载荷文件)

输出: 去重类名列表 (含数组类型如 [B / [[Ljava.lang.Object;)

用途: 类名集合即可判断依赖版本线, 如
    org.apache.commons.collections.comparators.*  = commons-collections 3.x
    org.apache.commons.collections4.comparators.* = commons-collections 4.x
SUID 区分小版本价值低 (cc3.2.1/3.2.2 等 SUID 不变), 列出来仅作参考。
"""
import base64
import struct
import sys

MAGIC = b"\xac\xed\x00\x05"


def extract(raw: bytes):
    names = []
    seen = set()
    i = 0
    while i < len(raw) - 2:
        if raw[i] == 0x72:  # TC_CLASSDESC: 2字节长度 + 类名 + 8字节 SUID
            ln = struct.unpack(">H", raw[i + 1 : i + 3])[0]
            nm = raw[i + 3 : i + 3 + ln].decode("utf-8", "replace")
            suid = ""
            end = i + 3 + ln + 8
            if end <= len(raw):
                v = struct.unpack(">q", raw[i + 3 + ln : end])[0]
                suid = "  0x%016x" % (v & 0xFFFFFFFFFFFFFFFF)
            if nm not in seen:
                seen.add(nm)
                names.append(nm + suid)
        i += 1
    return names


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    data = open(path, "rb").read()
    if "--b64" in sys.argv:
        data = base64.b64decode(data)
    if data[:4] != MAGIC:
        print("[!] 不是 Java 序列化流 (魔数应 aced0005), 仍尝试提取:", file=sys.stderr)
    for n in extract(data):
        print(n)


if __name__ == "__main__":
    main()
