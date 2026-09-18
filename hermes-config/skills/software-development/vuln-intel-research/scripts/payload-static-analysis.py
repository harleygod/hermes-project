#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯静态载荷/class 分析 —— 绝不执行反序列化(readObject/Class.forName/实例化)。

只读字节流: 扫 Java 序列化流的 TC_CLASSDESC(0x72) 类名 + 提取 .class 常量池 CONSTANT_Utf8 字符串。
用途: 拿反序列化链结构、恶意类假设、产品指纹, 全程不触发任何 Java 代码执行。

用法:
    python payload-static-analysis.py -p value.txt                    # 序列化流(自动识别 b64 或原始魔数)
    python payload-static-analysis.py -c _cls0.class _cls1.class      # .class 文件常量池字符串
    python payload-static-analysis.py -p value.txt -c a.class b.class
"""
import base64
import struct
import sys
import argparse


def scan_serial_classnames(raw: bytes):
    """扫 TC_CLASSDESC(0x72): u2 类名长度 + UTF类名, 去重保序。不 readObject。"""
    out, i, n = [], 0, len(raw)
    while i < n:
        if raw[i] == 0x72:
            if i + 3 <= n:
                ln = struct.unpack('>H', raw[i + 1:i + 3])[0]
                if i + 3 + ln <= n:
                    out.append(raw[i + 3:i + 3 + ln].decode('utf-8', 'replace'))
                    i += 3 + ln
                    continue
        i += 1
    seen = []
    for c in out:
        if c not in seen:
            seen.append(c)
    return seen


def class_strings(path):
    """提取 .class 常量池 CONSTANT_Utf8 字符串。纯字节读取。"""
    data = open(path, 'rb').read()
    if data[:4] != b'\xca\xfe\xba\xbe':
        return None, '非 class 文件(魔数 %s)' % data[:4].hex()
    major = struct.unpack('>H', data[6:8])[0]
    count = struct.unpack('>H', data[8:10])[0]
    i, strings = 10, []
    for _ in range(count - 1):
        if i >= len(data):
            break
        tag = data[i]
        i += 1
        if tag == 1:  # CONSTANT_Utf8
            ln = struct.unpack('>H', data[i:i + 2])[0]
            strings.append(data[i + 2:i + 2 + ln].decode('utf-8', 'replace'))
            i += 2 + ln
        elif tag in (7, 8, 16, 19, 20):   # Class/String/MethodType/Module/Package
            i += 2
        elif tag == 15:                    # MethodHandle
            i += 3
        elif tag in (3, 4):                # Int/Float
            i += 4
        elif tag in (5, 6):                # Long/Double
            i += 8
        elif tag in (9, 10, 11, 12, 17, 18):  # refs/NameAndType/Dynamic/InvokeDynamic
            i += 4
        else:
            break
    return major, strings


# 有情报价值的字符串关键词: 路径/类名/密钥/危险 API
_INTEREST = ('/', '.jsp', 'WEB-INF', 'CodeSource', 'defineClass', 'forName', 'Cipher',
             'SecretKey', 'http', 'com.', 'org.', 'Pwner', 'Gadget', 'Runtime', 'exec',
             'ProcessBuilder', 'ysoserial', 'BASE64', 'getMethod', 'getRuntime', 'translet')


def main():
    ap = argparse.ArgumentParser(description='纯静态载荷/class 分析(不执行反序列化)')
    ap.add_argument('-p', '--payload', help='序列化流文件(base64 或原始魔数 aced0005)')
    ap.add_argument('-c', '--classes', nargs='*', help='.class 文件')
    a = ap.parse_args()

    if a.payload:
        raw = open(a.payload, 'rb').read().strip()
        if raw[:4] != b'\xac\xed\x00\x05':
            raw = base64.b64decode(raw)
        print('[序列化流类名] 魔数 %s' % raw[:4].hex())
        for c in scan_serial_classnames(raw):
            print('   ', c)

    for p in (a.classes or []):
        r = class_strings(p)
        if r is None:
            print('[%s] %s' % (p, r[1]))
            continue
        major, ss = r
        print('\n[%s] class major=%d  共 %d 个字符串' % (p, major, len(ss)))
        for s in ss:
            if any(k in s for k in _INTEREST):
                print('   ', s)


if __name__ == '__main__':
    main()
