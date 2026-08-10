#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密 ASPX webshell 探测脚本（只发加密垃圾密文，不执行命令、不改数据）。
用法:
  python decrypt_probe.py http://target/shell.aspx --key afdd0b4ad2ec172c
  python decrypt_probe.py http://target/shell.aspx --key afdd0b4ad2ec172c --sizes 80,1024,4096,4624

判读:
  HIT(BadImageFormat/无法加载程序集) -> 该密钥解密成功 = 密钥正确
  PAD(Padding is invalid)            -> 密钥不对，或载荷被服务端截断
  15B oracle 返回 "Length of the data to decrypt is invalid"
                                     -> 服务端密钥长度有效(解密器在跑)
  15B oracle 返回 key size/IV 不匹配  -> Session 密钥为空或长度非法
"""
import argparse
import re
import sys

import urllib3
import requests

urllib3.disable_warnings()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad


def aes_enc(key: bytes, plain: bytes) -> bytes:
    padder = sympad.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return c.update(data) + c.finalize()


def classify(t: str) -> str:
    if "Padding is invalid" in t:
        return "PAD(密钥不对或载荷被截断)"
    if "BadImageFormat" in t or "Could not load file or assembly" in t or "incorrect format" in t:
        return "HIT(解密成功, 密钥正确!)"
    m = re.search(r"Exception Details:\s*</b>(.*?)<br", t, re.S)
    return ("ERR: " + m.group(1).strip()[:80]) if m else ("OTHER len=%d" % len(t))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="shell 完整 URL")
    ap.add_argument("--key", required=True, help="16字节 AES 密钥(冰蝎=密码MD5hex前16位)")
    ap.add_argument("--sizes", default="80,1024,4096,4624", help="密文长度列表, 逗号分隔")
    a = ap.parse_args()

    key = a.key.encode()
    if len(key) != 16:
        print("密钥必须是 16 字节(如冰蝎: hashlib.md5(pass).hexdigest()[:16])")
        sys.exit(1)

    # 15B oracle: 先确认服务端密钥长度状态
    r = requests.post(a.url, data=b"\x00" * 15,
                      headers={"Content-Type": "application/octet-stream"}, timeout=20)
    print("15B oracle:", classify(r.text))

    # 各长度密文: 小载荷过了=密钥对, 大载荷挂了=截断
    for n in [int(x) for x in a.sizes.split(",")]:
        ct = aes_enc(key, b"\x00" * max(0, n - 16))
        r = requests.post(a.url, data=ct,
                          headers={"Content-Type": "application/octet-stream"}, timeout=20)
        print(f"{n:6d}B -> {classify(r.text)}")


if __name__ == "__main__":
    main()
