#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用探测型 POC 三分支验证脚手架（配合 vuln-intel-research 的 POC 编写规范）
用法：复制本文件到临时目录，修改下面 TODO 区（POC 路径 + 漏洞特征响应 + 断言关键字），
然后: python mock_probe_verify_harness.py
断言三分支: 漏洞版(200+特征响应体) / 已修复版(401) / 死端口(连接拒绝)。
三分支全 PASS 才可交付 POC。
若 POC 先发 GET 指纹请求（如首页含 window.nps），需在 VulnH/PatchedH 里补 do_GET
（漏洞版返回指纹页 200，修复版 401）——否则 mock 会回 501 干扰判定。
"""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# ===== TODO 区：按待验证 POC 修改 =====
POC = r"D:\path\to\your_poc.py"     # 待验证的 POC 脚本绝对路径
VULN_STATUS = 200                    # 漏洞接口返回码
VULN_HEADERS = {'Content-Type': 'application/json'}
VULN_BODY = json.dumps({"list": [{"Id": 1, "VerifyKey": "vk-test", "Password": "pw-test"}]}).encode()
VULN_TAG = "[VULN]"                  # POC 输出的漏洞标记
HIT_MARK = "VerifyKey"               # 漏洞特征串（须出现在 POC 输出/响应体）
PATCH_TAG = "likely patched"         # POC 对 401 等已修复情形的标记
FAIL_TAG = "conn fail"               # POC 对连接失败的标记
# =====================================

PY = sys.executable


class VulnH(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(VULN_STATUS)
        for k, v in VULN_HEADERS.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(VULN_BODY)))
        self.end_headers()
        self.wfile.write(VULN_BODY)

    def log_message(self, *a):
        pass


class PatchedH(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(401)
        self.end_headers()

    def log_message(self, *a):
        pass


s1 = HTTPServer(('127.0.0.1', 0), VulnH)      # port 0 = 动态端口，避免冲突
s2 = HTTPServer(('127.0.0.1', 0), PatchedH)
threading.Thread(target=s1.serve_forever, daemon=True).start()
threading.Thread(target=s2.serve_forever, daemon=True).start()
p1, p2 = s1.server_address[1], s2.server_address[1]
dead = p1 + 1 if p1 + 1 not in (p1, p2) else p2 + 1


def run(url):
    r = subprocess.run([PY, POC, url], capture_output=True, text=True, timeout=30)
    return r.stdout + r.stderr


cases = [
    ("vuln-mock   ", f"http://127.0.0.1:{p1}", VULN_TAG, HIT_MARK),
    ("patched-mock", f"http://127.0.0.1:{p2}", PATCH_TAG, None),
    ("dead-port   ", f"http://127.0.0.1:{dead}", FAIL_TAG, None),
]

fails = 0
for name, url, must, must2 in cases:
    out = run(url)
    ok = must in out and (must2 is None or must2 in out)
    print("%s %s -> %s" % ("PASS" if ok else "FAIL", name, url))
    if not ok:
        fails += 1
        print("   output: %s" % out.strip()[:200])

print("verification: %s" % ("ALL PASS" if fails == 0 else "%d FAILED" % fails))
sys.exit(1 if fails else 0)
