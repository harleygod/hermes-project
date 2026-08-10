# 武器库持久回归测试脚本范例（verify_<name>_poc.py 结构）

来自 GeoServer CVE-2024-36401 交付实例。要点：import POC 模块直接测函数分支 +
subprocess 测 CLI 确认守卫 + 三态 mock。持久保留在武器库目录，改 POC 后重跑。

## 结构骨架
```python
# -*- coding: utf-8 -*-
"""<漏洞> POC 回归测试 (本地 mock, 无网络依赖)。用法: python verify_<name>_poc.py"""
import re, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, __file__.rsplit('\\', 1)[0])   # 保证 import 同目录 POC 模块
import <name>_poc as P
POC = P.__file__
PY = sys.executable

class VulnMock(BaseHTTPRequestHandler):     # 漏洞版：正常指纹 + 回显命令输出
    def log_message(self, *a): pass
    def do_GET(self):
        # 按路径分发：指纹页 200 / 注入点 200 回显 / 其余 404
        ...

class ReflectMock(BaseHTTPRequestHandler):  # 反射版：原样反射 payload（测 is_echo 防误报）
    ...
class FixedMock(BaseHTTPRequestHandler):    # 修复版：注入点返回 401/400/无效参数
    ...

def serve(h):
    s = HTTPServer(('127.0.0.1', 0), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return 'http://127.0.0.1:%d' % s.server_address[1]

def main():
    base_v, base_r, base_f = serve(VulnMock), serve(ReflectMock), serve(FixedMock)
    dead = 'http://127.0.0.1:1'
    fails = []
    def check(name, cond, detail=''):
        print('%s %s %s' % ('PASS' if cond else 'FAIL', name, detail))
        if not cond: fails.append(name)
    # 断言组（按漏洞分支设计）：
    # 1 指纹/前缀识别 2 参数提取 3 漏洞版判 VULN 4 反射版不判漏洞 5 修复版不判漏洞
    # 6 死端口失败短路 7 CLI 非 tty 拒绝 --exploit/--verify（subprocess stdin=DEVNULL，
    #   断言输出含"拒绝"且无执行结果） 8 exploit 输出提取
    ...
    print('regression: %s (%d failed)' % ('ALL PASS' if not fails else 'FAILED', len(fails)))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
```

## 关键点
- **死端口断言**：`http://127.0.0.1:1` 必拒绝连接（WinError 10061），测失败短路
- **CLI 守卫断言**：subprocess 传 stdin=subprocess.DEVNULL 模拟非交互；
  断言 stdout 无执行结果 + 输出含拒绝文案（见 SKILL.md Pitfalls 的 EOFError 方案）
- **反射断言**：mock 返回 `%s` % ref 原文，POC 应判"未执行"
- mock 对注入点用 parse_qs 解 valueReference 后正则提取命令串，按命令内容回显模拟输出
