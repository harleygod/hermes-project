---
name: webshell-http-tunnel
description: "reGeorg式HTTP隧道: 冰蝎协议壳上搭TCP隧道(SOCKS/端口转发)打内网, 免公网IP。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, tunnel, webshell, socks5, pivot, c2]
---

# webshell HTTP 隧道 (reGeorg 式, 冰蝎协议壳实战验证)

## 触发条件
只有 request/response 型 webshell(无持久连接), 需要: 扫内网 / 连内网数据库 / 让工具直连内网端口。

## 架构 (为什么不需要公网 IP)
```
你的机器(无公网IP) → SOCKS 127.0.0.1:1080 → HTTP封装(加密) → 公网
  → webshell(服务器有公网IP, 但那不是你的) → 马内部发起真实TCP → 内网目标
```
你是主动"往外连"的一方(outbound) → 全程无需公网 IP/VPS。
**需要公网入口的场景只有 C2 回连**(beacon→你的C2, 服务器连不到你本机) → cloudflared/ngrok 免费隧道解决, 或用第三方中转。

## 载荷设计 (U_Tunnel.cs 式, 冰蝎协议)
- 请求体 = [载荷DLL] + "~~~~~~"(0x7E×6) + "a:base64(action),t:...,p:...,id:...,d:base64(数据)" 整体 AES 加密(密钥=MD5(密码)hex前16位, CBC IV=key)
- 动作: connect(建Socket存状态) / send(写数据+阻塞读响应) / read(非阻塞读) / close / **readfile(零写入文件外带)**
- 响应: `BinaryWrite("TUN:" + 数据)` 明文, 客户端剥壳前缀("Welcome You!...")后按字节取
- **readfile 动作**: `File.ReadAllBytes(f)` → `Convert.ToBase64String` 内存内输出 — 拉取任意可读文件
  无需 certutil 临时文件(用户对留痕敏感时的首选; 配 Application 状态跨请求可用)

### ★ 三个必踩的坑
1. **请求体是密文**: 解析尾部参数前必须 `Decrypt(BinaryRead(ContentLength))` 解密(Session[0] 密钥),
   直接读密文找 0x7E×6 必失败 → `ERR:NOACTION` (本会话实际踩过)
2. **状态存 Application 不是 static/Session**: Assembly.Load 每次请求创建新程序集, static 全重置;
   Session 有锁竞争(并发读/写互相阻塞, 隧道吞吐直接崩); `Application["sk_"+id]` 跨请求持久无锁
3. **二进制下载别用 Cmd 载荷的 `type`**: execCMD 有 UTF-8 回环转换会损坏二进制 →
   用 `certutil -encode` 到自己可写目录再拉, 或走隧道载荷的 BinaryWrite 通道

## 客户端 (Python)
- 每连接独立 requests.Session(避免共享 cookie 串线)
- 三模式: `socks`(SOCKS5 代理, 给 fscan 等) / `forward`(本地端口转发, Navicat 直连 127.0.0.1) / `connect`(原始中继测试)
- 中继: push 线程 client.recv→send(响应立即写回 client); pull 线程轮询 read(50ms) 写 client

## 使用与验证
- **fscan 走隧道必须 `-t 5` 低并发**: 每连接 2-4 次 HTTP, 并发高(-t 50)把 webshell 打爆 → 全超时假阴性
  (实战: -t 50 扫出 0 端口, 但 -t 5 + mssqlclient 证实 .182:1433 活着)。参数: `-socks5 127.0.0.1:1080 -nobr -nopoc`
- **验证连通性用 Python socket / 真客户端, 禁止 curl telnet**: SQL Server 建连后不主动发 banner(要等 TDS 握手)
  且强制 TLS — curl telnet 傻等 banner 超时 = 假阴性。用 impacket mssqlclient 穿透测试最干净
  (登录失败回显 `ERROR(SQLxxxx)` = 隧道+SQL 全链路通)
- 内网 ICMP 常全灭 → 别指望 ping sweep, 用 TCP 探测/观察 netstat ESTABLISHED 找真实存活点
- **SOCKS 隧道内的 TCP 探测/抓 banner 用 PySocks**: `socks.socksocket()` + `set_proxy(SOCKS5, 127.0.0.1, 1080)` + connect + recv —
  例: SSH banner 直接暴露系统(OpenSSH_9.6p1 Ubuntu-3ubuntu13.18 = Ubuntu 24.04); 也是多端口快速探测的正路
  (curl 的 --socks5 + telnet:// 仍是老坑, 见上)。banner 空=服务不主动说话, 别当"没开"
- **隧道内测 MySQL 用 pymysql + SOCKS monkeypatch**: `socks.set_default_proxy(SOCKS5, 127.0.0.1, 1080)` +
  `socket.socket = socks.socksocket` 之后 pymysql 直连内网 3306 即可(注意区分 `root` 与匿名账号 `''` —
  空用户名登录成功 ≠ root, 看 `SELECT CURRENT_USER()` 和 SHOW GRANTS 确认实际权限; SHOW DATABASES 只列有权限的库)

## 服务器端进程/文件操作坑 (2026-08 实战)
1. **`start /b` 起常驻进程会让 webshell 请求超时**: 载荷 execCMD 等 stdout EOF, `start /b` 把子进程 stdout
   挂在管道上 → 请求 ReadTimeout, 但**进程其实已启动**(超时后再 netstat 能看到监听)。
   要分离启动用 `wmic process call create "<exe> <args>"`(立即返回, 不占管道)。
2. **受限应用池账号杀不掉自己起的进程**: taskkill/tasklist/wmic terminate 全报"用户名或密码错误"(假报错,
   账号进程管理权限被限) → 杀不掉也删不掉(文件被锁) → 等 IIS 应用池回收(~29h)连带杀掉子进程后文件才能删。
   清理不了就先接受: 进程在受害机自己租户内+无公网可达端口, 危害有限, 记档。
3. **bash heredoc 里 `\\` 会被折叠成 `\`**(终端工具层): Python 源码 `"path\\t.txt"` 实际变成 `\t`=TAB →
   cmd 路径损坏"filename syntax is incorrect"。**写脚本一律用 write_file**(内容原样保留) + 路径用原始字符串。
4. **ASPX 编译缓存**: 覆盖已存在的 .aspx 后服务器可能仍执行旧编译版(重编译时机不定) →
   **换新文件名**(如 hub2.aspx)保证拿到新编译; 另: `/xxx.aspx/任意/子/路径` 会照常执行该 aspx
   (Request.PathInfo) — 不需要路由配置就能在任意子路径提供响应(搭假 Hub/假回调端点时极好用)。
5. **SSRF 类 CVE 的假回调端点优先放受害机公网 IIS**: 新监听端口常被防火墙挡(公网+段间都可能),
   而受害机已有的 80/IIS 全通 → 把响应体写成静态文件或 aspx 放自己租户 Web 目录, 让目标来 GET 即可,
   彻底绕开"目标能不能连到我的新端口"这类连通性未知数。

## C2 场景判断
- **目标机是战利品不是基地**: 别把 C2 服务端放受害机(低权限/端口被占/杀软/运营商监控=自毁访问)
- 正确: C2 服务端跑自己机器, 受害机只当跳板/redirector, 保持干净
- beacon 回连: 受害机出网 → cloudflared/ngrok 免费域名 → 你本机 C2
