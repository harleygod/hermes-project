---
name: vuln-intel-poc-collection
description: 用户给接口/参数/系统名要求查公开POC、判断1day、写POC并收录武器库时使用。
---

# 漏洞情报检索与 POC 收录工作流

用户长期任务：把新漏洞收录进 `D:\Pentest\攻防\武器库\`，格式见下文。核心承诺：**未公开的漏洞才自己写 POC**。

## 触发条件
- "这个漏洞公开了吗 / 市面上有没有 POC"
- "写个 POC / 收录这个漏洞"
- 用户给接口+参数（如 `/api/excel/formula/verifyFormula` + `expressSql`）要求查证

## 流程

### 1. 情报检索（公开性判断）
用户偏好：**浏览器搜索优先**（Google 的 AI 概述很有用），或第三方联网搜索 API（用户愿意提供 API key：Tavily/Serper/Brave 等）。curl 兜底途径与可用性矩阵见 `references/public-poc-search.md`。

要点：
- 搜"接口名 + 参数名 + 系统名"、系统名 + 漏洞类型（表达式注入/SQLi/RCE）
- 必须**区分同名相似漏洞**：命中一堆"系统名+漏洞类型"的文章 ≠ 目标漏洞公开。逐个核对接口路径是否一致
- 检查官方 nuclei-templates / xray poc 库是否有该接口模板

### 2. 原理分析
- 从接口命名 + 参数命名推断（`expressSql` → 表达式转 SQL → 表达式引擎或 SQL 拼接）
- **先问用户要报告/样本细节**——用户手上常有利用链情报（如"内存马注入 defineClass 字节码"），这比盲猜引擎类型值钱得多
- 引擎指纹候选：JEXL / QLExpress / SpEL / OGNL / 自研公式转 SQL

### 3. 探测型 POC 编写
渐进式设计，默认零副作用：
1. 接口存在性（GET + POST 空参）
2. 正常公式回显（算术/字符串/布尔/Excel 函数/模板语法）
3. 引擎指纹判定
4. 时间型探测（`--sleep-test` 显式开启）
5. RCE/利用（`--exploit` 显式开启 + tty 交互确认）

红线（用户明确要求）：**内存马注入、文件写入、数据修改等写操作绝不自动执行**；POC 不内置注入载荷，只提示利用链。

### 4. 验证（必须做）
用 Python 内置 `http.server` + `ThreadingTCPServer` 起本地 mock 服务器，模拟多场景：
- 表达式执行回显 → 应判 vulnerable
- 原样回显（服务器反射输入）→ 必须不误报
- 连接失败/404 → 必须短路
- 慢响应（sleep）→ 时间型判定
- CLI 入口 + JSON 输出文件
写临时验证脚本（tempfile 路径、hermes-verify- 前缀），跑完即删。

### 5. 收录格式
```
D:\Pentest\攻防\武器库\<漏洞名或系统名>\
├── 0day.md          # 漏洞分析：状态(未公开/公开)、原理、利用链、与相似漏洞区分
├── <poc>.py         # 探测 POC
├── targets.txt      # 目标列表(注释注明仅限授权)
└── requirements.txt
```

## Pitfalls（踩过的坑）

1. **patch 工具模糊匹配会破坏缩进**：某次 patch 把 `return results` 缩进改成 8 空格，导致函数体提前结束、后续代码被吸进另一个函数变成死代码，函数返回 None。症状：函数行为诡异、部分代码不执行。诊断：`dis.dis(fn)` / 检查 `fn.__code__.co_consts` 是否缺少预期常量。修复：直接 `write_file` 重写整个文件，别用多次 patch 修补。
2. **回显判定必须排除"原样回显"**：服务器可能只是反射输入（body 含 payload 本身），数字特征（如 `"1" in body`）会误报。判定前先排除 `normalize(payload) in normalize(body)`。
3. **连接失败/404/403/405 要短路**：错误文本里的数字会触发引擎误判。
4. 执行回显 vs 原样回显的区分是 POC 防误报核心，验证脚本必须覆盖。
5. 用户搜索方式偏好：不要用 curl 大规模 grep 本地目录/搜索引擎（慢且效果差）；浏览器搜索或联网搜索 API 优先。

## 支持文件
- `references/public-poc-search.md` — 各搜索途径 curl 可用性矩阵
- `references/weaver-ecology-verifyformula.md` — 泛微 e-cology verifyFormula 1day 案例（利用链+指纹判定）
- `references/jeesite-default-keys.md` — JeeSite 默认密钥/账号速查
