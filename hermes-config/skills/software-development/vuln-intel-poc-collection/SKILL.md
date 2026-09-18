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

## 收录决策（用户明确规则，2026-08 确认）

用户原话："它是老day呀nday嘛，是的话就不收录了"——**公开传播已久的老 nday 一律不收录武器库**，直接说明判定依据即可，不建目录。收录价值 = 新洞/未公开/独到利用链。

老 nday 快速判定信号（任一强信号即可定论）：
1. 公开文章/POC 传播时间 ≥2 年（CSDN 文章 ID 段可粗估发布时间，1380 万段 ≈ 2024 年中）
2. POC 内**硬编码固定 token**（如 `accessToken: eyJhbG...`）——真未授权接口不需要 token；固定 token 是老 POC 互相抄的特征
3. 利用链是教科书式老打法（multipart + `filename="./webapps/...jsp"` 路径穿越写 shell）——2019-2023 用友/致远/泛微系列遍地都是，已被扫描器/WAF 覆盖
4. 各来源 POC 抄同一 token / 同一种姿势 = 圈内传烂

判老 nday 后的回复格式：结论（老 nday，不收录）+ 判定依据（文章时间/token 特征/利用链老旧/扫描器覆盖）+ 与本库已有条目的区分（同厂不同洞必须指出，如 NC65 mp 上传已在库、NC Cloud importhttpscer 不收录）。

实战中"有人用"不构成收录理由：老 nday 打存量未打补丁目标本来就是攻防主流玩法，圈内一直有人用，与漏洞的新旧/收录价值无关。

## 0day 价值评估（用户报"未公开 0day"时）

用户原话（2026-08）："不是，它就是0day,我的重点是它这个漏洞值钱不，适用范围多吗"——**用户报 0day 时不要花时间辩论公开性**（除非有强烈疑点），直接评估两件事：值钱度 + 适用范围。回复结构：产品定位确认 → 值不值钱（原因）→ 适用范围（广/窄两面都要说）→ 结论 + 收录前提。

**公开性快速佐证**：NVD `keywordSearch=厂商名` 查 CVE 归属（如 `inspur` 名下 5 条全是服务器硬件、无 inBuilder 相关 → CVE 层面干净）。GitHub repo/code 搜产品名无对应安全仓库也可佐证。

**值钱度评估维度**：
1. **平台类漏洞 = 一锅端**：低代码平台/中间件/ERP 的 SQLi 不是单系统，拖库拖的是平台上所有业务应用数据（财务/人力/供应链），还能顺带尝试写文件/读配置。一个平台 ≈ 几十个业务系统的数据量
2. **0day 溢价**：未公开 = 无 WAF 规则/扫描器特征/蓝队没见过，护网/攻防第一次打是降维打击
3. **客户质量**：厂商主攻央国企/政企（如浪潮通软 inBuilder 客户 = 央企集团总部/省属国企）→ 攻防演练重点目标，出洞即拿分

**适用范围评估**（关键限制必须说清）：
- 广的一面：存量部署量、开源社区版（能下源码逆向确认端点，不用靠猜）
- 窄的一面：**私有化部署基本不暴露公网**（低代码平台多在集团内网，过 VPN/堡垒机）→ 实战场景是"已进内网后横向"或授权测试，不是 FOFA 扫一批。必须如实说明，否则用户对目标存量会误判

**使用广度（存量）快速评估**（数犀云身份连接器案例 2026-08）：CSDN API + Bing + GitHub issues + NVD 全渠道查产品名/产品名+核心词（如"数犀云身份连接器"）。判读信号：第三方讨论≈0 且命中全是自家营销稿 = 长尾小产品；结果里自然带出竞品名（Authing/宁盾/竹云类）= 同赛道小玩家；BOSS直聘在招"解决方案专家" = 公司扩张中但规模小；CSDN 有安全组件新闻（鸿蒙适配类）但无安全讨论 = 有技术输出无安全热度。结论句式："单点价值高（身份/凭证类一锅端）+ 存量少/碰到概率低 → 遇到了就打，不适合主动测绘"。官网/企查查被反爬时如实说渠道受限，别用旧知识顶替。

**收录前提三件事**（对用户说清）：
1. 利用链确认：普通注入（只拖库）vs 可升级写文件/RCE（价值翻倍，低代码平台常配文件生成功能）
2. 端点细节：具体端点/参数/payload 形态，最好能下开源版源码自验证（铁规矩：POC 真实环境端到端，mock 不算）
3. "未公开"纯度：没进过公众号/群文件/公开 POC 库，纯度决定能卖多久

## 流程

### 1. 情报检索（公开性判断）
用户偏好：**浏览器搜索优先**（Google 的 AI 概述很有用），或第三方联网搜索 API（用户愿意提供 API key：Tavily/Serper/Brave 等）。curl 兜底途径与可用性矩阵见 `references/public-poc-search.md`。

要点：
- 搜"接口名 + 参数名 + 系统名"、系统名 + 漏洞类型（表达式注入/SQLi/RCE）
- 必须**区分同名相似漏洞**：命中一堆"系统名+漏洞类型"的文章 ≠ 目标漏洞公开。逐个核对接口路径是否一致
- 检查官方 nuclei-templates / xray poc 库是否有该接口模板
- **全渠道零命中时的处理（致远 wapi.getConditionValue 案例 2026-08）**：CSDN/GitHub issues/GitHub HTML/搜狗/Bing/百度/微信搜狗/先知/POC 仓库全查完仍零直接命中时，**停止盲目扩渠道**。三种可能：① 极新鲜（几天内）未索引；② 名称来自源码/调用链，公开文章用别的名字；③ 圈内私有流传。回复结构：如实汇报"公开渠道找不到" + 已查渠道清单 + 问用户来源线索（公众号/群/通报链接——定向挖比盲搜快十倍）+ 建议浏览器 Google 精确串（引号全匹配，索引最新中文情报）。顺带可用百度验证"接口名是否出现在厂商官方开发文档"（致远 open.seeyon.com 的 wapi 即被官方文档收录）确认接口真实存在。nuclei-templates 树 API 常被共享 IP 限流，可改用 git 浅克隆 templates 仓库 grep（git 协议不受限）

### 2. 原理分析
- 从接口命名 + 参数命名推断（`expressSql` → 表达式转 SQL → 表达式引擎或 SQL 拼接）
- **先问用户要报告/样本细节**——用户手上常有利用链情报（如"内存马注入 defineClass 字节码"），这比盲猜引擎类型值钱得多
- 引擎指纹候选：JEXL / QLExpress / SpEL / OGNL / 自研公式转 SQL
- **泄漏源码验证（国产商业产品 1day 首选，通达OA 案例实证）**：GitHub 搜 `<产品名> 源码/v11` 常有泄漏仓库（如通达OA `sever686/-OAv11`，155MB 完整 v11）。浅克隆后三看：① 前端 chunk.js 里 `$.ajax({url:"...", data:{...}})` 实锤接口存在+参数名（通达 `general/hr/medals/manage/list.chunk.js` 就实锤了 setlaunch 的 id/is_launch）；② 控制器/模型看 SQL 拼接风格——参数直拼（`LIKE '%$kw%'`、`IN ($priv_id)`）= 注入风格实锤；③ 入口文件看参数预处理（通达 appbuilder 的 `web/index.php` 会把所有 GET/POST 值 `base64_encode` 后进框架——若新版保留该逻辑，payload 需 base64 适配）。注意 zend/ioncube 加密文件可能解不开（解密残留 `class not found` 是坏文件），但同模块其他文件够看风格。

- **产品官方开源时（汉得 HZERO 案例 2026-08）**：`git clone -c http.proxy=<代理> --depth 1 <官方仓库>` 直接拿源码（**git 协议不受 GitHub API 限流**，API 403 时的替代通道），grep 接口实现后做**商业版 vs 开源版对照**：商业版独有接口（如 `/rule-engine/run-script` 的裸 `script` 字段）在开源版里没有，开源等价接口（`/rule-scripts/test`）只有 `scriptCode`+`params` 且带 `@Permission(level=ORGANIZATION)` 注解——**权限注解直接回答"认证前置"问题**，这是 0day 值钱度的分水岭（未授权=前台 RCE，需登录=后台 RCE 大打折扣）。坑：开源仓库 git 历史可能被压成单提交（`[AUTO] commit project`），无法考古旧版；Maven 构件可能不在 Maven Central 而在厂商私有 nexus（REST search 未认证返回 0、直接路径 404——抓构件难，靠开源源码即可）
- **NVD API 快查 CVE 核心事实（fastjson 案例 2026-08）**：`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` 一次拿到描述/影响版本区间/CVSS/发布日期——判定新老、影响面、收录价值的第一步，比搜文章快。注意 NVD 描述可能自带关键筛选条件（如 CVE-2026-16723 要求 Spring Boot fat-jar 部署、fastjson2 不受影响）——这些直接决定适用范围，必须写进 0day.md
- **GitHub Wiki 是独立 git 仓库（fastjson 案例）**：官方通告常放 wiki（`<repo>.wiki.git`，如 `alibaba/fastjson2.wiki.git`）——`git clone` 直接拿原文，比反复解析 wiki 网页（react-payload/markdown-body 正则常失配）可靠。坑：wiki 文件名含 `:`/en-dash 等特殊字符（如 `Security-Advisory:-...1.2.83.md`）Windows 检出报 `invalid path`——用 `git ls-tree -r HEAD --name-only` 看树 + `git show "HEAD:<路径>"` 直接读内容，无需 checkout

### 3. 探测型 POC 编写
渐进式设计，默认零副作用：
0. **认证前置判定（后台 RCE vs 前台 RCE 的分水岭，汉得 HZERO 案例 2026-08）**：无凭据发**无害脚本**（如 Groovy 字符串字面量 `{"script":"'probe'","params":{}}`——eval 字面量零副作用，可全资产扫）探接口：401/403=需登录(后台RCE)，200=未授权(前台RCE)。**401 响应体结构本身即产品指纹**：HZERO 权限过滤器返回 `<oauth><status>PERMISSION_ACCESS_TOKEN_EXPIRED</status>`——401 而非 404 = 路由存在+需认证，一眼区分"接口活着但被拦"与"接口不存在"。武器化文档**必须标注前台/后台 RCE**（用户原话："标明是后台rce就行了"），这是值钱度的第一标注
1. 接口存在性（GET + POST 空参）
2. 正常公式回显（算术/字符串/布尔/Excel 函数/模板语法）
3. 引擎指纹判定
4. 时间型探测（`--sleep-test` 显式开启）
5. RCE/利用（`--exploit` 显式开启 + tty 交互确认）

红线（用户明确要求）：**内存马注入、文件写入、数据修改等写操作绝不自动执行**；POC 不内置注入载荷，只提示利用链。

### 3.5 第三方 POC/载荷文件：先解读、再校验、后收录（2026-08 TongWeb 案例确立）

用户提供第三方 exploit 文件（抓包/序列化流）要求收录时，顺序必须是：**先一起逐段解读（大白话+Java 术语讲清每段作用），用户确认安全后，才继续收录/验证**。用户会明确喊停（"先等下，先跟我一起解读下这个文件，我才能放心"）；且**载荷发送动作（--send，即使对本地 mock）需用户批准，被否决后不得重试/换法绕过**——安全敏感度高于一般流程。

解读要覆盖：文件是什么（抓包存档 vs 脚本，前者不会自执行）、请求头、body 魔数（Java 序列化 `AC ED 00 05`）、gadget 链各环节、终点表达式（如 EL→JS 引擎→defineClass 内存加载）、内嵌类字节本来干什么（睡眠类=时间型检测）。用户是 Java/Spring 背景，直接用 Java 术语（readObject/defineClass/ClassLoader）最有效。

安全校验三层（对任何第三方载荷，收录前必做）：
1. **全量网络指示符扫描**：IPv4 / 域名 / URL 协议（http/ldap/rmi/jndi/dns）/ C2 关键字（beacon/cobalt/meterpreter/reverse/exec/socket）。自包含链（JNDI 用 BeanFactory 本地实例化 + 内嵌类加载，无远程引用）即无回连能力
2. **内嵌类字节只做 defineClass 等价加载测试**（临时 Java 程序喂字节，看是否 ClassFormatError）——**绝不本地 `ObjectInputStream.readObject()` 整条流**（那是唯一会让本机执行链的操作，链会在本机触发）
3. **严格 base64 校验**：`base64.b64decode(s, validate=True)` 找非法字节。流传 PoC 常混入损坏字节（TongWeb 案例 b64 偏移 593-596 混入 `\x00\x00\x02\xb9` → JDK8 defineClass 报 ClassFormatError），宽松解码会静默跳过 → 误判类可用。损坏载荷只能当"链触发"证据，不能做时间型检测
4. **执行位置诚实披露 + 操作透明**（用户问"你是在沙箱上执行的嘛"时）：如实说明 terminal 直接跑在用户本机（git-bash），**不是沙箱/VM**——这是信任基础，隐瞒必翻车。用户要求证明"没执行过恶意命令"时，给 ① 全部命令清单（对话记录即完整日志）② 取证式独立检查：ps/进程、netstat 外连、磁盘产物+时间戳、sha256 哈希留存供复验、临时文件清理确认 ③ 主动披露疏漏（如 mock 进程没杀干净、机器上已有相关依赖 jar——用户会自己发现，不如先说）。完整利用链验证建议放隔离环境/VM，本机只做静态分析
5. **0day/敏感载荷数据严禁外传**（用户 2026-08 明确要求，记入长期记忆）：不上传任何服务、不拿载荷内容做搜索/查公开性、不写入公共渠道（公众号/群/报告模板/在线工具）。查公开性**只查接口路径名/类名**（如 `dispatch/invoke`、`copyValueOf`），载荷内容（序列化字节/恶意类/JSP 源码）绝不外发——名字和内容两码事，动手前先跟用户说清这条边界。用户确认"它就是0day"后不再辩论公开性（入口新就是新，链老不影响入口新的判断）
6. **第三方 Java 反序列化载荷的静态取证**（泛微 CB1 案例沉淀）：结构识别/gadget 家族判定/内嵌类与 JSP 提取/生成器溯源/损坏判定，方法见 `references/java-deserialization-payload-forensics.md`

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
6. **HTTP GET 注入 payload 必须 URL 编码（通达OA 案例实证）**：SQLi payload 含空格/括号（`id=0 AND SLEEP(3)`）直接拼进 URL 发给 urllib 会损坏 HTTP 请求行 → status=0/超时，POC 静默失效且难排查。发送前 `urllib.parse.quote(query, safe="&=:%'+,~-_.!*")`（safe 保留 `%` 防已编码序列二次编码）。**对称坑**：mock 验证服务器必须 `urllib.parse.unquote` 收到的参数后再匹配 SLEEP 正则，否则编码后 `SLEEP%283%29` 匹配不到 → 验证假失败。症状：POC 单跑正常、验证脚本里全 FAIL 时，先查 mock 是否 unquote。
7. **验证脚本断言别用宽泛子串**：POC 汇总行固定打印"疑似注入 %d 个"（含"疑似注入"字样），用 `"疑似注入" not in out` 检查"不判注入"会误判 FAIL。用带标记的精确串（如判定行的 `"疑似注入!"`）或检查 `"VULN:"` 行。
8. **URL fragment/query 必须剥干净再当 base（实战假阳性案例 2026-08）**：浏览器 URL 常带 `#/?logintype=1&_key=...` fragment——HTTP 客户端从不发送 fragment，norm_url 不剥时所有探测路径实际全落在 fragment 前的路径（如 `/wui/index.html`，SPA 恒 200）→ dispatch/static.jsp 全误报"存在"（zlq.grassict.cn 案例：POTENTIAL 假阳性，修后真 404）。norm_url 必须：剥 fragment+query+已知 SPA/登录页后缀（`/wui/index.html`、`/login/Login.jsp`、`/index.jsp`）回到 `scheme://host[:port][/context]`；修完用"真 404 vs 假 200"复核。
9. **软 404 服务器骗状态码探测**：部分服务器对缺失路径返回 200+自定义错误页（"您所请求的网页不存在"/404.png 等特征）。status==200 ≠ 资源存在。探测脚本必须抓响应体片段：非 404 记 body 前 ~120 字符；200 时匹配错误页特征，命中按"不存在"处理并注明，不直接报"已被写马/接口存在"。
10. **只读扫描版与写马版分离**（用户明确要求，泛微 0day 实证）：同一漏洞出两个文件——`*_scan.py` 纯只读批量跑影响范围（不读载荷文件、末尾出判定汇总），`*_exploit.py` 写操作单独存（--send 门控+二次确认）。第三方/非最终版载荷从外部文件读（如 value.txt），不写死进代码，后续实时更换不用改代码。
11. **mock 验证只覆盖只读路径**：--send 无法用 mock 验证（mock 要"验证"就得本地反序列化=红线）。只读逻辑（指纹/接口存在性/状态判断）mock 三场景验证；exploit 路径靠代码审查 + 载荷结构校验（base64 合法、魔数 aced0005）+ 授权目标实测。
12. **cmd.exe 的 & 分隔符坑（用户实战撞到 2026-08）**：用户把带 `&` 的完整 URL 不加引号丢进 cmd 跑扫描 → cmd 按 `&` 拆命令，`&time=...` 段撞上 Windows 内置 `time` 命令弹"系统无法接受输入的时间/输入新时间"（`&_key=...` 段报"不是内部或外部命令"）。git-bash 里裸 `&` 是后台执行同样拆段。对策：教用户**只传根地址**（norm_url 会自动剥 fragment/query/登录页后缀），或 URL 加双引号；解释时讲清这是 shell 层的坑不是脚本 bug。
13. **特定载荷的写马路径检查无意义（用户纠正 2026-08）**：影响范围扫描里加"检查 static.jsp 是否被写马"是假信号——那是这份特定载荷的落点，别的攻击者写马不会同名同路径，200/404 都说明不了目标是否被打过。影响范围扫描只关心：是不是目标产品（版本指纹）+ 漏洞入口在不在（接口存在性）。写马验证（--verify 查落点）归 exploit 工具，不归扫描器。
14. **蜜罐/诱饵信号（zlq 目标暴露）**：① Server 头异常（如 `WVS`——非正常中间件名）但页面内容却"很真"（真实产品资源路径/cookie 齐全）= 蜜罐或定制反代，警惕；② 群聊/卖家分享的带参目标链接（`?_key=xxx` 等）诱饵概率高。对策：只读扫描可做（无副作用），但发载荷前必须交叉验证目标真实性（多路径、部署细节自洽性）。
15. **fastjson1/fastjson2 触发路径勿混（fastjson2 FNV 碰撞案例 2026-08）**：fastjson1 CVE-2026-16723 走 `getResourceAsStream` 资源探测（fat-jar LaunchedURLClassLoader 会把 URL 当真）；fastjson2 FNV 碰撞链走 `contextClassLoader.loadClass` 标准类加载（`import static TypeUtils.loadClass` 实锤），jar: URL 必然 CNFE **零回连**。前置条件/探测方法/可用环境是两套，收录分析必须各自源码实锤，fat-jar 前置不可搬用。
16. **碰撞后缀与前缀绑定 + 复用前必校验**：FNV 增量哈希从字符串头逐字符算，URL 前缀一变后缀即失效，换回调服务器必须重搜碰撞（2^48 空间，Go CPU 数小时~CUDA 快）。复用公开 payload 的后缀前先 Python 复算验证（`h = ((h ^ ord(ch)) * 0x100000001b3) % 2**64`，命中白名单哈希 -6293031534589903644 的无符号值 0xa8aaa929446ffce4）——shell heredoc 里别用 `&` 位运算（terminal 拦截报 "uses '&' backgrounding"），用 `% 2**64`。
17. **类加载器/JVM 行为问题 mock 不能替代，必须起真实 JVM 实测**（fastjson2 案例）：Python mock 只能验证触发形态，验证不了类加载器对 jar:/URL 类名的行为。可复用方法: ① 手动拼 Spring Boot fat-jar（Maven 不可用）: spring-boot-loader jar 解压 org/ 进根 + BOOT-INF/classes + BOOT-INF/lib + MANIFEST（Main-Class=org.springframework.boot.loader.JarLauncher, Start-Class=业务类）+ `jar -0cfm`（**嵌套 jar 必须 STORED**，DEFLATED 报 nested jar files must be stored）; ② javac 中文路径 GBK 乱码报"找不到目录"，测试工程放纯 ASCII 路径（%TEMP%\xxx）; ③ curl（Windows 原生）写 MSYS /tmp 的文件 Windows python 读不到，路径用 `cygpath -w /tmp` 对齐; ④ 触发判定用耗时差分: 碰撞 vs 非碰撞后缀解析耗时差（~300ms vs 0ms）= loadClass 被调用的证据，无需改代码加日志。

## 支持文件
- `references/public-poc-search.md` — 各搜索途径 curl 可用性矩阵
- `references/java-deserialization-payload-forensics.md` — Java 反序列化载荷静态取证方法论（gadget 家族识别/CB1 结构/内嵌类与 JSP 提取/生成器溯源/损坏判定/取证自证/传输形态速记与适用版本推断框架）
- TongWeb heimdall/ejbserver 反序列化案例（指纹/链/载荷损坏分析/收录决策）见 commercial-app-pentest 的 `references/tongweb-heimdall-deserialization.md`
- `references/weaver-ecology-verifyformula.md` — 泛微 e-cology verifyFormula 1day 案例（利用链+指纹判定）
- `references/weaver-ecology-dispatch-invoke.md` — 泛微 e-cology /dispatch/invoke 反序列化 0day 操作案例（接口形态/版本指纹查询集/影响范围扫描工作流/蜜罐信号）
- `references/jeesite-default-keys.md` — JeeSite 默认密钥/账号速查
- `references/inspur-inbuilder-product-intel.md` — 浪潮 inBuilder 低代码平台 0day 评估案例（产品情报/值钱度/适用范围/收录前提）
- `references/tongda-oa-appbuilder-setlaunch.md` — 通达OA appbuilder setlaunch 1day 案例（泄漏源码验证路径/入口 base64 编码坑/公开性判定）
- `references/impact-scope-survey.md` — 影响范围调查方法论：0 命中判定四步（随机路径对照/方法变体/WAF 排除/版本细分）、阳性对照需求、样本偏斜识别（同组织子域/ETag 同 Last-Modified 异=正常）
- `references/hande-hzero-ruleengine-0day.md` — 汉得 HZERO rule-engine Groovy RCE 0day 评估案例（商业版独有接口 vs 开源版等价接口、权限注解、认证=决定性未知项）
- `references/fastjson-cve-2026-16723.md` — fastjson 1.2.68~1.2.83 默认配置 RCE 案例（NVD/官方通告取证、URL 类型名根因、fat-jar 前置、回连探测/mock 回连验证法）
- `references/fastjson2-fnv-collision.md` — fastjson2 <=2.0.62 FNV-1a 碰撞 AutoType 绕过案例（长亭通告解读、触发形态矩阵、代理对 JSON 转义坑、类加载器前置实测、碰撞搜索器用法）
- `references/fastjson2-fnv-collision-autotype-bypass.md` — fastjson2 <=2.0.62 FNV-1a 哈希碰撞 AutoType 绕过 RCE 案例（触发形态矩阵/类加载器前置实测: 标准环境零回连/碰撞后缀前缀绑定/手动拼 fat-jar 复现法）
