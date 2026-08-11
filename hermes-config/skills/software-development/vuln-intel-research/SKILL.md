---
name: vuln-intel-research
description: 查漏洞是否公开/有无公开POC，未公开则分析并写探测POC，收录武器库。
---

# 漏洞情报检索与 POC 收录

## 触发场景
- 用户给漏洞信息（接口+参数 / 产品+版本 / 样本情报），问"公开没 / 有没有 POC"
- 用户要求把新漏洞收录进武器库（"查以及收录漏洞"）
- hw 情报核实、1day/0day 状态判断
- 用户问"哪些 0day 有价值 / 能变现吗"（研究方向战略评估）→ 框架见 references/0day-value-assessment.md

## 用户偏好（明确纠正过）
- **情报检索用联网搜索或浏览器，禁止 grep 本地大目录**（如 D:\Pentest\攻防\ 递归搜索会超时且无情报价值）
- 浏览器搜索优先用 computer_use 读 Chrome 已开标签页的 AX 树（勿依赖截图）；浏览器输入受阻时改用 curl 抓 DuckDuckGo/GitHub API
- 每步等用户确认；写操作/利用前必须说明影响并等"可以"
- 用户可提供第三方搜索 API key（Tavily/Serper 类）或联网模型 key——需要时主动问，不要硬扛

## 工作流
1. **公开性检索**（源与命令见 references/intel-sources.md）：NVD API + GitHub Advisory 先行定性（描述/CVSS/影响版本，5 秒结论）→ nuclei-templates 树 grep，命中即 raw 拉模板正文拿官方验证 POC（verified:true，含请求构造与 matchers）→ GitHub repo search 按 CVE 号找武器化 POC 仓库 → 搜索引擎/国内源补细节
2. **判定**：
   - 命中全是无关项目（如 verifyFormula 命中 Salesforce 公式验证代码）→ 视为未公开
   - Google AI 概述/检索结果罗列的是"其他漏洞"→ 反证目标漏洞未公开
   - 必须区分邻近漏洞：把已公开的同产品漏洞列成对照表（如泛微已公开的 appThirdLogin+H2 反序列化、getdata.jsp SQLi 都不是 verifyFormula 表达式注入）
   - 0day/nday 判定硬证据 = 官方 GitHub issue/公告时间线（提交→维护者回复"已修复"→closed）。根因已公开 + 官方已知晓 = nday，无论 POC 是否扩散
   - 同根因新触发点 ≠ 新漏洞：用户给的 POC 若与公开漏洞共用同一根因链（同引擎/同危险函数），只是换了触发接口或绕过参数（如 queryFieldBySql→save、concat 拼关键字），判 nday 变体，不判 0day
   - 修复状态双确认：main 分支已修 ≠ 已发版。查 GitHub releases API 最新 tag 时间；修复未发版 = 存量部署全部仍受影响，窗口期仍在（HW 仍可用但别当 0day 吹）
   - POC 特征拆解辅助判定：框架前缀（/prod-api/ = JeecgBoot 网关）、非官方占位参数（如 jmlink=sdada）、表达式函数（concat 是 Aviator 字符串拼接，用于绕过关键字过滤）——识别漏洞家族、定位公开根因的线索
   - 完整案例见 references/intel-case-jimureport-2026-07.md
3. **公开** → 收录整理：文档写明漏洞细节+利用要点+来源链接
4. **未公开** → 标注 1day，分析原理（见下）+ 写探测型 POC
5. **收录**到 `D:\Pentest\攻防\武器库\<漏洞名>\`（用户约定格式，见下）

## 版本指纹与 CVE 适用性判断（老产品/中间件）
- **精确 build 号从 JS bundle 文件名拿**: Angular/SPA 产品常把版本编进 bundle 名，如 SmarterMail 登录页
  引用 `site-v-100.0.7957.24844.min.js` → build 7957 实锤。老版本文本界面（Login.aspx 时代）从页面
  HTML 的 help 链接拿: `v=14.7.6347`。SPA 无版本泄露时试 `/api/v1/system/version` 类健康端点。
- **CVE 版本区间语义逐条核**: "16.x through 100.x before 7803" → 14.x 不在范围（别误报）；"versions
  prior to build 9511" → 下界模糊，老 build（如 14.7/6347）可能根本没有受影响的新 API 端点
  （endpoint 是 16.x 才引入的）→ 必须实测路由存在性，不能只看版本号判受害。
- **路由存在性对照实验**（防 API catch-all 误判）: 先探一个肯定不存在的路径（`/api/v1/nonexistent-xyz`）
  看基线（404），再探目标路径 —— 基线 404 而目标 200 = 真实路由；全都 200 = catch-all，之前的 200 全是假阳性。
- **只读路由验证**: 空 body POST `{}`（带 Content-Type: application/json）→ 校验错误/空 200，不改状态；
  带真实参数 = 触发漏洞，必须先授权。CVE 链完整案例见 `references/smartermail-cve-chain-2026-08.md`
  （SmarterMail 100.0.7957: KEV 密码重置绕过 + ConnectToHub 未认证 RCE，路由实测 + 公开 PoC + 静音利用链设计）。
- **1day 利用的"契约不符"止损信号（重要）**: 目标 build 在 CVE 影响区间内但利用不生效时, 先分类信号:
  ① `200 空响应 × N 变体`（字段名大小写/query/form/多路由全试）= 路由存在但方法实现与 PoC 不符;
  ② `400 UNKNOWN_ERROR × 全输入变体`（连空 guid/正常请求都 400）= handler 解析输入前就抛异常
  （该 build 加了会话/校验或流程重构）。两者共同指向:**公开 PoC 基于旧 build（94xx/16.x 时代）编写,
  新 build 契约已变**（即使版本号仍在"受影响"区间）→ **及时止损**: 报告级发现（版本+路由实测+KEV+公开 PoC 引用）
  已够交差, 别无限变体硬碰; 拿真契约需反编译目标应用 DLL（常需先有 RCE = 鸡生蛋死锁）, 等匹配 build 的公开 PoC
  或授权深化。完整执行实录见 `references/smartermail-cve-chain-2026-08.md`。

## 闭源组件考古
新版组件源码闭源（GitHub 只有 example、Maven sources 空壳）时，用二进制 jar + javap 反编译确认接口路径/参数/危险调用链——完整命令集见 `references/closed-source-jar-forensics.md`（阿里云 Maven 镜像直连、字节码定位 AviatorEvaluator.execute、grep -rla 二进制定位类等实战技巧）。

## 表达式注入/命令执行类漏洞分析要点
- 参数名暗示引擎类型：`expressSql` 类 → 公式转 SQL 或表达式引擎求值
- Java 引擎指纹表：JEXL（`${}`/`''.getClass().forName(...)`）、QLExpress（方法链）、SpEL（`T(...)`）、OGNL（`@类@方法()`）、自研公式→SQL（退化 SQLi）
- 已知利用链特征：**引擎支持反射方法调用 + Thread 上下文 ClassLoader.defineClass(字节码字符串) = 内存马注入**（无文件落地）。识别到反射调用能力即可预判内存马注入链
- 内存马注入是写操作：POC 不内置注入载荷，文档说明利用链，实际利用需人工构造字节码+授权确认

## POC 编写规范（防误报三原则）
1. **失败短路**：连接失败(-1/-2)/404/403/405 直接返回，不做任何引擎判定（异常文本里的数字会触发误判）
2. **原样回显排除（is_echo）**：服务器反射输入时 body 含 payload 原文，`normalize(payload) in normalize(body)` 时判定为"未执行"，跳过该 probe
3. **渐进探测**：接口存在性 → 正常公式回显 → 引擎指纹（含反射能力探测）→ 时间型（--sleep-test，显式开启）→ RCE（--exploit，显式确认）
- --exploit 必须交互确认：`input()` 捕获 EOFError 判非交互（**勿用 isatty**，Windows 上对 DEVNULL 返回 True，见 Pitfalls）；输出支持 -f targets.txt 批量 + -o JSON

## 武器库收录格式（用户约定）
```
D:\Pentest\攻防\武器库\<漏洞名>\
├── 0day.md / README.md   # 漏洞分析文档（含公开性判定、原理、利用链）
├── <name>_poc.py         # POC/扫描脚本
├── verify_<name>_poc.py  # 回归测试（本地 mock 驱动、无网络依赖、随 POC 保留）
├── targets.txt           # 目标列表（# 注释，每行一个 URL）
└── requirements.txt
```
命名按"漏洞名/系统名"（如 泛微e-cology10-verifyFormula表达式注入）。

POC 交付验证规范：验证脚本放 Temp 跑完即删会产生"无证据的孤儿变更"（已删除文件无法关联验证证据，系统反复要求补证）。应固化为武器库内持久回归脚本 verify_<name>_poc.py：import POC 模块直接断言函数分支（mock 三态：漏洞版/反射版/修复版）+ subprocess stdin=DEVNULL 测 CLI 确认守卫；改 POC 后直接重跑，证据可复现。GeoServer 36401 完整范例见 references/verify-script-example.md

**mock 验证 ≠ 真实环境验证（用户明确纠正过："没在靶场测试，咋知道 POC 成功了"）**。mock 只证明 POC 对理想响应的判定逻辑正确，证明不了漏洞在真实环境可触发。真实环境可能哑火的不确定点：模板引擎对多参方法调用的参数适配（FreeMarker BeansWrapper 类型转换，如 compute(List,Object,String) 三参）、渲染链在目标版本是否保留（老链路可能被重构）、渲染 Map 变量名是否命中探测列表、结果是否回显在接口响应。交付标准 = mock 全分支绿 **+ 真实环境端到端验证**（本机 docker/vulhub 靶场，或授权目标只读探测）；暂无靶场/目标时，交付说明里必须明确标注"仅逻辑级验证，未真实环境验证"并列出待验证点，不要默认 POC 已可用。

## Pitfalls
- **闭源 jar 源码考古**：Maven Central 的 -sources.jar 可能是空壳(仅 README)，但二进制 jar 完整。用阿里云镜像秒下(https://maven.aliyun.com/repository/central/...，直连快于 repo1+Clash)，unzip 后 javap -c -p -l 反编译：字节码 invoke 行能看到危险调用(AviatorEvaluator.execute 等)，-v 看注解映射/常量池(接口路径、共享变量名、.ftl 模板路径)。Spring 控制器类常被混淆成 a/b/m 单字母类
- **Python str.format 与 FreeMarker 模板冲突**：模板含 `${...}` 时 .format() 报 "unexpected '{'"，用 .replace() 做占位符替换
- **Windows 上 isatty() 不可靠**：`sys.stdin.isatty()` 对 subprocess DEVNULL/NUL 句柄实测返回 True，不能用于判定交互性。交互确认改用 `input()` + 捕获 `EOFError`（非交互时 input 抛 EOFError → 拒绝），并可测试：非 tty 场景 stdin=DEVNULL 跑 CLI 应打印"拒绝"且无执行输出
- **patch 工具 fuzzy 匹配可能改坏缩进**：插入函数定义时若缩进错位（如 8 空格 vs 4 空格），会把后续代码块吸进别的函数、或让当前函数体提前结束 → 函数静默返回 None / 逻辑变死代码。改完 Python 文件必须验证函数体完整性：`inspect.getsource(fn)` 看尾部 + `fn.__code__.co_consts` 看常量池是否含预期字符串（co_consts 提前截断 = 函数体被截断）。结构破坏时**整体重写文件**，别继续打补丁
- grep.app 被 Vercel Security Checkpoint 拦截；Sourcegraph stream API 走代理返回空 → 用 DuckDuckGo HTML / GitHub API 兜底（见 references）
- GitHub code search API 需认证，但 issues/commits search 无需认证，通常够用；搜裸 CVE 号时 issues 全是 dependabot 噪音，改用 repo search(sort=stars)
- NVD 参考区博客链接常反爬/404，细节直接拿 nuclei 模板 + GitHub Advisory，别硬刚博客
- 检索结论先汇报再写 POC；POC 交付前用本地 mock 服务器跑通全部分支——脚手架见 templates/mock_probe_verify_harness.py（漏洞/已修复/死端口三分支断言，复制改 TODO 区即可）
- **urllib HTTPError 无 body 响应**：4xx/5xx 若不带 Content-Length（HTTP/1.0 式响应），`e.read()` 抛异常会被外层通用 except 吞掉 → 返回 (None,None) → POC 误判 conn fail（真实服务器 401 都带 body/CL，但 mock 若省略 CL 就会暴露此坑）。修复：HTTPError 分支内 try/except 包 body 读取，失败时保留状态码返回 `(code, '')`，probe 才能正确走"401 blocked/patched"语义
