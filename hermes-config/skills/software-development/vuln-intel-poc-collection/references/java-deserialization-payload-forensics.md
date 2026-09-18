# Java 反序列化载荷静态取证方法论（2026-08 泛微 CB1 / TongWeb 案例沉淀）

目的：**不执行**地识别一份 Java 反序列化攻击载荷——它是什么链、要干什么、谁生成的、能不能用。全程只读字节/解码/反编译，绝不本地 `ObjectInputStream.readObject()`（那是唯一会让本机执行 gadget 链的操作）。

## 1. 先定身份

- 魔数：`AC ED 00 05`（base64 形态 `rO0ABX`）→ 确认是 Java 序列化流
- 顶层对象 ≠ 字符串出现顺序：用偏移定位第一个 `TC_OBJECT(0x73)+TC_CLASSDESC(0x72)+类名长度` 才是真正的入口对象（TongWeb 案例：字符串里 EJBResponse 先出现，但偏移更靠前的 spring `RemoteInvocation` 才是顶层，EJBResponse 嵌套在 arguments[0]）
- 头部填充识别：魔数后接大段**纯单字节**（如 0x79×11 万）＝工具 WAF 绕过/防长度检测的填充，不是损坏。判定方法：统计该段字节种类，只有一种就是填充

## 2. 识别 gadget 家族（看三个特征）

| 特征 | 指向 |
|---|---|
| `PriorityQueue` + `BeanComparator(property="outputProperties")` + `ComparableComparator` + `TemplatesImpl` | **CB1**（ysoserial CommonsBeanutils1） |
| `HashTable` + `TextAndMnemonicHashMap` + `ReadOnlyBinding`（com.tongweb.*） | TongWeb 原生链（TongWeb heimdall 案例） |
| `CaseInsensitiveMap`(com.tongweb.commons.collections.*) + `ReadOnlyBinding` + `ResourceRef` + `BeanFactory` + `ELProcessor` | TongWeb 原生链变体（同一洞另一条链） |

CB1 触发流程（读懂它就能向用户讲"为什么"）：
`PriorityQueue.readObject → heapify/siftDown → comparator.compare → BeanComparator.compare → PropertyUtils.getProperty(obj, "outputProperties") → TemplatesImpl.getOutputProperties → newTransformer → defineClass(_bytecodes) → 恶意 translet 的 static{} 执行`

## 3. 提取内嵌载荷（恶意类/JSP）

- `TemplatesImpl._bytecodes` 是 `[[B` 二维数组：`[0]` = 恶意 translet，`[1]` = 辅助桩类
- 类字节定位：全流搜 `\xca\xfe\xba\xbe`，相邻魔数之间就是类文件；offset 6-8 读 major version（0x33=Java7, 0x31=Java5）可判生成环境
- translet 的 `<clinit>` 字符串即意图：`FileOutputStream`+`/xxx.jsp`+`BASE64Decoder` = 写 JSP webshell 型；`Runtime`/`ProcessBuilder` = 命令执行型；`Thread.sleep` = 时间型检测类
- JSP 内容常在常量池里是 base64：`re.findall(rb'[A-Za-z0-9+/]{40,}={0,2}', raw)` 后逐个 `b64decode(validate=True)`，命中 `<%`/`jsp` 就是 webshell 源码
- **webroot 推导技巧（泛微案例）**：defineClass 加载的类没有 CodeSource，恶意 translet 借第三方库类定位 webapp 根——`Class.forName("com.fasterxml.jackson.databind.node.POJONode").getProtectionDomain().getCodeSource().getLocation().getPath()`（webapp 的 lib 类必有 CodeSource），再 `substring(0, indexOf("WEB-INF"))` 截出 `{webroot}`，拼 `/static/static.jsp` 等相对路径写马；os.name 含 windows 时去首斜杠。javap -c 还原 `<clinit>` 即得完整路径逻辑
- **JDK 版本硬约束从类引用推**：出现 `sun.misc.BASE64Decoder` = 目标 JDK 必须 ≤8（JDK9+ 该类删除，写文件静默失败）；translet 字节码 major version（0x33=Java7）只约束生成环境，不约束目标

## 4. 生成器溯源（判断公开/定制）

- 桩类名：原版 ysoserial = `Gadgets$StubTransletPayload`；定制 fork 常见改名（案例：`Gadgets1$Foo`）+ 随机类名后缀（案例：`tmp.Out51pw` 里的 `51pw`）
- JSP 源码全文 `\uXXXX` 转义（写盘编译时才还原）= WAF/特征绕过设计，也是生成器特征
- 硬编码 AES 密钥 + 自定义 ClassLoader + `request.getReader().readLine()` 解密 defineClass = 内存马加载器 JSP 模式（密钥/格式即指纹）

## 5. 损坏判定（能不能用，必须实测）

- **严格 base64 校验**：`base64.b64decode(s, validate=True)` 抛错 = 载荷流传中损坏。宽松解码（默认跳过非法字符）会静默产出错误字节 → 误判可用
- 内嵌类损坏的实证：把提取的类字节喂给本地 JDK `defineClass`（写临时 Java 程序，仅此一步，不反序列化整条流）→ `ClassFormatError` = 类加载失败，静态块/构造器**零执行**（"零执行"的证据链就是这个）
- 损坏后果分级：
  - 链完整 + 类损坏 = 只能当"链触发"证据（目标处理了流→异常响应≠404），不能做时间型检测/完整 RCE
  - 链完整 + 类完好 = 时间型检测（sleep 类）或完整利用可用
- 修复前提：损坏字节是**丢失**不是错位时不可恢复（原始字符未知），需按公开链重新生成序列化流（需要目标产品的 jar 写生成器）

## 6. "没执行过"的取证式自证（用户要求时）

1. 全部命令清单（对话记录即完整日志，逐条列）
2. 独立痕迹：`ps`/`tasklist` 进程、`netstat` 外连（自己只走代理）、磁盘产物+时间戳、`sha256sum` 哈希留存供复验
3. 主动披露疏漏（mock 进程残留、机器上已有相关依赖 jar）——用户会自己发现，不如先说
4. 边界说明：terminal 直接跑在用户本机（git-bash），不是沙箱/VM；execute_code 的沙箱不用（缺依赖）；完整利用链验证才需要隔离环境

## 7. 用户红线（处理第三方载荷时）

- 禁本地反序列化；禁对 mock 发 --send；被否决的命令不重试不换法绕过
- 先解读再收录：逐段大白话讲清，用户确认安全才继续
- 0day/敏感载荷数据严禁外传：不上传、不拿载荷内容搜索、不入公共渠道；查公开性只查接口名/类名

## 8. 载荷传输形态速记 + 适用版本推断框架

**传输形态（载荷怎么进接口，泛微 /dispatch/invoke 案例）**：
- 形态：`POST /dispatch/invoke/{类名}/{方法名}` + JSON body，`options._SYS_ARGS.class="[B"` + `value=<base64(序列化流)>`（魔数 rO0ABX 可直接校验）
- 机关：声明调无害静态方法（如 `java.lang.String/copyValueOf` 作"过桥"），实际触发点是 `_SYS_ARGS` 值的反序列化——**"声明调 String、实际传 [B" 的类型错配就是漏洞点**，链在框架 readObject 那一刻触发
- 同类接口形态：`/dispatch/invoke/...` 属于"远程调用分发"组件，测绘时先按产品指纹圈资产、再批量只读 POST 空值探接口（非 404=活着），鹰图/FOFA 语法：`web.header="ecology_JSessionid"` / `web.body="/wui/index.html"` / `app="泛微-ecology"`

**适用版本推断（用户问"能打什么版本"时的正确姿势——不空口断版本表）**：
1. 从载荷硬约束推下限/上限：JDK 版本（依赖类是否还在，如 BASE64Decoder→≤8）、classpath 依赖（commons-*/jackson 等是否目标标配）、目录布局（`indexOf("WEB-INF")` 找不到即异常）、可写目录
2. 结论只能是"大概率/待实测"：给判定流程而不是版本号清单——版本指纹（登录页/静态资源/特征接口，如 e-cology 8 的 `/login/Login.jsp` vs 9/10 的 `/wui/index.html`）+ 接口存在性（空参 POST 非 404）+ 依赖假设交叉验证
3. 版本线常识只作背景：新版本线（如 e-cology 10）可能换 JDK/删老依赖，老版本线（8/9）典型部署大概率满足——但每个目标必须实测
