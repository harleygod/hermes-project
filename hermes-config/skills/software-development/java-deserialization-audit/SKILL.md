---
name: java-deserialization-audit
description: "Use when auditing Java deser defenses (hessian/whitelist)."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, deserialization, hessian, gadget, whitelist, java, lab-verification]
    category: software-development
---

# Java 反序列化防御审计（白名单 / gadget 面）

静态提假设、靶机定生死、结论不夸大。

## 何时用

- 目标有 Java 反序列化入口：hessian / Java 原生 `ObjectInputStream` / Jackson default typing / fastjson autotype / XStream
- 目标是**框架自带白名单**（如自研 `CustomSerializerFactory`）或部署了 RASP，需要判断**能不能绕**
- 报告里要给出可信结论："公开 PoC 适不适用"、"到底能不能 RCE"

## 铁律

1. **静态只提假设，靶机定生死。** 白名单分支、字节码、公开 gadget 只能给你"可能"。最终结论必须本地靶机实测，且必须用**目标的同版本库 + 真实白名单源码**。
2. **不夸大成 RCE。** 能加载类 ≠ 能实例化；能实例化 ≠ 有可达 gadget。没有可达链就如实写"机制成立、未见可利用链"。
3. **只出能拿权限/信息的结论**，不写修复建议（用户审计标准）。
4. **结论落盘**：每条带 `FILE:LINE` + 靶机证据文件名，不要只留在对话里。

---

## Step 0 — 静态侦察（先定位三件事）

```bash
# 1) 找序列化实现与白名单
grep -rn "setWhitelist\|SerializerFactory\|CustomSerializerFactory" --include="*.java" . | head
# 2) 找反序列化入口
grep -rn "readObject()\|Hessian2Input\|ObjectInputStream\|readValue(" --include="*.java" .
# 3) 入口的鉴权（是否预认证）
grep -rn "@WebFilter\|urlPatterns=\|Filter" --include="*.java" . | head -20
```

用 `javap` 直接看字节码（比反编译源码更权威，能看清常量与分支）：

```bash
javap -p -c -cp <hessian.jar> com.caucho.hessian.io.ClassDeserializer | grep -B 14 -A 4 "forName"
```

## Step 1 — 白名单的三个致命检查点

这三处决定"能不能绕"，逐个确认，不要凭经验猜：

| # | 检查点 | 关键问法 | 一次实战结论 |
|---|---|---|---|
| 1 | **未白名单类 → 拒绝还是降级？** | `ClassFactory.load()` 返回什么 | hessian 返回 `HashMap.class` = **静默降级**，顶层公开 gadget 全废 |
| 2 | **`getDeserializer(Class)` 重载查不查白名单** | 字段的**声明类型**走哪条路 | **不查** → 白名单类的"非白名单类型字段"可被真实例化 ⚠️ |
| 3 | **`Class.forName(name, initialize, loader)` 的 initialize** | 字节码里是 `iconst_0` 还是 `iconst_1` | `iconst_0` = **false** → 加载不初始化，**static 块不触发** |

> 第 2 点是这类防御最常见的真漏洞面。用"白名单类做载体 + 字段声明为非白名单类型"即可绕过；顺手扫全库统计这种字段有多少种（某产品实测 **408 种**，TOP 为 `ApplicationContext` / fastjson `JSONObject` / `RedisTemplate` / `RabbitAdmin`）。

其他高频分支：

- **JDK 集合类**（`PriorityQueue` / `TreeMap` / `SynchronousQueue`）走内置 deserializer，**绕过白名单被真实例化**，且反序列化时会触发元素的 `compareTo` / `hashCode` → 天然 gadget 触发入口（元素可用白名单内的 Comparable 类）。
- **不可序列化的字段类型**（如 `java.lang.reflect.Method`）在**生成端**就报 `must implement java.io.Serializable` → 依赖该字段的链（如 job handler 的 `method.invoke`）直接是死路，别再花时间。
- **裁剪残留死代码**：框架里留着 `GroovyClassLoader.parseClass(codeSource)` 之类能力，但全库 `loadNewInstance()` **零调用点** → 不可达，如实排除。

## Step 2 — 搭靶机（关键步骤）

目标：用**目标的真实白名单实现 + 同版本库**，在可控 JVM 里复现服务端反序列化。

```bash
LAB=<审计目录>/hessian_lab
mkdir -p $LAB/{lib,src,out,payloads}

# 1) 拷目标的真实源码（从源码包里取，不要自己重写等价物）
cp <src>/com/xxx/rpc/serialize/impl/CustomSerializerFactory.java $LAB/src/.../
cp <src>/com/xxx/rpc/serialize/impl/HessianSerializer.java        $LAB/src/.../
# 2) 拷同版本 jar（从目标环境里取的）
cp extracted/hessian-4.0.63.jar $LAB/lib/
cp ~/.m2/repository/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar $LAB/lib/

# 3) 编译（-cp 用 lib/* 避免分号被 MSYS 转换；java 运行时 Windows 用 'out;lib/*'）
javac -encoding UTF-8 -cp 'lib/*' -d out $(find src -name "*.java")
```

靶机三件套（模板见 `templates/HessianLab.java`）：

1. **探针类**：static 块写标记文件，内容带 `System.getProperty("probe.tag")` —— 区分"生成端触发"还是"靶机端触发"（否则会自欺）。
2. **载体类**：包名要落在目标白名单内（如 `com.dahua.evo.audit.*`），字段刻意复刻真实危险字段（`Class` / `Method` / 非白名单类型）。
3. **gen / read 双模式**：gen 用默认 `SerializerFactory` 打 payload（生成端不查白名单），read 用目标白名单 `setSerializerFactory(new CustomSerializerFactory())` 读。

```bash
java -Dprobe.tag=GEN -cp 'out;lib/*' audit.Lab gen
java -Dprobe.tag=LAB -cp 'out;lib/*' audit.Lab read
```

## Step 3 — 测试矩阵（缺一不可，必须含对照组）

| 组 | payload | 要回答的问题 |
|---|---|---|
| 对照 | 非白名单普通 POJO（非集合） | 白名单到底拦不拦？ |
| 对照 | 标准 gadget（`JdbcRowSetImpl` / `TemplatesImpl`） | 公开链是否失效？ |
| A | `Class` 对象（值 = 非白名单类名） | 能否任意类加载？static 副作用有没有？ |
| B | 载体类的 **`Class`/`Method` 字段** | "危险字段类型"假设是否成立？ |
| C | 载体类 + **非白名单类型的普通字段** | **字段声明类型绕过**（一般这就是突破口） |
| D | JDK 集合（`PriorityQueue`/`TreeMap` + 白名单内 Comparable） | 反序列化副作用（compareTo/hashCode）能否触发？ |
| E | 白名单里的 `Collections$*` 包装类 | 能否当容器传导恶意对象？ |

## Step 4 — 判定与收敛

- 每条结论必须能指向**靶机输出行**（`readObject() 返回: <类名>` / `[SIDE-EFFECT] ...`）
- 有绕过 ≠ 有 RCE。收尾明确写："入口预认证 + 绕过面成立，但 classpath 上未见可达 gadget，RCE 未证实"
- 与代码审计主流程配合：审计 skill 负责广度（入口 / 鉴权 / 危险方法清单），本 skill 负责把反序列化这一条线**判死或判活**

---

## 已知结论：hessian + CustomSerializerFactory 型白名单

逐条实测证据见 `references/hessian-whitelist-empirical.md`。速查：

| 场景 | 结果 |
|---|---|
| 顶层非白名单类（含公开 gadget） | 降级为 `java.util.HashMap`，不实例化 |
| 自定义非白名单 Map/List（顶层） | 降级 / 抛 `UnsupportedOperationException` |
| `Class` 对象（任意类名） | 加载成功，但 `initialize=false`，**static 块不触发** |
| `Method` 字段 | 生成端即失败（非 Serializable） |
| **载体类 + 非白名单类型字段** | **真实例化 + `readResolve` 被调用** ⚠️ |
| JDK 集合（PriorityQueue/TreeMap） | 真实例化 + 元素 `compareTo` 被调用 ⚠️ |

## 工具坑（踩过的，别再踩）

- **嵌套命令替换 / 转义花括号**：`$(grep ...)` 套在引号里、或正则写成 `\{0,600\}`，会被终端命令解析器 hardline 拦下（不可重试）。拆成简单命令，或改用 `read_file` / `search_files`。
- **git-bash 传路径给 Windows 程序**（`python`/`java`/`javac`）：`/c/...` 会被 MSYS 改成 `D:\c\...` → 报 `No such file`。用**原生反斜杠**并用单引号包裹：`python 'C:\Users\u\x.py'`。
- **非 ASCII 路径 + 搜索**：`search_files`/ripgrep 对中文路径可能报 `IO error ... 系统找不到指定的路径` → 退回 `terminal` 里的 `grep -r`，或写 python 脚本扫。
- **`rm -rf`**：出现在复合命令里会触发审批、可能超时被拒；**被拒后不要重试、不要换写法绕**，改用不删除的流程（写到新目录）。

## 协作坑：多 Agent 并行审计的结果保全

- 子 agent 的批量结果**可能丢失**（返回 `Delegation owner exited before recording a terminal result; outcome unknown`）。
- 恢复路径①：实时日志是 append-only 的 —— `~/AppData/Local/hermes/cache/delegation/live/<delegation_id>/task-N.log`（注意行内长输出会被截断到 ~400 字符，用 `read_file` 能多看一点）。
- 恢复路径②（更可靠）：**子 agent 留在磁盘上的产物** —— 直接重跑它编译好的靶机 / payload / 脚本，拿完整结果。所以派活时就要要求它**把靶机、payload、脚本落盘**，不要只在 stdout 里给结论。

## 支持文件

- `references/hessian-whitelist-empirical.md` — 双靶机 21 组实测结果、源码行号、408 种字段类型分布
- `templates/HessianLab.java` — gen/read 双模式靶机模板（探针类 + 载体类 + 测试矩阵骨架），复制改包名即可用
