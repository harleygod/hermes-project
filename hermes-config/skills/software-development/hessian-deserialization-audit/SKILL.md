---
name: hessian-deserialization-audit
description: Use when 审计 hessian/burlap 反序列化漏洞：白名单机制、4个触发点、gadget链、绕过。
---

# Hessian 反序列化审计

针对 caucho hessian 库（RPC 序列化，入口 `Hessian2Input.readObject()`）的反序列化漏洞审计。**hessian 不是 Java 原生反序列化**，触发点完全不同，Java 原生 readObject 链在这里全部失效。

## 触发条件
- 目标用 hessian/burlap 做 RPC 序列化，反序列化入口是 `Hessian2Input.readObject()` 或自定义 Serializer 的 `deserialize()`
- 要找白名单内的 RCE gadget，或白名单绕过
- 判断 hessian 反序列化能否利用（gadget 类是否在白名单内）

## 核心机制：hessian 白名单（ClassFactory）

hessian-4.0.x 反序列化时类加载走 `ClassFactory.load(className)`：

```java
public Class<?> load(String className) {
    if (this.isAllow(className)) return Class.forName(className, false, _loader);
    return HashMap.class;   // ★ 不在白名单的类静默替换成 HashMap（不抛异常）
}
```

`isAllow` 检查顺序：自定义 `_allowList` → 静态 `_staticAllowList` → 否则返回 `!_isWhitelist`。

**静态白名单**（hessian 内置，即使不设自定义白名单也生效）：
- allow `java\..+`（所有 java.*）
- allow `javax\.management\..+`（只 javax.management，注意 javax.swing/activation/naming 都不在）
- deny `java.lang.Runtime / Process / System / Thread`（**黑名单只有这 4 个，严重不完整**，java.net.URL、反射、Proxy 都没拦）

调用链：`Hessian2Input.readObject` → 类型标签 → `SerializerFactory.getObjectDeserializer(type)` → `getDeserializer(String)` → `loadSerializedClass(type)` → `ClassFactory.load`。`_staticTypeMap`（"object"、HessianRemote 等极少数类型）直接返回 Deserializer，绕过白名单。

**关键结论**：白名单外的类静默替换成 HashMap（不报错），gadget 链在反序列化第一步就断。所以**先确认 gadget 类在白名单内，再花力气构造 payload**。

### 机制层面的绕过点（hessian-4.0.63 白盒实测，CFR 反编译）

- **`getDeserializer(Class)` 重载不查白名单**：`Hessian2Input.readObject(Class cl)` 里 `case 'H'`(72 无类型 Map) 与末尾 fallback 直接 `getDeserializer(cl)`；`getObjectDeserializer(type, cl)` / `getListDeserializer(type, cl)` 在类型不匹配时也 fallback 到 `getDeserializer(cl)`。但 `cl` 是目标类编译时写死的**字段声明类型**，攻击者无法直接注入任意 Class —— 只有当某个白名单内类声明了"危险非白名单类型"的字段时才可利用（审计自定义白名单如 com.dahua.evo.* 时的重点）。
- **`java.lang.ProcessBuilder` 不在黑名单 → 放行**（deny 只有 Runtime/Process/System/Thread 4 个）。UnsafeDeserializer(JDK8 默认启用) 用 `Unsafe.allocateInstance` 免构造器实例化，可完整构造 command 字段；但反序列化本身不调 `start()`，缺触发点。
- **`java.lang.Class` 放行 → `ClassDeserializer` 里 `Class.forName(name, false, loader)`**：`false` 不执行静态初始化器，故加载任意类不会触发静态块 RCE，只能当"类加载原语"喂给别的 gadget。
- **deny 用 `Pattern.matches()` 全串匹配**：`java.lang.Runtime` 精确 deny，但 `java.lang.Runtime$1`、`java.lang.RuntimeXX` 等内部类/同前缀类**不**被 deny（落回 `java\..+` 放行）。
- **`_staticTypeMap` 全表无危险类**（void/boolean/byte/short/int/long/float/double/char/string/date/原始数组 + `object`→JavaDeserializer(Object.class) + HessianRemote→RemoteDeserializer），静态表命中虽绕过 load() 但都无害，不能借此 RCE。
- **★ 决定「哪些类真能被实例化」的是静态白名单 `java\..+`，与类实现了什么接口无关（本地靶机实测，本次曾误判）**：自定义白名单（如 `com.dahua.evo.*`）之外，静态白名单 `java\..+` 仍放行**全部 `java.*` 类**。同一靶机三组对照：
  - `java.util.concurrent.SynchronousQueue`（`java.*`）→ **真实例化**，`readObject()` 返回 `SynchronousQueue`
  - `audit.PlainBean`（非 `java.*`、非白名单）→ **降级**，返回 `java.util.HashMap{num=1, name=plain}`
  - `com.sun.rowset.JdbcRowSetImpl`（`com.sun.*`，教科书 JNDI gadget）→ **降级**，返回 `java.util.HashMap`
  ⚠️ **别把第 1 组误读成「Collection/Map 实现类走内置 deserializer 绕过白名单」**——本次实战正是据它推出「唯一缺口」并报给了用户，补做第 2/3 组对照后才定位真因是 `java\..+` 放行。两条实际含义：(a) 可实例化集合 = 白名单内厂商包 + `java.*` + `javax.management.*`；**`com.sun.*` 与第三方 gadget（JdbcRowSetImpl / TemplatesImpl / CB·CC·Spring 系列）全被降级，标准链打不通**；(b) 设计对照实验时**反证组必须选「既不在 `java.*` 也不在自定义白名单」的类**。
- **`ClassDeserializer` 的 `_loader` 在真实部署里恒非 null**：字节码有两条分支 `Class.forName(name, false, _loader)`（`_loader!=null`）与 `Class.forName(name)`（`_loader==null`，initialize=true）。但 `new SerializerFactory()` = `this(Thread.currentThread().getContextClassLoader())` → **实际固走 `false` 分支，加载任意类都不触发静态块**（static 块探针靶机实测无命中）。别把 `_loader==null` 那条当可用路径耗时间。
- **`Method` 字段路线实测判死（不再是「大概率」）**：`java.lang.reflect.Method` 不实现 `Serializable`，hessian **生成端即抛** `RuntimeException: Serialized class java.lang.reflect.Method must implement java.io.Serializable`（报错带字段名与宿主类）。攻击者连 payload 都构不出来 → `MethodJobHandler.execute()` 的 `method.invoke(target,param)` 无法经反序列化注入，不必再投入。
- **白名单内类的 `Class` 字段确实可承载非白名单类名（实测成立，但无 RCE 收益）**：靶机反序列化 `EvoHolder{clazz=audit.ProbeStatic}` 成功，字段被赋成非白名单包内的类 → 证实「`getDeserializer(Class)` 不查白名单」这个结构性入口真实存在。因 `initialize=false` 它只等于**类加载原语**：价值在**类加载探测**（探目标 classpath 有哪些类）或喂给后续会 `newInstance()/getMethod().invoke()` 的业务代码，自身不触发静态块。
- **★ 该绕过的真正确认形态：「字段声明类型」通道（第二轮靶机实测成立，比 `Class` 字段强得多）**：白名单只按**类名**拦顶层类型，但 hessian 给**字段**选反序列化器时走 `getDeserializer(字段的声明类型)`，**不查白名单**。实测（`hessian_lab2`，15 组）：
  - `EvoHolderBean{ b: NotAllowedBean }`（厂商白名单类的字段，声明类型 = 非白名单 bean）→ 反序列化后 `field b -> audit.NotAllowedBean val=NotAllowedBean(cmd=whoami,num=1)`：**字段值被真实例化，且 `readResolve` 被调用**（探针打出 `[SIDE-EFFECT] NotAllowedBean.readResolve`）
  - `EvoHolderMap{ m: NotAllowedMapResolve }` / `EvoHolderList{ l: NotAllowedList }` → 非白名单 Map/List 实现类型同样被**真实例化**
  → 结论：**绕过取决于「字段的声明类型」，与类实现了什么接口无关**（此前「Collection 实现类走内置 deserializer」的解释是错的，那条实为静态白名单 `java\..+` 放行，见上文）。
  → 因此审计动作是**枚举厂商白名单类的非白名单字段类型**，而不是枚举集合类。实测某产品 43,324 个 .java 里这类字段类型 **408 种**，TOP：`org.springframework.context.ApplicationContext` 564 处、`com.alibaba.fastjson.JSONObject` 509、`org.springframework.amqp.rabbit.core.RabbitAdmin` 199、`org.springframework.data.redis.core.RedisTemplate` 134、`org.springframework.http.HttpHeaders` 119。**枚举时必须按 import 解析简单名**（反编译代码用简单类名；不解析会得到 0 结果的假阴性）。
  → 升级为 RCE 还需这些类型里存在「实例化 / readResolve 即做危险事」的 gadget；厂商包与 `java.*` 之外的第三方类型（spring/fastjson 等）若 classpath 版本合适就是这条路的出口。
  完整 15 组矩阵 + 枚举脚本要点 + 复现命令见 references/hessian-field-declared-type-bypass.md
- **JDK 集合的 compareTo/hashCode 是「读侧真实触发」的可用通道（实测确认）**：`control_priorityqueue_compareto` → 反序列化返回 `PriorityQueue [EvoComparable(1), EvoComparable(5)]` 且**服务端**打出 `[SIDE-EFFECT] EvoComparable.compareTo`；`TreeMap` 同理。元素类型可用**白名单内的厂商类**，所以这是「白名单内 Comparable/Comparator 里若调用了可控对象的危险方法」就能成链的入口——审计时别只扫触发点方法本身，要扫厂商 Comparable 的 `compareTo`。

靶机布局/复现命令/六组实测矩阵/未完成线索见 references/dahua-evowpms-hessian-lab.md

完整机制（`_staticTypeMap` 全表、readObject 全标签→load() 映射、getDeserializer(String) 全流程）见 references/hessian-4.0.63-whitelist-mechanism.md

## 触发点（hessian 不走 readObject，也不走 setter）

hessian 反序列化实际只触发这几个点，`TemplatesImpl`、`BadAttributeValueExpException.readObject` 等 Java 原生链全不适用：
1. **字段 setter —— ❌ hessian-4.0.63 不调 setter**：`FieldDeserializer2Factory.create(Field)` 只按字段类型生成 String/Byte/…/Object 反序列化器；`ObjectFieldDeserializer.deserialize()` 是 `in.readObject(field.getType())` + `field.set(obj,value)`（反射直写，JDK8 下走 `FieldDeserializer2FactoryUnsafe` 的 `Unsafe.putObject`）。全程无 `getMethod/getDeclaredMethod` setter 查找，`SerializerFactory.getDeserializer(Class)` 只走 JavaDeserializer/UnsafeDeserializer/EnumDeserializer，不用 BeanDeserializer。**危险 setter 不是 gadget——别把 Fastjson 的 setter 触发思路套到 hessian**（白盒反汇编证据见 references/hessian4-setter-and-scan-methodology.md）
2. **readResolve()**：`JavaDeserializer.getReadResolve` + `UnsafeDeserializer.resolve` 调用无参 readResolve
3. **Map 的 hashCode/equals**：`MapDeserializer.readMap` 里 `map.put(k,v)` → `k.hashCode()/equals()`
4. **TreeMap/PriorityQueue 的 compareTo/Comparator**：反序列化时堆排序调 `Comparator.compare()`
5. **（弱）构造器**：`JavaDeserializer.instantiate()` 若 `_constructor!=null` 则 `newInstance(_constructorArgs)`，参数由 `getParamArg` 填充（primitive→0/false、对象→null，**非攻击者可控**）；否则 `Class.newInstance()` 无参构造。JDK8 Unsafe 启用时直接 `Unsafe.allocateInstance` 免构造器。→ 构造器副作用可被触发但入参全 null/0，别指望传命令进去

## 审计流程

1. 定位反序列化入口：grep 目标代码 `Hessian2Input` / `readObject` / `SerializerFactory` / 自定义 Serializer。反序列化入口常藏在 **RPC 服务端**（如 `NettyHttpServerHandler.process()` 里 `deserialize(body, XxxRequest.class)` 零鉴权反序列化 body），且可能通过 **nginx 动态代理从外部 SSRF 触发**（`proxy_pass http://$arg_xxx` 参数控转发目标 + `rewrite` 去前缀 + body 原样透传）——端口用 `ss -tlnp` 找进程→端口映射（注意执行点可能在 RPC 端口而非业务 HTTP 端口）
2. 确认 SerializerFactory 类型：自定义（有白名单）还是默认（无白名单）。**先把「序列化器变体」全列出来再下结论**：`ls`/grep `*Serializer.java`，对每个无白名单变体做引用计数（`grep -rn "<名>.class\|new <名>("`）——0 引用 = 死代码，不构成绕过路径。**自定义工厂必须 `javap -p` 看方法列表**——大华 `CustomSerializerFactory` 声明了 `acceptClassNames`/`firstDeserializer` 字段却**没重写 `getDeserializer`**（死字段），实际白名单就是构造器里 `ClassFactory.allow()` 设的那些，无额外过滤/绕过逻辑。别被字段声明误导以为有第二层白名单
3. 反编译 `ClassFactory` 确认白名单/黑名单内容（静态 + 自定义两层）
4. 枚举白名单内类，找 4 个触发点上的危险操作（setter/readResolve/hashCode/equals/compareTo 里调 Runtime.exec/JNDI/类加载/URL 连接）
5. 白名单内 JDK 类：grep rt.jar 找 readResolve 类（见 references/jdk-readresolve-classes.md）

## 已知 gadget 速查

- **SwingLazyValue + UIDefaults + MimeTypeParameterList**：JDK-only 链，`UIDefaults.get → LazyValue.createValue → 反射 Runtime.exec`。但类在 sun.swing/javax.swing/javax.activation，**只有静态白名单放行这些包时可用**（hessian-4.0.63 默认不放行，链断）。
- **java.net.URL**：白名单内（java.*）。readResolve 重建 URL；`HashMap.put` 触发 `URL.hashCode → DNS 查询`（DNS 外带，配合出网 DNS 53 可做"反序列化已触发"的验证 POC，非 RCE）。
- **javax.management.loading.MLet**：URLClassLoader 但实现 Externalizable，`readExternal` 抛 UnsupportedOperationException，hessian 反序列化**不可用**。
- **javax.management 全包（含 loading/remote/openmbean/modelmbean/monitor/relation）**：已完整审计，**无可利用 RCE gadget**。BadAttributeValueExpException 的 toString 仅在原生 readObject/构造函数触发（hessian 走 Unsafe+反射直接写 val 字段，不触发）；MLet/PrivateMLet readExternal 抛异常；RMIConnector 的 JNDI 仅在 readObject（hessian 不调）；全包 7 个 readResolve 全无害（返回单例/校验）；所有 hashCode/equals/compareTo/setter 都是字段级赋值或比较。逐类结论 + javap 批量扫描命令见 references/javax-management-audit.md
- **JDK readResolve 类（约 27 个）**：java.net.URL/InetAddress、java.lang.invoke.MethodType/SerializedLambda、java.awt.*、javax.management.openmbean.* 等，多为返回单例/重建对象，需逐个审计是否有危险操作。

## 本地验证技巧

- CFR 反编译：中文路径用 Windows 原生反斜杠 `java -jar "D:\Pentest\反编译工具\...\cfr-0.151.jar" xxx.class`（`/d/` 格式会被 MSYS 转义坏）
- `javap -p -c` 看字节码（`-p` 显示 private；readResolve 常是 private，javap 默认不显示）
- 找 readResolve 类：python zipfile 遍历 rt.jar，`if b'readResolve' in data`
- **javap 批量扫触发点**（`-p` 显示 private，readResolve 常是 private）：遍历 rt.jar 目标包所有类，分别 grep `readResolve|readExternal`、`compareTo|hashCode\(\)|boolean equals`（**不再 grep setter——hessian 不调 setter**）；再用 `javap -c -p` 字节码层 grep 危险 sink（`javax/naming|ProcessBuilder|doLookup|InitialContext|addURL|loadClass|Class\.forName|newInstance|defineClass`）定位调用是否落在触发点方法里。完整命令见 references/javax-management-audit.md
- **大规模 .class 批量 javap 提速 + Windows/MSYS 路径坑**：逐 class 起子进程会超时，用 `find > allclasses.txt` + `xargs -n 150 javap -p`（先只出签名）+ `xargs -n 80 javap -p -c`（每批单次 JVM 启动）；危险字符串先 `grep -rla` 扫 .class 常量池 triage。Python 里 `os.walk`/`subprocess` 用原生 `D:\...` 路径（MSYS `/d/` 会 0 结果）、`/tmp`=`C:\Users\<user>\AppData\Local\Temp`（`cygpath -w /tmp`）。详见 references/hessian4-setter-and-scan-methodology.md
- 找 java.home：`java -XshowSettings:properties -version`；rt.jar 在 `$JAVA_HOME/jre/lib/rt.jar`
- 本地测链：hessian jar + JDK 写 Java，`Hessian2Output.writeObject` → `Hessian2Input.readObject`
- 反编译关键类：ClassFactory、SerializerFactory（getDeserializer/loadSerializedClass/_staticTypeMap）、JavaDeserializer（getReadResolve）、MapDeserializer（readMap）、Hessian2Input（readObject 类型标签 switch）

## 判定「链能不能通」的五步框架（按序做，任一步为 0 即链不成立）

1. **触发面**：hessian 只有 4 个触发点（readResolve / hashCode / equals / compareTo·compare）。原生 `readObject` 链、setter 链、构造器副作用**全部无效**（JDK8 下 Unsafe 免构造器）。先看候选 gadget 靠什么触发——靠 readObject/setter 的直接划掉（**公开 gadget 99% 死在这一步**）
2. **白名单内类的触发点**：对自定义 allow 包 + `java.*` + `javax.management.*` 的所有类，取触发点方法体 grep 精确 sink。**跨类调用必须展开**（只做同类 1-hop 会漏 `ShellUtils.exec()` 这种跨类 sink；但要注意展开后的调用目标大多是 getter → 说明还是 Lombok 样板）。产出 0 时基本可定论
3. **字段类型通道**（唯一能实例化白名单外类的路）：`ObjectFieldDeserializer.deserialize()` = `in.readObject(field.getType())` → 类型不匹配 fallback `getDeserializer(cl)`，**该路径不查白名单**。靶机实测：白名单载体的字段类型=非白名单类 → **真实例化且 readResolve 被调用**；同一类的**顶层**对象则被降级成 HashMap。→ 所以「白名单类有没有声明危险类的字段」是能否实例化的唯一判据
4. **目标 classpath 上有没有 gadget 类**：把部署包 jar 全解出来，遍历 57079 个 class 的常量池找 `readResolve` / 危险字符串（Python zipfile + `b'xxx' in data`，1-2 分钟；比 xargs javap 快一个数量级，用于 triage 后再 javap -p -c 精查）。**classpath 上没有 gadget 类 = 链不可能存在**（大华实测无 CC/CB/c3p0/fastjson/xstream/groovy）
5. **运行时拦截**：先看 classpath 有没有 RASP（`com.baidu.openrasp`、`com.fuxi.javaagent`、`com.xx.rasp`）——有则 `Runtime.exec`/原生反序列化会被 hook，可用性再打折

**误报三件套（一定先滤掉再报结论）**：
1. Lombok 样板 equals/hashCode（特征 `result = result * 59 +`、`$x = this.getX()`、调用目标全是 getXxx/getClass）
2. 类名/方法名撞 sink 词（`DataSourceDTO` 命中 `DataSource`、业务 `getMethod()` getter 命中反射 `getMethod`）
3. 工具类的 static 方法（hessian 反序列化**从不调用 static 方法**。如 `DateUtil.compareDate*` 方法体外的 `Runtime.exec` 与链无关——triage 会因方法名含 compare 命中，必须 javap 确认 sink 落在哪个方法）

**判链铁律**：字段类型通道存在 ≠ 可利用。必须「字段类型 = 危险类」**且**「该类在它自己的触发点方法上有危险操作」两条同时成立，缺一不可。

## Pitfalls

- **判断目标 classpath 上「有哪些库」时，绝不能只数部署包里的 jar（本 Skill 犯过这个错）**：厂商给的"代码包"常常**不含运行依赖**——大华 739 jar 里连 Spring 核心 / Tomcat / MyBatis / hessian 本体都没有，照它统计会得出"classpath 上没有 CC/CB/fastjson/xstream/groovy"的**错误结论**（实际这些库都在，fastjson 的 import 有 9802 处）。正确姿势两条：① **扫源码 import 反推**（43324 个 java 的 import 一遍过，能直接列出真实用到的第三方库）② **读 jar 内 `META-INF/maven/*/pom.properties` 拿准确版本**（大华实测拿到 javassist 3.23.1-GA / snakeyaml 1.23 / commons-lang3 3.3.2·3.5 / hutool 4.6.17 / gson 2.8.5 / log4j 1.2.17 / jsoniter 0.9.23）。**结论上的分寸**：gadget 库存在 ≠ hessian 链成立（公开链靠原生 readObject/setter，hessian 那 4 个触发点照样喂不动），但它直接决定「原生 OIS 入口 / fastjson / xstream / snakeyaml」这些**别的反序列化面**值不值得打——别因为 hessian 打不通就顺手把整个反序列化方向判死。
- **有源码时先判「无白名单变体」是不是死代码**：厂商常同时放多个序列化器（如 `HessianSerializer`(v2+自定义白名单) 与 `Hessian1Serializer`(v1，直接 `new HessianInput().readObject()`，**完全没有 `setSerializerFactory`**）。看到无白名单变体别立刻当成绕过点，**先 grep 它有没有被真正引用**：`grep -rn "Hessian1Serializer.class\|new Hessian1Serializer("`。实测大华：该类存在于两个模块的 client jar 里，但**全代码库 0 处引用**（`RpcProviderFactory.serializer = HessianSerializer.class` 是默认且唯一）→ 死代码，白名单结论不变。**引用计数为 0 就写清楚「不是绕过路径」，别拿它去构造 payload 浪费时间**。
- **绕过候选要看「白名单内类的危险字段类型」**：白名单放行的厂商包（`com.厂商.*`）里声明为 `Class`/`Class<?>`/`Method`/`ProcessBuilder` 的字段是唯一结构性入口（配合 `getDeserializer(Class)` 不查白名单）。实测大华厂商包内此类字段 **120 处**（如 `DataType.serviceClazz`、`MethodJobHandler.initMethod/destroyMethod`）。但**必须再验一步**：hessian 能否实例化该类型的值——`Class` 有 `ClassDeserializer`（`Class.forName(..., false, loader)`，不触发静态块），`Method` **攻击者生成端就构造不出**（`java.lang.reflect.Method` 非 `Serializable`，hessian 生成端直接抛 RuntimeException，见上文绕过点实测）。字段存在 ≠ 可利用，**判链路可行性仍按「每个类/类型逐个对照白名单 + 有无该类型的 Deserializer」**。
- hessian 不走 readObject，Java 原生链全失效——别套用 ysoserial/原生链思路
- 白名单外类静默替换成 HashMap（不报错），先确认 gadget 类在白名单再构造 payload
- 黑名单只有 4 个类（Runtime/Process/System/Thread），java.* 里其他危险类都没拦
- **SerializedLambda 其实有 readResolve**：`javap -p` 可见 `private java.lang.Object readResolve()`（本轮 JDK8u281 rt.jar 实测）。早前"本身没 readResolve、grep 命中的是常量池字符串"的结论**是错的**——错因是 javap 不加 `-p` 看不到 private 方法，只 grep 常量池会漏。它在 `java.lang.invoke` 包内 → 静态白名单 `java\..+` 放行，故 hessian 能实例化并调其 readResolve。但该 readResolve 走 `capturingClass` 的 `$deserializeLambda$` 反射查找，需要一个真实存在该方法的类（javac 为"可序列化 lambda"生成），大华 43324 java 里 `deserializeLambda` 命中 **0**，故无落点；MethodType 也有 readResolve（重建方法类型，无危险）
- **javassist `SerializedProxy`**（readResolve → `loadClass(proxyClassName)` + ProxyFactory）：类加载原语，但类在非白名单包，且要求某个白名单类以它为**字段类型**才可实例化（见下"字段类型通道"），实测无落点
- 类型标签：'C'(67)对象 'M'(77)Map 'U'(85)列表 'V'(86)定长列表，Map/List 的 type 也走 loadSerializedClass 白名单，不绕过
- **厂商白名单内（com.xxx.*）的命令执行类本身不是 gadget**：如 `ShellUtil extends Thread`，`run()`→`Runtime.exec`。但 run() 需 `start()`、exec() 需显式调用，hessian 反序列化都不触发（无参构造缺失时 Unsafe 实例化，字段写了但方法不跑）。必须找触发点（readResolve/hashCode/equals/compareTo/构造器，**不含 setter**）上**调用它**的载体——审计这类类时重点扫它的调用方是否落在触发点方法里，而不是看它自身有没有 Runtime.exec
- **判断「这条链是不是真的堵死」要给结论而不是留悬念**：用户会直接问「到底能不能通，是不是依赖包版本的问题」。回答格式应是「哪条路径、被什么机制拦住、证据在哪（源码/字节码行号）、还有哪几条窄路值得试、试它们需要什么前置条件」——别用「大概率/可能」含糊过去，也别为了有交代就把死代码变体说成可用绕过
- **`deserialize(bytes, clazz)` 的 `clazz` 参数是摆设**：`HessianSerializer.deserialize(byte[], Class)` 内部只调 `hi.readObject()`，**完全没使用 clazz**，类型强转（`(RpcRequest) obj`）在调用方。所以 payload 不必是目标期望的类型——**任意对象图都会被完整反序列化，后续 ClassCastException 不影响已发生的副作用**。构造验证 payload 时不用为「类型要对上」费心。
- **涉及「机制是否被绕过」的结论必须先跑正反对照实验，不能用单组结果外推**：本次曾据「SynchronousQueue 未被拦截」推出「内置 deserializer 绕过白名单」并作为唯一缺口报给用户，靶机补做 `PlainBean`/`JdbcRowSetImpl`（既非 `java.*` 也非厂商白名单）对照后才定位真因是静态白名单 `java\..+`。**只有「通过」组、没有「拒绝」组的实验结论不可采信**；给用户的绕过类结论必须同时给出被挡住的反证组及其返回（HashMap）。
- **靶机验证时用 `-Dprobe.tag=GEN|LAB` 区分「构包端」与「目标端」的静态块副作用**：探测类 static 块里读 `System.getProperty("probe.tag")` 写标记文件，否则用 `Class.forName` 构包时本地触发的副作用会与靶机触发混淆，得出「static 块能触发」的假阳性。同理判「是否触发 static 块」**必须用 static 块探针实测**，别只看 `forName` 的 boolean 参数推断。
