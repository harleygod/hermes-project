# 大华 EvoWpms hessian 白名单本地靶机实证（2026-09）

对象：大华 EvoWpms v5.0.0.17（RPC 序列化 `com.dahua.evo.rpc.serialize.impl.HessianSerializer`
+ 自定义白名单 `CustomSerializerFactory`，hessian **4.0.63**，JDK 8）。
目的：把 SKILL.md 里「must 再验一步」的两条悬而未决（危险字段能否实例化、白名单到底挡不挡）
在本地靶机上一次性做成实验结论。

## 靶机布局

`D:\Pentest\大华代码审计_20260916\hessian_lab\`

```
lib/        hessian-4.0.63.jar (目标同版本) + slf4j-api-1.7.36.jar (CustomSerializerFactory 用)
src/com/dahua/evo/rpc/serialize/impl/CustomSerializerFactory.java   ← 厂商真实源码(白名单)
src/com/dahua/evo/rpc/serialize/impl/HessianSerializer.java         ← 厂商真实源码(反序列化入口)
src/com/dahua/evo/rpc/serialize/Serializer.java / rpc/util/RpcException.java
src/com/dahua/evo/audit/EvoHolder.java      白名单内载体(包名命中 com.dahua.evo.*), 字段 Class clazz + Method method
src/audit/ProbeStatic.java                  static 块探针(非白名单包), 读 -Dprobe.tag 写标记文件
src/audit/PlainBean.java                    普通 POJO 反证组(非 java.* 且非白名单)
src/com/dahua/evo/audit/LabMain.java        靶机(等价 NettyHttpServerHandler.process)
src/com/dahua/evo/audit/GenPayload.java     payload 生成器
payloads/  out/  STATIC_BLOCK_HIT.txt(探针输出, 用完删)
```

关键：**直接用厂商反编译源码编译，不自己重写等价类**，保证白名单行为与目标一致；
只补一个「厂商包名下的载体类」(`EvoHolder`) 和「非白名单探针/反证类」即可闭环。

## 复现命令（git-bash 实测可用）

```bash
cd /d/Pentest/大华代码审计_20260916/hessian_lab
javac -encoding UTF-8 -cp 'lib/*' -d out $(find src -name "*.java")
# 构包端 (tag=GEN)
java -Dfile.encoding=UTF-8 -Dprobe.tag=GEN -cp 'out;lib/*' com.dahua.evo.audit.GenPayload
# 目标端 (tag=LAB)
java -Dfile.encoding=UTF-8 -Dprobe.tag=LAB -cp 'out;lib/*' com.dahua.evo.audit.LabMain payloads/v5_plain_bean.bin
```
路径坑：`-cp 'lib/*'`（单路径通配）与 `-cp 'out;lib/*'`（`;` 分隔）在 git-bash 下都可用；
源文件路径用 `$(find src ...)` 的相对路径形式最稳（MSYS 不会改写相对路径）。

## 六组实测矩阵

| # | payload 顶层类型 | 靶机 readObject() 返回 | 判定 |
|---|------------------|------------------------|------|
| V1 | `java.util.concurrent.SynchronousQueue`（`java.*`） | `java.util.concurrent.SynchronousQueue` | **真实例化**（静态白名单 `java\..+` 放行，非"绕过"） |
| V2 | `java.lang.Class`（值 = 非白名单 `audit.ProbeStatic`） | `class audit.ProbeStatic`，探针文件**无命中** | 可加载任意类；static 块不触发 |
| V3 | 白名单载体 `EvoHolder{clazz=audit.ProbeStatic}` | `EvoHolder{name=carrier, clazz=audit.ProbeStatic, method=null}` | Class 字段可承载非白名单类名 ✓ |
| V4 | `EvoHolder{method=Runtime.exec}` | **构包端即失败**：`RuntimeException: Serialized class java.lang.reflect.Method must implement java.io.Serializable` | Method 路线死路 |
| V5 | `audit.PlainBean`（非 java.*、非白名单） | `java.util.HashMap{num=1, name=plain}` | **降级**，未实例化 → 白名单有效 |
| V6 | `com.sun.rowset.JdbcRowSetImpl`（`com.sun.*`） | `java.util.HashMap`（含全部字段名） | **降级** → 标准 JNDI gadget 链打不通 |

反证组（V5/V6）是本次最有价值的一组：**没有它们就会把 V1 误判成白名单绕过**。

## 字节码证据

`ClassDeserializer.create()`（javap -p -c）：
```
35: ifnull 48                                  // if (_loader == null) -> 走 48
38-44: Class.forName(name, iconst_0(=false), _loader)   // 实际走这条: initialize=FALSE
48-49: Class.forName(name)                     // initialize=true 分支(真实部署不可达)
```
`SerializerFactory()` 无参构造：`invokevirtual Thread.getContextClassLoader()` → `this(<init>(ClassLoader))`
→ `_loader` 恒非 null → 恒走 `false` 分支。

`CustomSerializerFactory.java` 关键行：
```java
51: super.getClassFactory().setWhitelist(true);
56: super.getClassFactory().allow("com.dahua.evo.*");
77: super.getClassFactory().allow(Class.class.getCanonicalName());   // java.lang.Class 在白名单
```
另：声明了 `acceptClassNames` / `firstDeserializer` 字段但未重写 `getDeserializer`（死字段，别误判为第二层白名单）。

## 真实入口链路（源码行号）

```
NettyHttpServerHandler.process()                        // NettyHttpServerHandler.java:71
  → requestBytes 非空校验（无 token / 无签名）
  → rpcProviderFactory.getSerializerInstance().deserialize(requestBytes, RpcRequest.class)
  → HessianSerializer.deserialize()  // RpcProviderFactory.serializer 默认且唯一 = HessianSerializer
       hi.setSerializerFactory(new CustomSerializerFactory()); hi.readObject();
  → (RpcRequest) 强转     // clazz 参数在 deserialize 内部根本没用
```
`HessianSerializer.deserialize(bytes, clazz)` 只调 `hi.readObject()`，**不使用 clazz** →
任意对象图都会被完整反序列化，强转失败抛 CCE 时副作用早已发生。

## 未完成线索（下轮接手点）

1. **RpcRequest 未授权调用面（优先级最高 → 本轮已推荐给用户）**：
   `RpcRequest` 本身在 `com.dahua.evo.*` 白名单内 → 可构造**合法** RpcRequest →
   强转通过 → `rpcProviderFactory.invokeService(rpcRequest)` →
   **未认证调用任意已注册 RPC 服务方法**（不是绕过，是设计内服务调用缺鉴权）。
   待办：枚举全部已注册服务方法，筛文件写 / 命令执行 / SSRF / 二跳反序列化。
   与已知 0day（`evo-runs/controller/server/ServerModuleController.java:1851-1857`，
   `shellPath = deployPath + File.separator + manageScript + " {0} {1} {2}"` → agent 执行）同族但更底层。
2. **白名单内 gadget 挖掘**：可实例化集合 = 厂商包 + `java.*` + `javax.management.*`；
   在这三个范围内找 4 个触发点（readResolve/hashCode/equals/compareTo/构造器，**不含 setter**）上的危险调用载体。
   → **2026-09-20 已系统性排除，见 `D:\Pentest\大华代码审计_20260916\15_反序列化链结论_20260920.md`**：
   (a) 43324 个反编译 java 的 7412 个触发点方法中 6744 个是 Lombok 样板，余 668 个自定义触发点精确 sink 命中 **0**；
   (b) 危险字段 119 处（Class/Method/ClassLoader/URL/ScriptEngine/GroovyClassLoader/BeanFactory），第三方 gadget 包字段仅 **1** 处；
   "危险字段 ∩ 自定义触发点" 只有 1 个类且是 static 工具类（hessian 不调 static）；
   (c) 目标 739 jar/57079 class 里含 readResolve 的仅 **17** 个（全单例/枚举 + javassist SerializedProxy）→
   **在"4 个触发点"这个口径下无危险类可用**。
   ⚠️ **纠错（2026-09-20 当天更正）**：曾据"739 jar 的包统计"下结论说"classpath 上没有 CC/CB/c3p0/fastjson/xstream/groovy"，
   **这是错的**——厂商代码包**只含业务 jar + 少量库，不含运行依赖**（连 Spring 核心/Tomcat/MyBatis/hessian 本体都没有），
   数 jar 数不出真实 classpath。**正确办法：扫源码 import 反推**（大华实测：fastjson import **9802** 处、commons-collections 3.x+4.x、
   commons-beanutils、xstream、groovy、javassist 3.23.1-GA、json-lib、snakeyaml 1.23 **都在**）+ **jar 内
   `META-INF/maven/*/pom.properties` 反推版本**（大华实测拿到 javassist 3.23.1-GA / snakeyaml 1.23 / commons-lang3 3.3.2·3.5 /
   hutool 4.6.17 / gson 2.8.5 / log4j 1.2.17 / jsoniter 0.9.23 / rasp-engine 1.3.7 等）。
   **gadget 库存在 ≠ hessian 链成立**——公开链靠原生 readObject/setter，hessian 那 4 个触发点照样喂不动；
   但这些库的存在**让「原生 OIS 入口 / fastjson / xstream / snakeyaml」变成了更值得打的方向**（大华 fastjson 调用 9802 处、
   5 处原生 ObjectInputStream，snakeyaml 1.23 属 `Yaml.load` gadget 影响范围）。
   (d) 附加：classpath 上有 **OpenRASP(com.baidu.openrasp) + 悬镜(com.fuxi.javaagent)** 双 RASP，exec 会被 hook。
3. **未深挖的兄弟入口**：`evo-runs-adapt/AuthFilter` 保护 `/1.0.0/receive`（与已知 0day 同族接口、另一套服务），仅定位未展开。
4. **非 hessian 的 5 处 `ObjectInputStream`**：`ListUtils`×2、`BeanUtil.cloneObj`、
   `UniqueLinkedBlockingQueue`、`CronExpression` — 需逐个追调用方可达性（走 Java 原生链，不受 hessian 白名单约束）。
