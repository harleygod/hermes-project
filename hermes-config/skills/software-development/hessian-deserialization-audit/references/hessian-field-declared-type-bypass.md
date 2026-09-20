# hessian 白名单「字段声明类型」绕过 —— 第二轮靶机实测（15 组）

> 案例：大华 EvoWpms v5.0.0.17（hessian 4.0.63 + `CustomSerializerFactory` 白名单
> `allow com.dahua.evo.*` + 基础类型/Collections/时间类 + `java.lang.Class`）
> 靶机：`hessian_lab2`（编译厂商真实 `CustomSerializerFactory`/`HessianSerializer` 源码 + 同版本 hessian jar）
> 日期：2026-09

## 一、一句话结论

白名单按**类名**拦顶层类型；hessian 为**字段**选 deserializer 时用字段的**声明类型**（`getDeserializer(Class)` 重载），
该路径**不查白名单** → 只要 payload 里出现的**字段声明类型**非白名单，该字段值就被**真实例化**（并触发其 `readResolve`）。

## 二、实测矩阵（read 侧输出，`java -Dfile.encoding=UTF-8 -cp 'out;lib/*' audit.Lab2 read`）

| payload | 反序列化结果 | 判定 |
|---|---|---|
| `notallowed_map_filled`（顶层自定义 Map） | `java.util.HashMap {k=v}` | 降级 |
| `notallowed_map_resolve` | `java.util.HashMap {}` | 降级 |
| `notallowed_list`（顶层自定义 List） | `EXCEPTION UnsupportedOperationException: MapDeserializer@...` | 抛异常 |
| `notallowed_enum` | `java.util.HashMap {name=B}` | 降级 |
| `control_synchronousqueue` | `java.util.concurrent.SynchronousQueue []` | 真实例化（`java.*` 静态白名单放行） |
| `control_priorityqueue_compareto` | `PriorityQueue [EvoComparable(1), EvoComparable(5)]` + `[SIDE-EFFECT] EvoComparable.compareTo` | 真实例化 **+ 读侧触发 compareTo** |
| `control_treemap_compareto` | `TreeMap {EvoComparable(3)=three}` + `[SIDE-EFFECT] EvoComparable.compareTo` | 同上 |
| `whitelisted_evomap_resolve` | `com.dahua.evo.audit.EvoMap {}` | 白名单类正常 |
| **`holder_map_field_nonallowed`** | `EvoHolderMap` `[field m -> audit.NotAllowedMapResolve ; field plain -> java.util.HashMap]` | ⚠️ **字段值真实例化** |
| **`holder_list_field_nonallowed`** | `EvoHolderList` `[field l -> audit.NotAllowedList]` | ⚠️ **字段值真实例化** |
| **`holder_bean_field_nonallowed`** | `EvoHolderBean` `[field b -> audit.NotAllowedBean val=NotAllowedBean(cmd=whoami,num=1)]` + `[SIDE-EFFECT] NotAllowedBean.readResolve` | ⚠️ **真实例化 + readResolve 触发** |
| `collections_unmodifiablemap` / `_evokey` / `singletonmap` / `emptymap` | 均 `java.util.HashMap`（`_evokey` 额外打出 `[SIDE-EFFECT] EvoComparable.hashCode`） | 顶层仍降级；元素 hash 可触发 |

读法：**返回类型就是判据** —— `HashMap` = 被白名单拦下（未实例化）；返回真实类名 = 被实例化。
`[SIDE-EFFECT]` 打点在自建类的 `readResolve`/`compareTo`/`hashCode` 里 `println`，用于证明回调真被执行。

## 三、可利用面枚举：非白名单「字段声明类型」

靶机证明该通道存在后，审计动作转为**枚举厂商白名单类的非白名单字段类型**：

- 实测规模：43,324 个 .java 中，**408 种**不同的非白名单字段声明类型。
- TOP：`org.springframework.context.ApplicationContext` 564 处、`com.alibaba.fastjson.JSONObject` 509、
  `org.springframework.amqp.rabbit.core.RabbitAdmin` 199、`org.springframework.data.redis.core.RedisTemplate` 134、
  `org.springframework.http.HttpHeaders` 119、（其余 400+ 种）。
- **枚举坑**：反编译代码里字段类型是**简单类名**（靠 import 解析）。第一版脚本按全限定名匹配 → `distinct non-whitelisted field TYPEs: 0`（假阴性）。
  必须先解析同文件的 `import` 再比对白名单。用 Python + 原生 `D:\...` 路径（`os.walk`）扫，43k 文件约 25s；
  ripgrep 对含中文的 `/d/...` 路径会报 `IO error ... 系统找不到指定的路径`。

## 四、升级为 RCE 的判定（2026-09-20 全量复核后：该通道对本目标判死）

字段类型通道**确认可实例化任意非白名单类型**，但成链还需该类型本身有「实例化/readResolve 即危险」的行为。

**本轮全量复核**（口径：白名单类全部字段 + 全部触发点方法）：
- 字段 **33648 处 / 3895 种**（简单名口径；经 import 解析过滤掉白名单后 = 上一轮那 408 种），
  其中**第三方 gadget 包类型只有 1 处**；
- 「危险能力类」字段 **119 处**，全是 `Class` / `Method` / `ClassLoader` / `URL` / `ScriptEngine`(接口) /
  `GroovyClassLoader` / `BeanFactory`(接口)：`Method` 生成端即抛（非 Serializable），`ScriptEngine`/`BeanFactory` 是接口
  → 具体类只剩 `GlueFactory.groovyClassLoader`、`CtClassUtil.loader`、`HTTPRequest.url`；
- **「危险字段 ∩ 有自定义触发点」的类只有 1 个**，且是 **static 工具类**（`SosoDiscoverResultFilterAndSortUtils.java`，
  触发点里用的是 `PropertyUtils.getProperty`）→ hessian 反序列化**不调 static 方法**，不成链；
- 同口径扫白名单类自身：**7412 个触发点方法**中 6744 个是 Lombok 样板（`result = result * 59 +` / `$x = this.getX()`），
  余 **668 个自定义触发点的精确 sink 命中 0**。

**可复用判定口径（别再留悬念）**：字段类型通道成立 ≠ 可利用。必须
「**字段类型 = 危险类**」**且**「**该类在它自己的触发点方法上有危险操作**」两条同时成立；
两边交集为空即**判死**。结论要写成「哪条路径 / 被什么机制拦住 / 证据在哪（源码或字节码行） / 还剩哪几条窄路」，
不要写"待配合 classpath 上的具体 gadget"这类含糊说法。

## 五、复现命令（Windows / git-bash）

```bash
cd <lab2>
javac -encoding UTF-8 -cp 'lib/*' -d out $(find src -name '*.java')
java -Dfile.encoding=UTF-8 -cp 'out;lib/*' audit.Lab2 gen      # 生成 payloads/*.bin
java -Dfile.encoding=UTF-8 -cp 'out;lib/*' audit.Lab2 read     # 反序列化侧结论表
```
- classpath 用 `out;lib/*`（Windows 分隔符 `;`，单引号防 MSYS 改写）；`lib/` 放 hessian jar + slf4j。
- 自建「非白名单」测试类**必须 `implements Serializable`**，否则生成端直接抛
  `IllegalStateException: Serialized class X must implement java.io.Serializable`（宿主类用 Map 持有也不行）。
- 用 `-Dprobe.tag=GEN|LAB` 区分构包端/靶机端副作用。
