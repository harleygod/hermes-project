# hessian 4.0.63 + 自研 CustomSerializerFactory 白名单 — 实测记录

来源：某 Java 产品（Spring Boot fat-jar）源码审计，hessian 4.0.63。
方法：拷目标**真实**白名单源码 + 同版本 jar 编译成靶机，gen/read 双模式；两轮共 21 组 payload。

## 一、被测白名单实现（关键行）

`CustomSerializerFactory extends com.caucho.hessian.io.SerializerFactory`
```java
public CustomSerializerFactory() {
    super.getClassFactory().setWhitelist(true);      // 开白名单
    this.allowBasicType();                            // 基础类型 + Class + String
    this.allowCollections();
    this.allowConcurrent();
    this.allowTime();
    super.getClassFactory().allow("com.dahua.evo.*"); // 业务包通配
}
// allowBasicType() 里显式放行：
super.getClassFactory().allow(Class.class.getCanonicalName());   // java.lang.Class 在白名单内
```
反序列化入口：
```java
public <T> Object deserialize(byte[] bytes, Class<T> clazz) {
    Hessian2Input hi = new Hessian2Input(is);
    hi.setSerializerFactory(new CustomSerializerFactory());
    Object object = result = hi.readObject();   // 注意: clazz 参数完全未被使用
    return object;
}
```
→ **`clazz` 参数不参与任何校验/转换**，任意对象图都会被完整反序列化；外层 `(RpcRequest)` 强转失败抛 CCE 时，反序列化副作用早已发生。这是标准的反序列化漏洞特性，报告里要写清。

## 二、逐组实测结果（read 侧输出）

```
notallowed_map_filled        -> java.util.HashMap   {k=v}                # 顶层自定义 Map: 降级
notallowed_map_resolve       -> java.util.HashMap   {}                   # 降级
notallowed_list              -> EXCEPTION UnsupportedOperationException: MapDeserializer@...
notallowed_enum              -> java.util.HashMap   {name=B}             # 降级
control_synchronousqueue     -> java.util.concurrent.SynchronousQueue [] # 真实例化
control_priorityqueue_compareto -> java.util.PriorityQueue [EvoComparable(1), EvoComparable(5)]
     [SIDE-EFFECT] EvoComparable.compareTo                               # 反序列化期触发 compareTo
control_treemap_compareto    -> java.util.TreeMap {EvoComparable(3)=three}
     [SIDE-EFFECT] EvoComparable.compareTo
whitelisted_evomap_resolve   -> com.dahua.evo.audit.EvoMap {}            # 白名单类正常
holder_map_field_nonallowed  -> EvoHolderMap  [field m -> audit.NotAllowedMapResolve ; field plain -> HashMap]
holder_list_field_nonallowed -> EvoHolderList [field l -> audit.NotAllowedList]        # 字段值真实例化
holder_bean_field_nonallowed -> EvoHolderBean [field b -> audit.NotAllowedBean
                                 val=NotAllowedBean(cmd=whoami,num=1) ; field any -> HashMap]
     [SIDE-EFFECT] NotAllowedBean.readResolve                            # 真实例化 + readResolve 被调用
collections_unmodifiablemap* -> java.util.HashMap  (3 组: unmodifiable/singleton/empty)
```

第一轮另测：
```
v1 非白名单 Collection 类           -> 真实例化
v2 Class 对象(值=非白名单类)        -> 返回 class audit.ProbeStatic，static 块【未】触发
v3 载体类 Class 字段               -> EvoHolder{clazz=audit.ProbeStatic}  字段赋值成功
v4 Method 字段                     -> 生成端失败: "Serialized class java.lang.reflect.Method
                                      must implement java.io.Serializable"
v5 非白名单普通 POJO               -> java.util.HashMap {num=1, name=plain}  降级
v6 com.sun.rowset.JdbcRowSetImpl   -> java.util.HashMap                      降级
```

## 三、三个机制的字节码级证据

**1. 未白名单类被静默降级（不是拒绝）**
`ClassFactory.load()` 在白名单模式下对未允许类返回 `HashMap.class`，所以顶层任意类攻击（公开 gadget 链）全部失效。

**2. `ClassDeserializer.create()` 用 initialize=false**
```
35: ifnull 48                              // if (_loader == null) 跳转
38-44: Class.forName(name, iconst_0(=false), _loader)
47: areturn
48-49: Class.forName(name)                 // 仅 _loader==null 时 → initialize=true
```
`SerializerFactory()` 无参构造 = `this(Thread.currentThread().getContextClassLoader())` → **`_loader` 非 null** → 固定走 `forName(name, false, loader)`：**只加载类、不初始化 → static 块不执行**。
（`SerializerFactory` 字段是 `private WeakReference<ClassLoader> _loaderRef`。）

**3. 字段声明类型绕过（本次真正的突破口）**
hessian 为父对象字段挑 deserializer 时走 `getDeserializer(声明类型)` 重载，**该重载不查白名单** →
只要字段**声明类型**是非白名单类，字段值就被真实例化，并可触发其 `readResolve` / `readObject`。

扫全库统计"白名单类/业务类里声明为非白名单类型的字段"：**408 种**，TOP：

| 字段类型 | 出现次数 |
|---|---|
| `org.springframework.context.ApplicationContext` | 564 |
| `com.alibaba.fastjson.JSONObject` | 509 |
| `org.springframework.amqp.rabbit.core.RabbitAdmin` | 199 |
| `org.springframework.data.redis.core.RedisTemplate` | 134 |
| `org.springframework.http.HttpHeaders` | 119 |

## 四、同系统其它反序列化面（一并判死的部分）

- `Hessian1Serializer`（无白名单版）：全库**零引用** → 死代码
- `ObjectInputStream` 仅 5 处，全在工具类（`ListUtils.readObject` / `BeanUtil.cloneObj` / `UniqueLinkedBlockingQueue` / `CronExpression`）→ 需逐个追调用方与数据源可控性
- `GlueFactory`：保留 `GroovyClassLoader.parseClass(codeSource)`（等价任意 Groovy 执行），但全库 `loadNewInstance()` **零调用点**，且 `GlueTypeEnum` 只剩 `BEAN("BEAN", false, null, null)` → 脚本模式已裁剪，**不可达**
- 目标环境装了 OpenRASP（响应头 `X-Protected-By: OpenRASP`）→ 利用时注意拦截/记录

## 五、结论写法（可复用模板）

> 该入口预认证（`NettyHttpServerHandler.process()` 直接 `readObject()`，无 token 校验）。
> 公开 gadget 链因白名单静默降级**不可用**；`Class` 加载因 `initialize=false` **无 static 副作用**；`Method` 字段**不可序列化**。
> **成立的真实绕过面 2 条**：(a) 载体类的非白名单声明类型字段（全库 408 种候选类型）+ `readResolve` 回调；
> (b) JDK 集合类绕过白名单并触发元素 `compareTo`/`hashCode`。
> 二者均**未找到 classpath 上可达的 gadget 链，RCE 未证实**（如实记录，不夸大）。
