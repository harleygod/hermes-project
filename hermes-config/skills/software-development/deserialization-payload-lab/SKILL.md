---
name: deserialization-payload-lab
description: "Java反序列化载荷本地验证靶机: 端到端测链/写马, 含class污染/中文路径/丢cause坑。"
---

# Java 反序列化链载荷本地验证靶机

拿到 CB1/CB3/CC 等反序列化 payload 或 ysoserial 载荷时, 搭本地伪靶机端到端验证能否打响(链兼容性、恶意类逻辑、写马落盘), 不用碰公网目标。

## 触发
- 验证某个序列化链/载荷在目标依赖版本下是否有效
- 排查链不触发 / 异常被吞 / 写马不落盘
- 拿到 0day 载荷先本地确认"武器本身能响"再上目标

## 靶机搭建
1. **依赖 jar 放 `webroot/WEB-INF/lib/` 且 classpath 指向该目录** — 恶意类若用 POJONode/某类的 CodeSource 反推 webroot, 依赖 jar 的物理位置必须含 WEB-INF/lib 路径, 否则反推错误
2. 入口用 JDK 自带 `com.sun.net.httpserver.HttpServer`(免容器): POST 路由 → 解析 body → base64 解码 → `ObjectInputStream.readObject()`
3. **lab 目录必须纯 ASCII 路径**(见坑)
4. 编译运行: `javac -encoding UTF-8 -cp "webroot/WEB-INF/lib/*"` ; `java -cp "webroot/WEB-INF/lib/*;."`
5. 发原始载荷 → `ls webroot/static/` 检查写马落盘 → 判定成功
6. 复刻到 ASCII 路径再完整闭环一次(中文路径下验证结果会被路径坑污染)

## 防护机制验证: 必须有「反证组」(方法论铁律)

靶机不只用来验证载荷「能响」, 也用来验证防护机制(白名单/黑名单/类过滤)**是否真的拦得住**。
验证防护时**单靠「通过」组会得出错误结论** —— 必须同时有预期被拒绝的反证组:

- 正证组: 预期被放行的载荷 → 记录实际返回
- **反证组: 预期被拒绝/降级的载荷 → 记录实际返回** (如 hessian 白名单把非白名单类静默降级成 `HashMap`,
  返回 `.getClass().getName()` 就是判定依据, 不用只看异常)
- 只有「通过」组、没有「拒绝」组的实验结论**不可采信**, 也不该报给用户

实测教训: 曾有载荷未被拦截就被推断成「内置 deserializer 绕过白名单」并作为唯一缺口上报,
补做反证组后才定位真因是库的**静态白名单按包名放行**(`java\..+` 放行全部 `java.*`) —— 与"绕过了什么机制"完全无关。
选择反证组时注意**排除掉会被静态规则放行的包名**, 否则反证组自己也会"通过", 反而强化误判。

**还要加一组「字段声明类型」正证(canary)**: 白名单/类过滤可能只拦**顶层类名**,
而反序列化器给**字段**选实现时用的是字段的**声明类型**(hessian 的 `getDeserializer(Class)` 重载即不查白名单)。
做法: 做一个白名单内的容器类, 其字段**声明类型**写成非白名单类, 反序列化后检查该字段是否被**真实例化**
(实测 hessian: 字段值真被实例化, 连 `readResolve` 都触发)。**只测顶层载荷会漏掉整条通道**;
同理「按接口/集合类判断能不能绕过」是错的 —— 决定因素是**字段的声明类型**。案例矩阵见
hessian-deserialization-audit → references/hessian-field-declared-type-bypass.md

**构包端副作用与目标端副作用必须可区分**: 载荷里若含会触发静态块/联网的类,
构建 payload 的那个 JVM 会先触发一次, 导致「靶机没打中也看到副作用」的假阳性。
做法: 探测类 static 块读 `-Dprobe.tag=GEN|LAB` 并把它写进标记文件, 构包用 `-Dprobe.tag=GEN`、
靶机用 `-Dprobe.tag=LAB`, 一眼分辨是谁触发的。判「某机制是否触发」**必须用探针实测**(static 块写文件、
DNS 出网、写马落盘), 不能只看参数/字节码推断。

## 坑(全部实测)
- **中文路径 → 写马错位**: `CodeSource.getLocation().getPath()` 返回 URL 编码路径(`%e6%94%bb...`), 恶意类静态块无 URLDecoder → 写到字面 `%xx` 目录(如 D:\Pentest\%e6%94%bb...)。真实目标标准部署(如 C:\Resin\webapps\ROOT)是 ASCII 不受影响, 但中文路径定制部署会写错位置
- **beanutils BeanComparator 丢 cause**: 1.9.4 源码 `throw new RuntimeException("InvocationTargetException: " + ite.toString())` — 异常链断裂, 反序列化器只见 RuntimeException。绕过: 直接反射 `TemplatesImpl.class.getMethod("getOutputProperties").invoke(t)` → catch InvocationTargetException → `getTargetException()` 拿真实异常
- **ClassFormatError "Extra bytes at the end of class file"**: class 文件从序列化流抠出时带尾随字节(流残留如 `75 71 00 7e...`)。从流中重新提取干净字节: 定位 `cafebabe`, 前 4 字节大端 = 数组长度, 取 [p, p+len]。TemplatesImpl `defineTransletClasses` 报 "Cannot compile translet class" = defineClass 返回 null = 字节码不干净
- **maven 坐标**: commons-collections 3.x groupId = `commons-collections`(`commons-collections:commons-collections:3.2.1`); `org.apache.commons:commons-collections4` 才是 4.x。阿里云 maven 镜像缺部分 artifact(404), 用 repo1.maven.org 走代理
- **链触发判定**: HTTP 500 + RuntimeException 即确认链触发(beanutils 吞真实异常属正常), 不必纠结报错内容; 写马落盘才是最终证据
- **搭靶机前先判「是不是死代码」**: `grep -rn "new XxxSerializer(\|XxxSerializer.class"` —— 引用计数 0 = 该序列化器/执行器从未被装配,
  为它搭靶机纯属浪费(实测大华 `FastJsonRedisSerializer` / `Hessian1Serializer` / `GlueFactory` 三例全 0 引用)。
  同理, **靶机跑通 ≠ 目标可利用**: 还要写清利用前提(如"能往该 Redis 写 pub/sub 消息")与运行时拦截
  (响应头 `X-Protected-By: OpenRASP` = 目标装了 RASP, 会 hook 原生反序列化与 exec, 先给可行性打折)
- **靶机保真度 = 依赖集合必须对**: 厂商给的"代码包"通常**不含运行依赖**(实测大华 739 jar 里连 Spring 核心/Tomcat/MyBatis/hessian 本体都没有),
  照它搭出来的 classpath 是错的。拿真实依赖清单两条路: ① 扫源码 `import` 反推(判断**有没有**这个库) ② 读 jar 内
  `META-INF/maven/*/pom.properties`(拿**精确版本**)。缺的构件从公开镜像取即可, 不必回目标端拉:
  `mvn dependency:get -Dartifact=g:a:v -DremoteRepositories=https://maven.aliyun.com/repository/public`
- JDK8 internal API(TemplatesImpl/TransformerFactoryImpl)javac 警告可忽略; 反编译内部类用 `javap -c -p -cp rt.jar`

## 支持文件
- references/weaver-dispatch-lab-case.md — 泛微 dispatch 载荷验证案例(依赖清单/发现记录)
- references/java-deser-sink-patterns.md — **搭靶机的前半程**: 按引擎(ObjectInputStream / MessageListenerAdapter /
  Jackson defaultTyping / fastjson / snakeyaml / XStream)**从源码里挖反序列化 sink** 的 grep 模式表,
  外加判定三问(有没有被装配=防死代码 / 能不能到达 / 有没有 RASP 拦截)与结论写法示范
- **验证「厂商自带白名单/序列化器」时, 直接编译厂商反编译源码进靶机, 别自己重写"等价类"** ——
  被验证的防护逻辑必须与目标逐行一致, 否则验的是你写的类而不是目标的类。
  这类场景(hessian + 自定义白名单)的完整靶机布局/复现命令/六组实测矩阵见
  hessian-deserialization-audit → references/dahua-evowpms-hessian-lab.md
