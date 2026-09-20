# Java Web 应用「反序列化面」定位速查（源码侧）

搭靶机之前的前半程：**在目标源码里找出所有反序列化 sink，再判断哪些值得搭靶机验证**。
比背 gadget 名有效得多 —— gadget 可以现查，sink 必须你自己从代码里挖出来。

## 一、按引擎分类的 grep 模式（全部实测命中过）

| 引擎 | 代码模式 | 说明 |
|---|---|---|
| **Java 原生** | `new ObjectInputStream(` / `.readObject()` | 最值钱：**不受任何框架白名单约束**。厂商常把它藏在工具类里（`ListUtils.deserialize`、`BeanUtil.cloneObj`、`CronExpression.readObject`…），要逐个追调用方可达性 + 数据源可控性 |
| Java 原生 | `new MessageListenerAdapter(x)` **未设 serializer** | Redis pub/sub 消息体走 **JDK 序列化**（Spring Data Redis 的默认）。非常隐蔽，容易漏 |
| **Jackson** | `enableDefaultTyping(...)` / `activateDefaultTyping(...)`、`new Jackson2JsonRedisSerializer(Object.class)` | 多态反序列化；常与 `setVisibility(PropertyAccessor.ALL, Visibility.ANY)` 一起出现（能写私有字段） |
| **fastjson** | `JSON.parseObject(str, Object.class)` / `JSON.parse(body)` | 读端目标类型宽泛时才有 autoType 空间；写端 `JSON.toJSONString(x, WriteClassName)` 是配对信号 |
| **fastjson(MVC)** | `FastJsonHttpMessageConverter` | 注册后 `@RequestBody` 全走 fastjson。**必须同时看它有没有 parser 侧加固**（`Feature.DisableSpecialKeyDetect` / safeMode / autoType）；只设了 `SerializerFeature.*` = 无加固 |
| **snakeyaml** | `new Yaml().load(` / `Yaml.loadAll(` | snakeyaml **< 2.0** 的 `load()`（非 `safeLoad`）可被 `!!` 标签 gadget 打 |
| **XStream** | `xstream.fromXML(` | 经典 RCE 面，看是否配了白名单/XppDriver |
| 其他 | `XMLDecoder(` / `XStream` / `Kryo` / `FSTObjectInput` / `Hessian2Input.readObject()` | 同上逐个评估 |

## 二、判定三问（缺一不可，全部要写进结论）

1. **有没有被装配？**（否则是死代码，别投入）
   ```bash
   grep -rn "new XxxSerializer(\|XxxSerializer.class\|XxxSerializer<" .
   ```
   引用计数 0 = 从未被装配。实测某产品三例：`FastJsonRedisSerializer`（写端 `WriteClassName` + 读端
   `JSON.parseObject(str, clazz)`，看着很像洞）、`Hessian1Serializer`（无白名单 v1 变体）、`GlueFactory`
   （`GroovyClassLoader.parseClass` 完整 RCE 能力）—— **全是 0 引用**。厂商裁剪/未启用残留极常见。
2. **能不能到达？** 数据源可控性 + 调用链可达性。例如 Redis 相关 sink 的前提就是"能写那个 Redis"
   （未授权 6379 / 弱口令 / SSRF 打进去）。**把前提写清，别把"配置危险"当"可利用"**。
3. **有没有运行时拦截？** 目标装了 RASP 时（响应头 `X-Protected-By: OpenRASP`）会 hook 原生反序列化与 `Runtime.exec`，
   可行性整体打折。查 classpath 佐证：`com.baidu.openrasp` / `com.fuxi.javaagent` 之类。

## 三、实测案例：某 Java 平台（v5.0.0.17，Spring Boot 2.6.15 + JDK8）

```
✔ 未授权 JSON 入口（body 被解析，鉴权在业务层）→ 可用来做解析器/版本指纹
✔ 5 处工具类 ObjectInputStream：ListUtils×2 / BeanUtil.cloneObj / UniqueLinkedBlockingQueue / CronExpression
✔ RedisPubSubConfig：new MessageListenerAdapter(subscriber) 未设 serializer → 消息体 JDK 反序列化
                     同处 topic serializer 配了 enableDefaultTyping(NON_FINAL) → Jackson 多态面
✔ classpath 上有 commons-collections 3.x+4.x / beanutils / xstream / groovy / javassist / snakeyaml 1.23 → 链原料齐备
✘ FastJsonRedisSerializer / Hessian1Serializer / GlueFactory → 0 引用，死代码
```

结论写法示范：**「机制成立，但卡在 X；要打通需要 Y」** —— 不要留"待配合 gadget"这种含糊悬念，
也不要因为有危险配置就报成漏洞。

## 四、相邻技能

- 靶机搭建 / 反证组方法论 / 依赖集合保真 → 本技能 SKILL.md
- 框架自带白名单（hessian `CustomSerializerFactory` 之类）怎么测、字段声明类型通道 → `hessian-deserialization-audit`
- 依赖/版本怎么查（厂商代码包 ≠ classpath）→ `black-box-web-pentest` 的 2.4 节
