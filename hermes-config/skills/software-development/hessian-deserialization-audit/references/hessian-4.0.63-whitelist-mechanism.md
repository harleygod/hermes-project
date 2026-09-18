# hessian-4.0.63 白名单机制白盒分析（CFR 反编译实录）

来源：CFR 0.151 反编译 hessian-4.0.63.jar 的 ClassFactory / SerializerFactory / Hessian2Input / JavaDeserializer / UnsafeDeserializer / MapDeserializer / BeanDeserializer / ObjectDeserializer / RemoteDeserializer / ClassDeserializer / FieldDeserializer2Factory / JMXSerializerFactory。

## ClassFactory.load / isAllow 全逻辑

```java
public Class<?> load(String className) throws ClassNotFoundException {
    if (this.isAllow(className)) return Class.forName(className, false, this._loader);
    return HashMap.class;   // 白名单外静默替换，不抛异常
}
private boolean isAllow(String className) {
    ArrayList<Allow> allowList = this._allowList;
    if (allowList == null) {            // 未配置自定义白名单
        Boolean isAllow = isAllow(_staticDenyList, className);
        if (isAllow != null) return isAllow;
        return true;                    // 默认全放行
    }
    Boolean isAllow = isAllow(this._allowList, className);      // 1. 实例白名单
    if (isAllow != null) return isAllow;
    isAllow = isAllow(_staticAllowList, className);             // 2. 静态白名单
    if (isAllow != null) return isAllow;
    return !this._isWhitelist;                                  // 3. 白名单模式默认 deny
}
```

`_staticAllowList` 顺序（**先 deny 后 allow，先匹配先生效**）：
1. `java\.lang\.Runtime` → false
2. `java\.lang\.Process` → false
3. `java\.lang\.System` → false
4. `java\.lang\.Thread` → false
5. `java\..+` → true（除上面 4 个外所有 java.*）
6. `javax\.management\..+` → true

`_staticDenyList` 只含上述 4 个 deny，仅在 `_allowList == null`（未设白名单）时被查。

`Allow.allow` 用 `Pattern.matcher(className).matches()` = **全串精确匹配**，所以 `java.lang.Runtime` 被 deny，但 `java.lang.Runtime$1` / `java.lang.RuntimeXX` 落回 `java\..+` 放行。

## SerializerFactory._staticTypeMap 全表（命中直接返回 Deserializer，绕过 load()）

| key | Deserializer |
|---|---|
| void(0) boolean(1) byte(2) short(3) int(4) long(5) float(6) double(7) char(9) string(10) date(12) | BasicDeserializer |
| StringBuilder → "string" | BasicDeserializer(11) |
| Object → "object" | BasicDeserializer(14)，**后被覆盖** |
| [boolean [byte [short [int [long [float [double [char [string [object | BasicDeserializer(15~24) |
| `object` | JavaDeserializer(Object.class)（静态块末尾 `_staticTypeMap.put("object", …)` 覆盖） |
| `com.caucho.hessian.io.HessianRemote` | RemoteDeserializer.DESER（resolve 依赖 getRemoteResolver()，默认 null，不 RCE） |

结论：`_staticTypeMap` 无任何危险类，不能借此 RCE。

## getDeserializer(String) 全流程

```
null/"" → null
查 _cachedTypeDeserializerMap 缓存
查 _staticTypeMap（原始类型/HessianRemote，无害）
type.startsWith("[") → 递归 getDeserializer(substring(1)) → ArrayDeserializer
否则 → loadSerializedClass(type) = getClassFactory().load(type)  ← 唯一白名单关卡
    → getDeserializer(cl)（deny 时 cl = HashMap.class → MapDeserializer，并以原 type 名缓存）
写缓存
```

`getDeserializer(Class)` 重载**不查白名单**，直接 `loadDeserializer(cl)`。

## Hessian2Input.readObject 类型标签 → 是否过 load()

| 标签 | 含义 | 路径 | 过 load() |
|---|---|---|---|
| C(67) | 对象定义 | readObjectDefinition → getObjectDeserializer(type) → getDeserializer(type) | ✅ |
| M(77) | 带类型 Map | readType → readMap(type) → getDeserializer(type) | ✅ |
| H(72) | 无类型 Map | readMap(null) → HashMap | 无类型 |
| U(85)/V(86) | 带类型 List | getListDeserializer(type) → getDeserializer(type) | ✅ |
| O(79)/0x60~0x6F | 对象引用 | 复用已定义的 classDef（定义时已过白名单） | 复用 |
| t | 类型定义 | readType 只读回字符串，后续 getDeserializer 校验 | ✅ |
| 其余 | null/布尔/整数/浮点/字符串/日期/二进制/引用 | 直接返回 | 无关 |

**无任何标签绕开 load()。** 数组 `type.startsWith("[")` 只 substring(1) 递归，最终仍过 load()。

## readObject(Class cl) 重载（字段类型驱动，不查白名单的两处）

```java
public Object readObject(Class cl) throws IOException {
    if (cl == null || cl == Object.class) return readObject();   // 走无预期类型 → 过白名单
    ...
    case 72:  // 'H' 无类型 Map
        return findSerializerFactory().getDeserializer(cl).readMap(in);  // ← 不查白名单(cl=字段声明类型)
    ...
    Object value = findSerializerFactory().getDeserializer(cl).readObject(in);  // ← fallback 不查白名单
}
```

字段反序列化入口：`FieldDeserializer2Factory.ObjectFieldDeserializer.deserialize` → `in.readObject(field.getType())`。
- 字段声明 `Object` → `readObject()` → 流内实际类型 → getDeserializer(String) → 过白名单 ✅
- 字段声明具体类 → `readObject(Class)` → 有类型标签时 getDeserializer(type)/getObjectDeserializer(type,cl) → 过白名单 ✅；仅 'H' 无类型 Map 和 fallback 用 cl 不查

`getObjectDeserializer(type, cl)`：`cl==null || cl.equals(reader.getType()) || cl.isAssignableFrom(reader.getType()) || reader.isReadResolve() || HessianHandle.isAssignableFrom(reader.getType())` 时用 type 的 reader，否则 fallback `getDeserializer(cl)`。

## Map key/value、字段类型结论

- `MapDeserializer.readMap`：`map.put(in.readObject(), in.readObject())` → key/value 都走 readObject() → getDeserializer(String) → 过白名单 ✅。副作用：put 触发 key 的 hashCode()/equals()（如 `java.net.URL.hashCode()` → DNS，SSRF 面）。
- 对象字段：见上，均过白名单（仅 'H' + fallback 两处用声明类型 cl，cl 不可注入）。

## 可直接引用的结论

1. 白名单机制（ClassFactory）无结构性绕过——所有攻击者可控类名字符串都经 load()。
2. 真正攻击面 = 白名单**放行范围过宽**：java.*（除 4 类）+ javax.management.* + 自定义（如 com.dahua.evo.*）。
3. RCE 落地需在这套放行集合内找触发链（readResolve/hashCode/equals/compareTo/setter 里触发 ProcessBuilder.start / MLet 加载 / Class.newInstance）。
4. c3p0 / commons-beanutils / commons-collections 等不在白名单的经典 gadget 会被静默替换为 HashMap，**链已死**，别浪费时间。
