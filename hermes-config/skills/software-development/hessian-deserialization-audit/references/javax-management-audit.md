# javax.management.* 全包 gadget 审计结果（白名单 java.* + javax.management.*）

结论：给定白名单下 javax.management 包内**无可利用 RCE gadget**。真正 RCE 需 `javax.naming`(JNDI) / `javax.swing`(SwingLazyValue) / `com.sun.*` 内部类，均不在白名单。审计此类目标时把精力放到自定义白名单（如 com.dahua.evo.*）或确认是否存在放行 swing/naming 的旁路。

## 批量扫描命令（javap 对 rt.jar）

```bash
javap -version; echo "$JAVA_HOME"
JAR="$JAVA_HOME/jre/lib/rt.jar"   # JDK8；JDK9+ 无 rt.jar，改用 jmods/jimage
jar tf "$JAR" | grep '^javax/management' | grep '\.class$' | grep -v '\$' | sed 's#/#.#g; s#\.class$##'
```

四类触发点批量扫（javap 必须 `-p` 显示 private，readResolve 常是 private）：
```bash
# ① readResolve / readExternal
for c in $(jar tf "$JAR" | grep '^javax/management' | grep '\.class$' | grep -v '\$' | sed 's#/#.#g; s#\.class$##'); do
  javap -p "$c" 2>/dev/null | grep -qE 'readResolve|readExternal' && echo "=== $c ===" && javap -p "$c" | grep -E 'readResolve|readExternal'
done
# ② setter：  grep -E '\bset[A-Z]'
# ③ hashCode/equals/compareTo：  grep -E 'compareTo|hashCode\(\)|boolean equals'
# ④ 危险 sink 定位（字节码层 -c，人工过滤 RuntimeException 误报）：
for c in ...; do javap -c -p "$c" 2>/dev/null | grep -qE 'javax/naming|ProcessBuilder|Runtime|doLookup|InitialContext|addURL|URLClassLoader|\.exec\(|loadClass|Class\.forName|newInstance|defineClass' && echo "=== $c ===" && javap -c -p "$c" | grep -nE '...'
done
```

坑：`javap` 要在无中文路径目录（如 /tmp）跑，MSYS 对中文路径转义会坏；类名 `/`→`.`、去 `.class`；`Runtime` 会误报 `RuntimeException`，`loadClass` 会误报 `ClassLoaderRepository.loadClass` 接口，需人工过滤后确认调用是否落在 setter/readResolve/hashCode/equals/compareTo 上。

## 逐类结论

### BadAttributeValueExpException（重点排查）— 不可利用
- `readObject()` 与构造函数都调 `val.toString()`，但 hessian 用 `Unsafe.allocateInstance` 免构造器 + 反射直接写字段，`val` 被直接赋值、`toString()` 不触发。
- 它是**原生 Java 反序列化**经典 gadget，hessian 下失效。

### javax.management.loading — 不可利用
- MLet / PrivateMLet：Externalizable，`readExternal` 抛 `UnsupportedOperationException`，hessian 调 readExternal 直接失败。
- DefaultLoaderRepository（根包 + loading 包）：只有 static `loadClass/loadClassWithout`，无实例字段，依赖已注册 MLet MBean（目标不存在）。
- MLetContent：非 Serializable，纯数据容器。

### javax.management.remote / remote.rmi — 不可利用
- RMIConnector：`readObject → findRMIServer → findRMIServerJNDI → JNDI lookup`（原生 JNDI gadget），hessian 不调 readObject；`connect()` 需显式调用；`rmiServer/jmxServiceURL` 是 final 字段无 setter。
- JMXConnectorFactory：仅 static `connect/newJMXConnector`，显式调用。
- JMXServiceURL：readObject 只 `validate()` 校验。
- RMIConnectionImpl / RMIServerImpl / _Stub / _Tie：服务端/存根，无触发点。

### readResolve 全量（仅 7 个类，全无害）
SimpleType（返回 canonicalTypes 单例）、ArrayType（类型转换）、ImmutableDescriptor（校验+返回自身/EMPTY）、OpenMBeanAttributeInfoSupport / OperationInfoSupport / ParameterInfoSupport（重建 descriptor）、MLet.readExternal（抛异常）。

### hashCode / equals / compareTo 全量 — 全无害
Attribute / ObjectName / JMXServiceURL / 各 MBean*Info / openmbean 系列 / JMXPrincipal / DescriptorSupport 均为字段级比较。ObjectName 是唯一 Comparable，compareTo 只比 domain+属性字典序。

### setter 全量 — 全无害
`setMBeanServer` 只存引用；monitor 类 setter 只数值校验；relation 类 setter 只操作本地数据结构。
