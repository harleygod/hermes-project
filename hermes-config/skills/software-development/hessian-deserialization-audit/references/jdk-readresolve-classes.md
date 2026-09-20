# JDK readResolve 类清单（hessian 白名单内潜在 gadget）

JDK 1.8 rt.jar 里实现 readResolve 的 java.* / javax.* 类（共 27 个，hessian 反序列化会调用 readResolve）：

```
java.awt.AWTKeyStroke
java.awt.SystemColor
java.awt.color.ICC_Profile
java.awt.font.TextAttribute
java.awt.font.TransformAttribute
java.io.ObjectStreamClass
java.lang.invoke.MethodType
java.lang.invoke.SerializedLambda
java.net.InetAddress
java.net.URL
java.security.KeyRep
java.time.Ser
java.time.chrono.Ser
java.time.temporal.WeekFields
java.time.zone.Ser
java.util.Currency
java.util.Locale
java.util.concurrent.ThreadLocalRandom
java.util.logging.Level
javax.management.ImmutableDescriptor
javax.management.openmbean.ArrayType
javax.management.openmbean.OpenMBeanAttributeInfoSupport
javax.management.openmbean.OpenMBeanOperationInfoSupport
javax.management.openmbean.OpenMBeanParameterInfoSupport
javax.management.openmbean.SimpleType
javax.print.attribute.EnumSyntax
javax.swing.Timer
```

## 逐个结论（hessian 场景）

- **java.net.URL**：readResolve 重建 URL（用 protocol 找 handler）；`HashMap.put` 触发 `URL.hashCode → DNS`（DNS 外带验证，非 RCE）
- **java.net.InetAddress**：readResolve 可能触发 DNS（类似 URL）
- **java.lang.invoke.MethodType**：readResolve 是 private，反序列化方法类型，可能触发类加载
- **java.lang.invoke.SerializedLambda**：**有 readResolve**（JDK8u281 `javap -p` 实测：`private java.lang.Object readResolve() throws ReflectiveOperationException`）。旧结论"没 readResolve"错误，错因是 javap 未加 `-p`（private 方法不显示）+ 只 grep 常量池。readResolve 会对 `capturingClass` 做 `getDeclaredMethod("$deserializeLambda$", SerializedLambda.class)` + invoke → 理论上是"任意类静态方法反射调用原语"，但需目标 classpath 上真存在 `$deserializeLambda$` 方法（javac 为可序列化 lambda 生成）；大华 43324 java 里命中 0，故无落点
- **javax.management.openmbean.*** / ImmutableDescriptor**：JMX 只读对象，readResolve 返回单例，无危险操作
- 其余（java.time.*、java.awt.*、Locale/Currency/Level 等）：readResolve 返回单例/重建对象，无 RCE

## 搜索方法（复现命令）

```bash
# 找 java.home
java -XshowSettings:properties -version 2>&1 | grep "java.home"
# rt.jar 位置 = $JAVA_HOME/jre/lib/rt.jar

python -c "
import zipfile
z = zipfile.ZipFile(r'D:\...\jre\lib\rt.jar')
hits = []
for n in z.namelist():
    if not n.endswith('.class') or not (n.startswith('java/') or n.startswith('javax/')):
        continue
    if 'module-info' in n or '\$' in n:
        continue
    if b'readResolve' in z.read(n):
        hits.append(n.replace('/', '.').replace('.class',''))
print('\n'.join(sorted(hits)))
"
```

## 大华 evo 平台 hessian 0day 审计结论（2026-09，供参考）

- 入口：`POST /evo-pic/oss?oss_addr=<内网>`，nginx `proxy_pass http://$arg_oss_addr`（SSRF，oss_addr 可控）
- 执行点：evo-job:8915（Netty RPC），`NettyHttpServerHandler.process()` 零鉴权直接 `deserialize(body)`
- 反序列化：`HessianSerializer.deserialize → Hessian2Input.readObject`，用 `CustomSerializerFactory` 白名单
- 白名单：静态 java.*(deny Runtime/Process/System/Thread) + javax.management.*，自定义 com.dahua.evo.* + 基础类型/集合
- 结论：c3p0/commons-beanutils/CB1 全被拦；SwingLazyValue 链类不在白名单；MLet 不可用。白名单内 RCE 链难找，SSRF 维度独立可用。
- 白名单内发现 `com.dahua.evo.acs.utils.ShellUtil extends Thread`（`run()/execCmd()` 里 `Runtime.exec(cmd)`），但无 setter/readResolve/hashCode，需找触发它的载体（Comparator/Map 等）
