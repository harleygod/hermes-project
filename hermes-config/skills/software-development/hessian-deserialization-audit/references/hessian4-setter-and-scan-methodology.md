# hessian-4.0.63「不调 setter」证据 + 大规模 .class 批量扫描方法

## 一、hessian-4.0.63 字段反序列化不调 setter（白盒反汇编实测）

结论：**危险 setter 不是 hessian 反序列化的触发点**。字段反序列化只做「反射直写 / Unsafe 直写」，无任何 setter 查找。

三点证据（`javap -p -c` 反汇编 hessian-4.0.63.jar）：

1. `FieldDeserializer2Factory.create(Field)` — 只按字段**类型**返回反序列化器（String/Byte/Short/Int/Long/Float/Double/Boolean/SqlDate/SqlTimestamp/SqlTime/Object 的 FieldDeserializer），不检查类里有没有 `setXxx` 方法。transient/static 字段直接返回 NullFieldDeserializer。
2. `FieldDeserializer2Factory$ObjectFieldDeserializer.deserialize(in, obj)` — 字节码：
   ```
   field.getType() → in.readObject(type) → field.set(obj, value)   // 反射直写
   ```
   无 `getMethod` / `getDeclaredMethod` / `invoke`（setter 查找特征全无）。JDK8 Unsafe 启用时走 `FieldDeserializer2FactoryUnsafe`，用 `sun.misc.Unsafe.putObject/putInt` 直写，同样不调 setter。
3. `SerializerFactory.getDeserializer(Class)` — 非特殊类只返回 `UnsafeDeserializer` 或 `JavaDeserializer`（+ Enum 用 EnumDeserializer），**不用 BeanDeserializer**。BeanDeserializer（setter 语义）不在 POJO 反序列化路径上。

对比：**Fastjson/Jackson 的 `@type` 会调 setter/getter，hessian 不会**。审计白名单（如 `com.dahua.evo.*`）时，别把精力花在「找危险 setter」上——那不是触发点。真正要扫的是 hashCode/equals/compareTo/readResolve/构造器。

### 构造器（弱触发点）细节

`JavaDeserializer.instantiate()`：
- `_constructor != null` → `_constructor.newInstance(_constructorArgs)`，参数由 `getParamArg(Class)` 填充：primitive → 默认值（0/false/'\0'），对象 → `null`。**参数非攻击者可控**。
- 否则 `_type.newInstance()`（要求无参构造器）。
- JDK8 下 `UnsafeDeserializer.isEnabled()==true` → 直接 `Unsafe.allocateInstance` 免构造器。

所以构造器副作用能被触发，但入参恒为 null/0，无法传命令字符串。实测大华 evo 全包无可疑构造器。

## 二、大规模 .class 批量扫描（2200+ 类，秒级完成）

坑：逐 class 起子进程 `javap -p -c`（每次一个 JVM 启动）极慢，2203 个类 per-class 循环 180s 直接超时。

正确做法（三步，bash/git-bash）：

```bash
cd <目标目录>
# 1) 危险字符串快速 triage（扫 .class 常量池，噪声大，仅当第一轮过滤）
grep -rla "getRuntime\|ProcessBuilder\|Class.forName\|InitialContext\|lookup\|openConnection\|getConnection" --include="*.class" extracted-acs lib-extract

# 2) 只出签名（javap -p 无 -c），秒级，够判 hashCode/equals/compareTo/readResolve/setter 有无
find extracted-acs lib-extract -name "*.class" > /tmp/allclasses.txt
cat /tmp/allclasses.txt | xargs -n 150 javap -p > /tmp/javap_sig.txt   # 单次 JVM 跑 150 个文件

# 3) 批量出字节码（-p -c），每批单次 JVM 启动
cat /tmp/allclasses.txt | xargs -n 80 javap -p -c > /tmp/javap_dump.txt
```

- `xargs -n N` 是关键：把 N 个 class 文件合并进**一次** javap 调用，省掉每个类的 JVM 启动开销。`javap` 支持命令行多文件参数，但 `@argfile`（`javap @list.txt`）在 JDK8 Windows 上不可靠，别用。
- 归属调用到方法：javap 输出里方法声明行以 2 空格缩进 + 含 `(` 结尾 `;`/`)`，`static {}`/字段初始化不匹配会并入前一个方法块（会误归属，注意 `static {}` 里的 Class.forName 会归到构造器）。解析时用 `// Method <owner>.<name>` 注释匹配危险 sink。
- 危险 sink 集合：`java/lang/Runtime.exec`、`java/lang/ProcessBuilder`、`java/lang/Class.forName`、`loadClass`、`java/net/URLClassLoader`、`InitialContext`/`Context.lookup`、`openConnection`、`ScriptEngine.eval`、`newTransformer`、`defineClass`、`java/lang/reflect/Method.invoke`、`getConnection`。
- 判定是否可利用：危险调用必须落在 `hashCode()`/`equals()`/`compareTo()`/`readResolve()`/构造器里才算 gadget；落在静态方法、普通实例方法（如 `run()`/`execCmd()`）里都**不是**触发点。

## 三、Windows/MSYS 路径坑（Python + javap 混用）

- Python `os.walk` / `subprocess` 要用**原生 Windows 路径** `D:\...`（或 `r"D:\..."`），MSYS 的 `/d/...` 传进 Python 是 0 结果 / FileNotFound。
- git-bash 的 `/tmp` 实际是 `C:\Users\<user>\AppData\Local\Temp`；Python 里访问用 `os.path.join(r"C:\Users\<user>\AppData\Local\Temp", ...)`。转换用 `cygpath -w /tmp`。
- `javap.exe` 在 JDK 目录：`D:\Program Files\Java\jdk1.8.0_281\bin\javap.exe`（`which javap` 拿到 MSYS 路径后 `ls` 该目录确认 .exe）。
- 中文路径 + CFR 反编译要用 Windows 原生反斜杠路径（`java -jar "D:\Pentest\反编译工具\...\cfr.jar" xxx.class`），MSYS `/d/` 会被转义坏——本 skill 已记。

## 四、大华 evo 审计结果（com.dahua.evo.* 白名单内）

结论：**白名单 `com.dahua.evo.*` 内无可行 hessian RCE gadget**。

- 危险 sink 全部落在静态工具方法或非触发实例方法：`ShellUtils.execLinuxCmd*`（static）、`ShellUtil.run()/execCmd()/execSh()`（`run()` 需 `start()`，反序列化不调）、`Executor.execute`（static）、`EnhancedReflectionUtils.getClassByName`（static Class.forName）、`ReflectionExtUtils.getCurrentMethod/getInvokingMethod`（static Class.forName）、`ClassUtil.resolveClass`（static Class.forName）、`XmlUtil.reBuildXml`（newTransformer，普通实例方法）、`DateUtil.resetSystemTime`（static）、`HttpClientPoolUtil/FileStreamUtils`（static openConnection）。
- 无 readResolve / readObject / validateObject / finalize。
- hashCode/equals/compareTo 全是字段级比较（Lombok 式），无危险调用。
- `ShellUtil extends Thread`、`ShellUtils extends Thread`：无参构造只 `super()`；即使 Unsafe 实例化写了字段，`run()` 也不会被反序列化触发。**命令执行类本身不是 gadget**（本 skill Pitfalls 已记，此处为实测印证）。
- 白名单机制：`CustomSerializerFactory` 构造器 `ClassFactory.setWhitelist(true)` + allow 基础类型/集合/并发/时间 + `allow("com.dahua.evo.*")`；声明了 `acceptClassNames`/`firstDeserializer` 字段但**没重写 getDeserializer**（死字段，无第二层过滤）。
