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

## 坑(全部实测)
- **中文路径 → 写马错位**: `CodeSource.getLocation().getPath()` 返回 URL 编码路径(`%e6%94%bb...`), 恶意类静态块无 URLDecoder → 写到字面 `%xx` 目录(如 D:\Pentest\%e6%94%bb...)。真实目标标准部署(如 C:\Resin\webapps\ROOT)是 ASCII 不受影响, 但中文路径定制部署会写错位置
- **beanutils BeanComparator 丢 cause**: 1.9.4 源码 `throw new RuntimeException("InvocationTargetException: " + ite.toString())` — 异常链断裂, 反序列化器只见 RuntimeException。绕过: 直接反射 `TemplatesImpl.class.getMethod("getOutputProperties").invoke(t)` → catch InvocationTargetException → `getTargetException()` 拿真实异常
- **ClassFormatError "Extra bytes at the end of class file"**: class 文件从序列化流抠出时带尾随字节(流残留如 `75 71 00 7e...`)。从流中重新提取干净字节: 定位 `cafebabe`, 前 4 字节大端 = 数组长度, 取 [p, p+len]。TemplatesImpl `defineTransletClasses` 报 "Cannot compile translet class" = defineClass 返回 null = 字节码不干净
- **maven 坐标**: commons-collections 3.x groupId = `commons-collections`(`commons-collections:commons-collections:3.2.1`); `org.apache.commons:commons-collections4` 才是 4.x。阿里云 maven 镜像缺部分 artifact(404), 用 repo1.maven.org 走代理
- **链触发判定**: HTTP 500 + RuntimeException 即确认链触发(beanutils 吞真实异常属正常), 不必纠结报错内容; 写马落盘才是最终证据
- JDK8 internal API(TemplatesImpl/TransformerFactoryImpl)javac 警告可忽略; 反编译内部类用 `javap -c -p -cp rt.jar`

## 支持文件
- references/weaver-dispatch-lab-case.md — 泛微 dispatch 载荷验证案例(依赖清单/发现记录)
