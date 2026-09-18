# 泛微 dispatch 载荷链级验证案例 (2026-08)

私有 0day 载荷: value.txt = base64(CB1 链), 写 {webroot}/static/static.jsp (AES 内存马加载器)。
入口: POST /dispatch/invoke/java.lang.String/copyValueOf, body 里 _SYS_ARGS.class="[B" 声明 byte[] → 服务端 base64 解码后反序列化。

## 靶机结构 (lab/)
- DispatchLab.java — JDK8 HttpServer, /dispatch/invoke/* 路由, 提取 body 的 "value" 字段 → Base64 decode → readObject
- 依赖 jar 在 webroot/WEB-INF/lib/ (classpath 指向它, 恶意类 POJONode CodeSource 才能反推出正确 webroot)
- 依赖清单 (maven central 经代理下载):
  - commons-collections:commons-collections:3.2.1 (注意 groupId 无 org.apache 前缀)
  - commons-beanutils:commons-beanutils:1.9.4 + commons-logging:1.2
  - com.fasterxml.jackson.core:jackson-databind:2.9.8 + core + annotations

## 验证结果
- 原始 value.txt 载荷 → HTTP POST → 链触发 → static.jsp (1555B) 落盘成功
- 完整闭环需在 ASCII 路径复刻 (D:\Pentest\lab_ascii)

## 三个关键发现
1. **_cls0.class 污染**: 存档 class 文件尾部被追加 10B 序列化流残留 (75 71 00 7e 00 12 00 00 01 81),
   defineClass 报 "Extra bytes at the end of class file"; 流内真实恶意类字节干净 (4208B, 提取为 pwner_clean.class)。
   教训: 从序列化流抠 class 文件容易切多; 验证 class 完整性用 TransletClassLoader.defineClass 而非 javap。
2. **中文路径坑**: POJONode CodeSource.getPath() = /D:/Pentest/%e6%94%bb%e9%98%b2/... (URL 编码),
   静态块无 URLDecoder → jsp 写到 D:\Pentest\%e6%94%bb... 字面目录。lab 必须放 ASCII 路径。
3. **beanutils 丢 cause**: 1.9.4 BeanComparator 反编译确认 `new RuntimeException("InvocationTargetException: "+ite.toString())`,
   无 cause。真实异常 (NPE at TemplatesImpl.getTransletInstance:457 等) 只能靠直接反射 Method.invoke 拿。

## 判定特征
- 链触发 = HTTP 500 + java.lang.RuntimeException (beanutils 吞了真实异常, 属正常)
- 最终证据 = static.jsp 落盘 (1555B, AES 密钥 1a1dc91c907325c6)

## 版本推断辅助
- 载荷假设: JDK≤8 (sun.misc.BASE64Decoder) + cc3.x + beanutils + jackson-databind 2.x + ROOT 部署
- → e-cology 8/9 标配完全符合, 7 排除 (无 jackson 2.x), 10 待测
