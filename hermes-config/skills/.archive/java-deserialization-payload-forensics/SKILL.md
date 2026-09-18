---
name: java-deserialization-payload-forensics
description: "分析 Java 反序列化攻击载荷: 安全静态取证, 禁本地反序列化。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, java, deserialization, ysoserial, forensics, payload-analysis]
---

# Java 反序列化载荷安全取证

触发条件：拿到声称是反序列化利用的 .bin/.sh/.txt/抓包/base64 载荷，需要解读结构、识别链、判定行为、评估可用性（TongWeb/泛微/用友等 Java 中间件、ERP 的 0day/1day 载荷）。

## 铁律（用户红线，2026-08 实证，违反=失去信任）

1. **禁本地反序列化**：绝不对载荷流执行 `ObjectInputStream.readObject()`——这是唯一能让本机触发 gadget 链的操作。分析只用静态手段。
2. **defineClass 测试 = 执行边界**：把内嵌类字节喂给 `ClassLoader.defineClass` 属于"加载类"，类损坏时抛 `ClassFormatError` = 零执行，曾用作验证手段；但用户已明确**禁止重跑此类测试**，需要时先问。
3. **载荷内容严禁外传**：不上传任何服务、不拿载荷字节/内嵌类名做搜索、不入公共渠道。**搜接口路径字符串（如 /dispatch/invoke）可以，搜载荷内容不行**——两者边界要跟用户说清。
4. 发给目标服务器才算"执行"，发送方只发字节不解析；但写操作（发载荷/写马）仍需授权+用户拍板。

## 静态分析流程（全部无执行）

1. **识别序列化流**：魔数 `AC ED 00 05`（base64 形态开头 `rO0ABX`）。
2. **解码 + 字符串提取**：`re.findall(rb'[\x20-\x7e]{4,}', raw)` 列出类名/字段名——`com.xxx.*` 命名空间直接指向产品（`com.tongweb.*`=TongWeb、`org.apache.commons.*`=ysoserial 依赖）。
3. **提取内嵌 .class**：找 `CA FE BA BE` 魔数切出类字节 → `javap -c -p <file>` 静态反汇编（javap 只解析打印字节码，不加载类不执行静态块，安全）。
4. **识别 gadget 链**（ysoserial 命名）：
   - `PriorityQueue + BeanComparator(property="outputProperties") + ComparableComparator + TemplatesImpl` = **CB1**（泛微/用友爱用，e-cology lib 带 commons-beanutils）
   - CC1-7/CB1-2/groovy1/spring1/bsh1/c3p0 等见 `UReport2系统/poc/payloads/*.bin` 命名对照
   - 触发路径：PriorityQueue.readObject → heapify → compare → PropertyUtils.getProperty(obj,"outputProperties") → TemplatesImpl.getOutputProperties() → newTransformer → 定义 _bytecodes 里的 translet → static{} 执行
5. **恶意类行为判定**（看字符串/反汇编）：
   - `FileOutputStream` + `WEB-INF`/`static.jsp` + `BASE64Decoder` = **落地写马型**（translet 静态块写 JSP）
   - `Thread.sleep` + `InterruptedException(ignored)` = **时间检测型**（证明执行，零状态变化）
   - `ClassLoader.defineClass` + `Cipher/AES` + `SecretKeySpec` + 读 POST body = **内存马加载器 JSP**（先落加载器再传密文）
   - `URLDNS`/`dnslog` = 验证型
   - 用 `CodeSource.getLocation()` 反推 webroot 的写法 = 兼容任意部署目录的通用写马载荷
6. **损坏检测**：base64 串中混入非字母数字字节 → Java `Base64.getDecoder()` 严格模式直接抛异常（目标上连 defineClass 都到不了）；Python 宽松解码后再喂 defineClass 报 `ClassFormatError` = 类字节损坏，无法修复（原始字符已丢失），需重新生成载荷。

## 取证纪律

- 提取的临时类文件（_cls0.class 等）标注来源保留在分析目录，或按用户要求清理；临时验证脚本用 `hermes-verify-` 前缀跑完即删
- 载荷文件 sha256 留档供复验
- 用户会要"命令清单 + 取证"（进程/网络/文件时间戳），操作要可审计

## 相关

- 收录决策/公开性判定/影响范围实测：见 vuln-intel-poc-collection skill
- 产品专项（TongWeb/泛微）：见 commercial-app-pentest skill
