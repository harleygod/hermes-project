---
name: webshell-ops
description: "WebShell 连接排障与载荷免杀：解密错误诊断阶梯、冰蝎4.x协议逆向、AMSI载荷免杀流水线。"
version: 1.0.0
metadata:
  hermes:
    tags: [webshell, behinder, amsi, evasion, penetration, aspx]
---

# WebShell 运维：连接排障 + 载荷免杀

## 触发场景
- 已有 webshell 突然连不上 / HTTP 500 / 客户端报"解密错误"（马没死但连不上）
- 需要确认马是否存活、客户端协议是否匹配
- 服务端杀软拦截载荷（响应 500 + "contains a virus" / 0x800700E1）
- 需要给冰蝎等管理工具的载荷做免杀改造

## 一、连接排障阶梯（严格按顺序，每步只读优先）
1. **马是否活着**：GET 马 URL。
   - 500 且错误页显示马自己的源码 → 马活着（Session 型加密马无有效载荷时**必然** 500，这是正常现象）
   - 404 → 文件被删；403 → 被拦；200 空白/异样 → 被改
2. **协议核对**：客户端工具版本必须匹配马的生成版本（冰蝎 4.0.6 马配 4.0.6 客户端；4.1/t00ls/behinderbypass 副本协议可能有差异）
3. **密钥核对**：见 references/behinder-4-protocol.md（密钥 = MD5(密码) hex 前 16 位，不是补零、不是 MD5 原始字节）
4. **载荷大小测试**：80B vs 9KB 密文，区分"截断/大小过滤"
5. **代理测试**：走/不走代理各发 3-5 次（Clash 等本地代理是常见嫌疑）
6. **杀软测试**：响应含 "contains a virus" / 0x800700E1 = Assembly.Load 被 AMSI 拦（载荷内容问题，与请求无关）→ 走免杀流水线

## 二、关键陷阱
- **PKCS7 巧合假阳性**：固定明文 + 错误密钥解密时，末块有 ~0.02% 概率恰好通过 PKCS7 → 报 BadImageFormat 而非 Padding。多个错误密钥对同一小载荷都"解密成功"时先怀疑这个假象，用不同内容/更大载荷复核。
- **空 body 也报 Padding**：PKCS7 对空密文同样报 "Padding is invalid"，不能据此判断密钥状态。正确 oracle：发 15B（非 16 倍数）密文——报 "Length of the data to decrypt is invalid" = 密钥长度合法、解密器已运行。
- **响应带壳前缀**：混淆马响应体带明文前缀（如 `Welcome You!<html>\n</html>\n{;}\n`），解密前必须剥掉。
- **会话密钥马无需握手**：密钥写死在马文件 Session.Add，每请求重建，客户端发对密钥即可，与 cookie/会话无关。
- 冰蝎客户端 data.db 的 proxys 表（1080/7890 混用）和 shells 表（可手工插标准条目，transProtocolId=-1）是常见排查点。

## 三、载荷免杀流水线（AMSI 拦截时）
完整步骤见 references/payload-av-bypass-pipeline.md。核心结论（实测）：
- 改 PE 时间戳 / 替换字符串 / 方法头插 NOP → **都不够**，签名匹配方法体 IL/元数据结构
- **反编译 → csc 重编译（IL 全重排）→ dnlib 改名（元数据结构改变）→ 有效**
- 保留最小集：类名 U、客户端按字段名反射设置的字段（冰蝎 Cmd 为 cmd/path/sessionId）、Equals 覆写
- 验证用 scripts/behinder_mini_client.py 全协议实测（BasicInfo + whoami）

## 四、Windows 工具链坑
- Framework csc（v4.0.30319）只支持 C#5：反编译源码的 `$"..."` 插值、C#8 using 声明需先转换（见 references）
- PowerShell 脚本必须纯 ASCII（中文注释无 BOM 时 PS5.1 解析报"字符串缺少终止符"）
- ICSharpCode.Decompiler 7.2.1.6856（NuGet）在 PS5.1 加载需先 LoadFrom 依赖（见 references）
- csc 输出 GBK 编码：Python subprocess 用 capture bytes + gbk decode，别用 text=True
- dnfile API：方法表是 `mdtables.MethodDef`（不是 Method）；TypeDef.FieldList 是 MDTableIndex 不能直接 .Name

## 支持文件
- references/behinder-4-protocol.md — 冰蝎 4.0.6 完整协议（shell 模板/密钥派生/载荷格式/响应格式/字段清单）
- references/payload-av-bypass-pipeline.md — 免杀流水线全步骤（无效尝试记录/工具下载/转换规则/dnlib 改名规则）
- scripts/behinder_mini_client.py — 迷你冰蝎客户端（完整协议，独立验证载荷/执行命令）
