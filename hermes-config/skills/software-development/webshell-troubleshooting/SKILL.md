---
name: webshell-troubleshooting
description: 诊断加密 ASPX webshell 连接故障（500 解密错误/密钥协议/载荷截断）。
version: 1.0.0
metadata:
  hermes:
    tags: [webshell, behinder, 冰蝎, aspx, aes, decrypt, pentest, troubleshooting]
---

# Webshell 连接故障排查（加密 ASPX 系）

**触发场景**：马连不上 / HTTP 500 / "Padding is invalid and cannot be removed" / 解密错误 / 之前能用突然不行（客户端密码没改、马没动过）。

## 0. 工作方式（用户偏好，必须遵守）
- 每跑完一批工具调用，给用户一两行状态说明——用户会中途问"在干嘛"，说明他们需要全程可见。
- **用户会拦下发往目标的探测命令**（即使只是往自己的马发加密垃圾密文、无执行无改动）。验证类请求**写成脚本交用户自己跑**，同时给"结果判读表"。
- 只读验证（GET 看错误页）可自行进行；上传新马/任何写操作必须先说明影响、等用户说"可以"。
- 不要连续自动发一串探测请求——先解释要发什么、为什么，再发最少的。

## 1. 判断马是否还活着（一个 GET 就够）
- GET shell URL：
  - **404** → 马被删/隔离
  - **500 且错误页显示马自己的源码**（ASP.NET 黄色错误页 "Source Error" 里就是马的代码）→ **马活着且在执行**。GET 无 body 必然解密失败 500，这是正常现象，不代表马死了
  - 403 → 被 WAF/权限拦截
- 错误页里的源码行号可以拿来确认马的结构、是否被改过、甚至推断被隐藏的前几行（握手/默认密钥逻辑）。

## 2. 识别马家族（对照错误页源码特征）
- **冰蝎 4.0.6 .NET**：`Session.Add("k",...)` + `Session[0]` + `Request.BinaryRead(Request.ContentLength)` + `Assembly.Load(...).CreateInstance("U").Equals(this)`。混淆版特征：`xlpass` 前缀随机变量名、`\u0045` 转义、`/*注释*/` 切分、`Convert.FromBase64String` 常量、`Session[Convert.ToInt32(ASCII.GetString(new byte[]{48}))]` = `Session[0]`（int 索引取第一个 Session 项）。
- **Skyhinder**：硬编码密钥 `900bc885d7553375` + `Session.Add("sky", key)` + body 第一行 Base64（StreamReader.ReadLine）。
- 本机模板对照：`D:\Pentest\环境\Behinder\Behinder_v4.0.6\server\shell.aspx`、`D:\Pentest\攻防\Skyhinder\shell\`。

## 3. 密钥协议（冰蝎 4.0.6，模板注释原文）
- **密钥 = 连接密码 MD5 hex 的前 16 位**（作为 ASCII 字节），默认密码 `rebeyond` → `e45e329feb5d925b`。
- **大坑**：不是 MD5 原始 16 字节摘要（`.digest()`），也不是全 32 位 hex——是 **hex 字符串截前 16 个字符**。
- 算法：AES-128-CBC，IV=密钥，PKCS7（.NET RijndaelManaged 默认）。载荷 = POST 裸二进制 body（`BinaryRead`），**无握手**（密钥写死在马的 Session.Add 里）。
- 例：密码 `Aa123456` → 密钥 `afdd0b4ad2ec172c`。
- 全部细节见 `references/behinder-aspx-protocol.md`。

## 4. 错误信息 oracle（判断服务端密钥状态）
| 发什么 | 返回 | 含义 |
|---|---|---|
| 15B（非16倍数）裸密文 | `Length of the data to decrypt is invalid` | 密钥长度有效，解密器在跑 |
| 15B 裸密文 | `Specified key is not a valid size` / IV 不匹配 | Session 密钥为空/长度非法 |
| 空 body | Padding is invalid | 正常（PKCS7 无数据），**不能**当密钥判断 |
| 80B 密文×候选密钥 | BadImageFormat / 无法加载程序集 | **密钥正确**（解密成功→程序集非法） |
| 80B 密文×候选密钥 | Padding is invalid | 密钥不对 |

## 5. "载荷大小相关"是假信号陷阱（2026-08 实测证伪，先看这节再谈截断）
- **用错误密钥测载荷大小会伪造出"4KB 截断"假象**：固定小明文（如 64 字节全零）密文 × 错误密钥，解密出的**固定垃圾可能恰好通过 PKCS7 校验**（约 0.02%/对，且确定性重复出现）→ 报 BadImageFormat 被误读成"解密成功"；换同一错误密钥发 4-6KB 密文就不凑巧 → 报 Padding → 看起来像"大载荷被截断"。
- **正确顺序**：先用正确密钥 + 真实程序集载荷（U.dll，第 6 节）验证小/大载荷都能 RCE。能跑通 = 没有截断，问题在客户端。
- 只有"正确密钥下任意大小载荷都失败、密钥/协议也核对无误"才考虑服务端过滤（chunked 绕过、换轻量马，`scripts/decrypt_probe.py`）。
- 顺手排除多 worker/负载均衡（结果交替、看似随机失败）：DNS 多个 A 记录（`socket.gethostbyname_ex`）；连续 GET 错误页源码特征段是否一致；同一密文连发 3 次结果是否交替。

## 5.5 服务端验证通过后 = 客户端条目配置问题（本案例最终结论）
- 马活着 + 自定义客户端 RCE 成功 → 服务器端 100% 正常，连不上是**客户端条目配置**，按序核对：
  1. **传输协议**：冰蝎 TransProtocol 表里 aspx 的 `default_aes`（id=28）是 **AES-ECB + Base64 文本**，而马是 **CBC + 裸二进制**——条目若选了它必解密失败。应选默认 AES（CBC）。
  2. 密码栏是否真的等于实际密码（尾随空格/大小写/重建条目时输错——用户常以为没改）。
  3. URL 变体：https://、www.、IP 直连可能连到别的端点（https 可能直接 reset）。
- 客户端考古要点（判定"客户端到底发的什么"）：冰蝎 jar `Crypt.class` 默认路径 = CBC（ENCRYPT_TYPE_AES），另有 ECB 方法；aspx 请求 `Content-Type: application/octet-stream` + 裸 body（`Utils.sendPostRequestBinary`）；`data.db` 的 TransProtocol 表存各类型加密封装模板。详见 `references/behinder-aspx-protocol.md`。

## 6. 本地复刻客户端（自建可用工具，绕过坏掉的客户端）
- 编译载荷程序集 U.dll：`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`。
  - **MSYS 坑**：给原生 csc.exe 传 forward-slash `C:/...` 路径会被转坏（报"系统找不到指定的文件"）→ **cd 进目录用相对路径**，或反斜杠路径。
  - 用**反射**拿 `Page.Response`（`GetProperty("Response")` + `GetMethod("Write")`），避免编译期引用 System.Web.dll；命令从 `Request.QueryString["cmd"]` 取。
- Python 驱动：AES-128-CBC IV=key PKCS7 加密 U.dll → POST 裸密文 → `?cmd=whoami` 验证。
- 详见 `references/behinder-aspx-protocol.md`（含 U.cs 完整代码）。

## 7. 工具配置考古（找已保存的会话/密码/编码器）
- 冰蝎：`Behinder_vX/data.db`（shells/shellentity/BShell 表）
- 蚁剑：`antData/db.ant` + `antData/encoders/custom/`（自定义编码器，空文件=未配）
- 哥斯拉：`godzilla/data.db`（shell 表）
- Skyhinder：`config/data.db`（webshell 表，字段含 url/type/pass）
- 各工具 DB 里可能没有目标会话——那就走协议复刻（第 3、6 节）。

## 红线
- 只读验证可自行进行；探测/验证脚本交用户自己跑；上传新马/写操作先说明影响等确认。
- 对已拿下的自己的马：执行 whoami 类只读命令前也先说一句，用户对命令执行很敏感。
