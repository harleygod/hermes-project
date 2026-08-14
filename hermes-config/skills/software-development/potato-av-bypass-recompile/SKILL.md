---
name: potato-av-bypass-recompile
description: 提权工具(potato类)被杀软拦 - 下载C#源码改命名空间/横幅混淆重编译绕过Avast/Defender
---

# 提权工具混淆重编译绕过杀软

## 触发条件
落地 potato 提权工具(exe/dll)被杀软(Avast/Defender)拦: LoadFrom 报 `0x800700E1`(ERROR_VIRUS_INFECTED)或执行报 Access is denied。

## 原理
杀软认的是工具的编译特征(命名空间/类名/作者横幅字符串)，不是提权行为本身。
证据: 内联 Add-Type 编译的 potato 代码不会被拦，只有官方编译版会被拦。
→ 改特征重新编译，杀软认不出来。

## 步骤
1. 下载工具 C# 源码(GitHub):
   - SweetPotato = `CCob/SweetPotato`(WinRM 模式不依赖 Spooler，触发 BITS+5985)
   - GodPotato = `BeichenDream/GodPotato`(main 分支)
2. 下载 Roslyn 新版 csc(本地老 csc 是 C#5.0，不支持 `$""`/`using static`):
   `https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers/3.8.0/microsoft.net.compilers.3.8.0.nupkg`
   解压拿 `tools/csc.exe`(支持 C#8)。注意 v2 端点会 302 跳转，用 v3-flatcontainer 直连。
3. 精简依赖: 去掉 NtApiDotNet 依赖(EfsRpc.cs/PrintSpoofer.cs/两个 GUID 大文件)，
   只保留 WinRM/DCOM 模式，改 PotatoAPI 删掉 EfsRpc/PrintSpoofer 字段和 case。
4. 混淆: `sed -i 's/SweetPotato/<随机名>/g' *.cs` + 改横幅字符串(@author 等)。
5. 编译: `<csc> /target:library /out:<随机名>.dll /nologo /langversion:8 *.cs`
6. 落地 + `[Reflection.Assembly]::LoadFrom` 加载(混淆后绕过 0x800700E1)。

## 关键坑
- 本地老 csc.exe 报 CS1056($"")/CS1041(using static) → 必须用 Roslyn csc。
- sed 把枚举值名也替换会断引用(如 `Mode.PrintSpoofer`→`Mode.PS`)，改完要检查编译错误。
- 内存加载 `Assembly.Load(byte[])` 不落地文件，但 AMSI 可能扫内存程序集；混淆重编译后再 LoadFrom 通常够用。

## 提权服务前提(先查再选变体)
`sc query spooler` / `sc query winrm` / `sc query bits` 看触发服务在不在:
- Spooler STOPPED+Disabled → PrintSpoofer 不可用
- WinRM+BITS Running → SweetPotato `-e WinRM` 模式
- DcomLaunch Running → DCOM 模式(`CoGetInstanceFromIStorage`+StorageTrigger)

## 战例
site4now 共享主机(WinServer2022/Virtuozzo): 最终 potato 提权走死——不是因为免杀没成
(混淆重编译成功绕过 Avast+Defender)，而是触发服务全加固(Spooler禁/BITS不触发/RPC不可用/无SeDebug/补丁2026-07)。
所以提权前先摸清触发服务，别在免杀上白费劲。
