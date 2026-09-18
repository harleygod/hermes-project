---
name: nuclei-0day-weaponization
description: "0day/未公开漏洞武器化为只读nuclei探测模板: 模板铁律、防误报matcher、批量扫描+基线复核流程。"
---

# 0day → nuclei 只读探测模板武器化

用户偏好: 新 0day 到手先武器化成 nuclei 探测模板(只读), 用于批量资产识别某漏洞存在性; **载荷/链细节绝不进模板**, 只进本地 exploit 脚本。模板收录在 `D:\Pentest\攻防\武器库\nuclei-templates\`。

## 触发
- 新 0day / 未公开漏洞要收录武器库并批量扫资产
- 需要对一批目标(FOFA 导出/资产清单)识别某接口/漏洞存在性

## 工作流
1. 解读: 入口 / 危害 / 版本约束 / 载荷依赖(先解读再收录)
2. 写只读探测模板(见铁律)
3. **真实目标校准指纹词**: curl 看版本标记实际在哪个页面, 别凭印象写
4. `nuclei -validate -t <模板>` 语法验证(Windows 下路径用反斜杠)
5. 批量扫描 → 解析汇总 → 命中基线复核 → 人工复核后才可进 exploit 阶段
6. 收录: 厂商子目录 + 更新 README(武器化规范 + 防误报教训)

## 模板铁律
1. **只读探测**: 接口存在性 / 版本指纹 / 空载荷请求。反序列化类漏洞发空 value(服务端反序列化失败但不执行代码、无副作用); 写马/RCE 载荷绝不进模板
2. **matcher-name 语义化**: version-e8 / dispatch-interface 之类, 命中输出可读可筛
3. 双路径变体: 主路径 + 常见上下文路径(如 ROOT + /ecology/)
4. severity 按真实危害(入口=RCE 给 critical), description 注明"探测型不含载荷" + 命中需人工复核

## 防误报(实测教训, 最重要)
- **禁止 `status negative: [404]` 判接口存在** — 请求失败(超时/连接重置/DNS)时状态码为 0, `0 != 404` 会误判命中(v1 模板因此产生 91 条假命中)。用 dsl:
  ```yaml
  matchers:
    - type: dsl
      name: <接口名>
      dsl:
        - "status != 404 && status >= 200 && status <= 599"
  ```
- **WAF/云防护统一拦截页防不住**: 对任意路径返回同一状态码(403/405/504/200"访问禁止"), 单请求模板无法排除 → 命中后必须基线复核
- **基线复核法**: 对命中目标同时请求 真实路径 / 同前缀假路径 / 随机路径, 状态码三者全相同 = 软404/统一响应 = 误报。写成脚本(见泛微案例)

## 批量实战流程
```bash
# FOFA 拉资产(如 body="ecology_JSessionid")导出 urls.txt
nuclei -t <模板> -l urls.txt -timeout 10 -retries 1 -c 25 -silent -jsonl -o result.jsonl
# 解析: 按目标汇总 matcher 命中; 筛核心 matcher 命中; verify 脚本基线复核
```
结果 JSONL 含完整 request/response, 可直接当证据(操作可审计)。

## Windows 坑
- nuclei.exe 是 Windows 程序: 路径必须用反斜杠原生路径(`D:\...`), `/d/...` MSYS 路径会被转换报 "could not find file"
- nuclei v3 DSL: `response_1.status_code` 编译报错("unexported field"); 官方模板用 status/word matcher 或 v2 风格 `body_N`/`status_N`, 别用 response_N.xxx
- 版本指纹词必须实测: 泛微版本标记在 /wui/index.html 的 `/js/ecologyN` 与 `theme/ecologyN`, 不在根路径; **e-cology 8.2+ 也有 wui**(wui 存在 ≠ 9/10, 版本细分只能靠 body 标记)

## 支持文件
- references/weaver-dispatch-probe-case.md — 泛微 dispatch 0day 武器化完整案例(模板结构/指纹校准/扫描结果)
