# nuclei 模板武器化 — 泛微 dispatch 0day 完整实录 (2026-08-23)

用户路线: 0day POC → nuclei 只读探测模板 → 批量扫资产识别存在性 → 收录武器库。
本文是 vuln-intel-research SKILL.md "0day 武器化成 nuclei 探测模板"一节的实录与踩坑复盘。

## 1. 产出文件 (武器库)

```
D:\Pentest\攻防\武器库\nuclei-templates\
├── README.md                        ← 武器化规范(只读铁律/批量流程/收录流程/防误报教训)
├── parse_nuclei_jsonl.py            ← 解析 -jsonl: 按目标汇总命中 matcher
├── verify_dispatch_hits.py          ← 命中复核: 基线对比法(真命中 vs 软404/WAF 误报)
└── weaver\
    └── ecology-dispatch-invoke-probe.yaml   ← 泛微 dispatch 0day 探测模板(v2 成品)
nuclei 3.4.2: D:\Pentest\攻防\nuclei_3.4.2_windows_amd64\nuclei.exe
```

## 2. 模板设计 (以 dispatch 0day 为例)

三段式: ① 根路径通用指纹/版本兜底 ② /wui/index.html 版本细分 ③ 核心接口探测。

```yaml
http:
  # ① 根路径
  - method: GET
    path: ["{{BaseURL}}/"]
    redirects: true
    matchers-condition: or
    matchers:
      - type: word
        name: weaver-fingerprint
        case-insensitive: true
        words: ["weaver", "ecology"]
  # ② 版本细分 (泛微标记实测在 wui 页面)
  - method: GET
    path: ["{{BaseURL}}/wui/index.html"]
    matchers-condition: or
    matchers:
      - type: status
        name: wui-frontend
        status: [200]
      - type: word
        name: wui-version-e8
        case-insensitive: true
        words: ["/js/ecology8", "theme/ecology8", "ecology8"]
  # ③ 接口存在性 (核心, 防误报版)
  - method: POST
    path:
      - "{{BaseURL}}/dispatch/invoke/java.lang.String/copyValueOf"
      - "{{BaseURL}}/ecology/dispatch/invoke/java.lang.String/copyValueOf"
    headers:
      Content-Type: application/json
    body: |
      {"taskType":"1","options":{"_SYS_ARGS":{"class":"[B","value":""}},"taskId":"1"}
    matchers:
      - type: dsl
        name: dispatch-interface
        dsl:
          - "status != 404 && status >= 200 && status <= 599"
```

关键设计决策:
- 空 value 载荷: 反序列化失败但不执行代码 → 只读无副作用, 可安全批量
- 双路径变体: ROOT 部署 + /ecology/ 上下文部署
- 版本指纹实测校准: 泛微标记在 /wui/index.html 的 `/js/ecologyN`(如 /js/ecology8/lang/...) 和 `theme/ecologyN`(如 /wui/theme/ecology8/...), **根路径没有**; **e-cology 8.2+ 也有 wui 前端**, wui 存在 ≠ 9/10

## 3. 误报复盘 (v1 → v2, 核心教训)

**v1 用 `matchers: - type: status, negative: true, status: [404]`** → 999 目标扫出 91 条 dispatch "命中"。
基线复核后 **91 条全部为误报, 真命中 0**。误报两类:

1. **连接异常假命中**: 超时/连接重置/DNS 失败时 nuclei 状态码为 0, `0 != 404` → 误判命中
   (如 218.104.228.26 RemoteDisconnected、tca.huatong-group.com DNS 失败)
2. **WAF/云防护统一拦截页**: 对任意路径返回同一状态码
   - 403 Forbidden 页 (222.207.13.103, 58.17.121.146)
   - 504 Gateway Time-out (47.99.226.126)
   - 405 (58.221.136.227)
   - 200 "访问禁止" (58.240.70.209)

修复: dsl 限状态码范围 `status != 404 && status >= 200 && status <= 599`(排除 0), 复扫 dispatch-interface **0 命中**。
WAF 统一页防不住(单请求模板无法对比), 靠 verify 脚本人工复核。

## 4. 基线复核法 (verify_dispatch_hits.py)

对每个命中目标请求 3 个路径对比状态码:
- A. 真实接口 (POST /dispatch/invoke/...)
- B. 同前缀假方法 (POST /dispatch/invoke/java.lang.String/NoSuchXYZ<rand>)
- C. 随机路径 (GET /zz-nonexist-<rand>)

判定: A≠404 且 B/C==404 → 真命中; A/B/C 全相同(403/405/504/200) → 统一响应/软404 → 误报。
注意: matched-at 可能已带路径, 先 urlsplit 归一化到 scheme://host[:port] 再拼请求路径。

## 5. 批量扫描命令

```bash
# 全量扫描 (只读)
nuclei -t 'D:\Pentest\攻防\武器库\nuclei-templates\weaver\ecology-dispatch-invoke-probe.yaml' \
       -l urls.txt -timeout 10 -retries 1 -c 25 -silent -jsonl -o result.jsonl
# 汇总
python parse_nuclei_jsonl.py result.jsonl
# 复核命中
python verify_dispatch_hits.py result.jsonl
```

结果 (999 泛微目标): e-cology 8 系 832 (wui 8.2+), e-cology 9 系 4 个
(123.56.216.165 / 218.92.17.86:8089 / 222.71.236.82 / 47.110.235.81:9999), dispatch 0 真命中。
→ 公网标准部署无 dispatch 组件, 组件归属 8 vs 9 未决, e9 目标是后续验证对象。

## 6. 相关坑速查

- nuclei v3 DSL: `response_1.status_code` 报 "Unable to access unexported field 'status_code'";
  官方模板 (v10.x) 不用 req-condition, 用 status/word matcher 或 v2 风格 body_N/status_N
- git-bash 跑 nuclei.exe: `/d/...` 被 MSYS 转成 `C:\Users\...\d\Pentest\...` 报找不到文件,
  必须用反斜杠原生路径 `'D:\Pentest\...'`; python 脚本读文件路径同理
- 终端 -jsonl 输出会把模板 base64 混进 stdout, 解析结果只读 -o 文件
- 反序列化空载荷探测: 只发 `"value":""`, 服务端反序列化空流报错但不执行代码, 可安全批量
