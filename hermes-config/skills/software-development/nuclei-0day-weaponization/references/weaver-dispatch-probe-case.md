# 泛微 e-cology dispatch 0day 武器化案例 (2026-08)

私有 0day: POST /dispatch/invoke/java.lang.String/copyValueOf 反序列化 RCE。
payload = CB1 链 (PriorityQueue + BeanComparator("outputProperties") + cc3 ComparableComparator + TemplatesImpl),
恶意类 ysoserial.Pwner* 静态块: POJONode CodeSource → 反推 webroot → 写 {webroot}/static/static.jsp (AES 内存马加载器, 密钥 1a1dc91c907325c6)。

## 探测模板结构 (ecology-dispatch-invoke-probe.yaml)
3 个请求:
1. GET / (redirects) — 通用指纹 weaver/ecology + 版本标记兜底
2. GET /wui/index.html — 版本细分主战场: /js/ecologyN、theme/ecologyN (e8/e9/e10)
3. POST dispatch 空载荷 — dsl matcher: `status != 404 && status >= 200 && status <= 599`, 双路径 (ROOT + /ecology/)

## 指纹校准发现
- 泛微版本标记在 /wui/index.html body 的 `/js/ecology8` 与 `theme/ecology8`, **根路径没有**
- **e-cology 8.2+ 也有 wui 前端** — wui 200 ≠ 9/10, 必须靠 body 标记细分
- 响应特征: Set-Cookie ecology_JSessionid, /cloudstore/resource/... 资源路径

## v1 → v2 误报修复
- v1 用 `status negative: [404]`: 999 目标扫出 91 条 dispatch "命中"
- 基线复核 (verify_dispatch_hits.py: 真实路径 vs 同前缀假路径 vs 随机路径 状态码对比) → **全部误报**:
  - 连接异常: 超时/重置/DNS 失败 → 状态码 0 → negative-404 误判
  - WAF 统一页: 403 (222.207.13.103), 504 (47.99.226.126), 405 (58.221.136.227), 200"访问禁止" (58.240.70.209)
- v2 改 dsl status∈[200,599] → 复扫 0 误报

## 批量扫描结果 (999 目标)
- e-cology 8 系 832 个 (wui 8.2+), **e-cology 9 系 4 个**: 123.56.216.165 / 218.92.17.86:8089 / 222.71.236.82 / 47.110.235.81:9999
- dispatch 真命中 0 → 公网标准部署无此组件 (仅特定版本/内网/定制部署)

## 工具链 (D:\Pentest\攻防\武器库\nuclei-templates\)
- weaver/ecology-dispatch-invoke-probe.yaml — 探测模板
- parse_nuclei_jsonl.py — 按目标汇总 matcher 命中
- verify_dispatch_hits.py — 基线复核 (真命中 vs 误报)
- README.md — 武器化规范 (模板铁律/批量流程/收录流程/防误报教训)
