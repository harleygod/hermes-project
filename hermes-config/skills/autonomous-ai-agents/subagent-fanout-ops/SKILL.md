---
name: subagent-fanout-ops
description: "Use when 用 delegate_task 并行派子代理（fan-out），或批量结果丢失/需核实子代理产出。"
version: 1.0.0
metadata:
  hermes:
    tags: [delegation, multi-agent, orchestration, recovery]
---

# 子代理 fan-out 编排与结果恢复

用 `delegate_task` 并行铺开子代理（batch 模式）时的派发规范、后台语义、以及**批量结果丢失后的恢复流程**。

## 触发
- 要把一个大审计/调研任务拆成 3 个子代理并行做（batch 模式）
- 批量返回了 `--- ERROR ---` / 结果缺失 / 想知道子代理干到哪了
- 需要核实子代理自述的产出是否真的落地

## 派发规范
- **并发上限**：受 `delegation.max_concurrent_children` 限制（本机为 3）；要 3 个以上就分批。
- **context ≤1500 字符，必须结构化**（子代理对当前会话零记忆）：
  ```
  项目/背景: <语言/框架/绝对路径>
  已知事实: <它必须知道的前提，如已实测结论>
  任务: <要它产出什么>
  重点: <点名最可能出结果的点>
  输出: FILE:LINE | 类型 | 严重度 | 描述（每条 <200 字符，最多 N 条，不写代码块/表格，不确定标 UNCERTAIN）
  ```
- **写进 context 的硬约束**：绝对路径；「找不到文件先 `find` 定位，别猜路径反复试」；
  「同一工具连续两次同参失败就换策略（例如 ripgrep 对含中文的 `/d/...` 路径会报 IO error → 改用 Python + 原生 `D:\...` 路径）」；
  要中文输出就明确写「用中文」。
- 子代理是 **leaf**：不能用 `clarify` / `memory` / `send_message`，不能再往下派。

## 后台语义
- 派发**立即返回**，结果在**全部完成**后作为一条新消息回到本会话；**不要轮询等待**，照常干自己的活。
- 批次的**实时日志是 append-only 落盘**的，可随时 tail 看进度：
  ```
  ~/AppData/Local/hermes/cache/delegation/live/<delegation_id>/task-N.log
  ~/AppData/Local/hermes/cache/delegation/live/<delegation_id>/manifest.json   # 每个 task 的 status
  ```
- 日志长行会被截断并标注 `…(+N chars)` —— **别指望日志里有完整输出**。

## ★ 批量结果丢失的恢复流程（实测 2026-09）

失败形态（原样记录）：
```
[ASYNC DELEGATION BATCH COMPLETE — deleg_xxxx]
--- ERROR ---
The batch did not complete successfully: Delegation owner exited before recording a terminal result; outcome unknown.
```
子代理**实际已经干完活**，只是调度器没记录终态。恢复步骤（**别重跑，先捞**）：

1. `ls` 那个 live 目录 + 读 `manifest.json` 看每个 task 的 status。
2. 读 `task-N.log`：先 `grep` 关键结论词（不是整篇读进上下文），必要时 `cut -c1-400` 压宽度。
3. **子代理的编译产物/脚本通常已落盘** —— 这才是恢复的富矿：找到它建的靶机/脚本，**自己重跑一遍**拿完整输出
   （本次子代理写完的 `hessian_lab2` 已编译好，重跑 `java ... Lab2 read` 就拿到了日志里被截断的完整结论表）。
4. 汇总时**如实说明「批量结果丢失 + 你如何恢复」**，不要把恢复来的结果说成批次正常返回。

## 核实铁律
- 子代理的 summary 是**自述**，不是证据。它写出的文件要自己 `ls`/读；它跑出的结论要重跑其产物验证。
- 对外部副作用（HTTP 写、远端改写、上传）要求它返回**可验证句柄**（URL / ID / 绝对路径 / 状态码）并由你复核。

## Pitfalls
- 别把整篇 transcript 读进上下文（每篇 10-30KB）：只用 grep 命中行。
- 子代理会**重复同一个失败调用**（实测连续 2 次同参 ripgrep 失败后自愈），所以 context 里提前给替代方案能省一整轮。
- 批次期间用户可以随时插话（out-of-band），恢复流程随时可能被打断 —— 先把关键产物落盘，再写汇总。
- 用户明确说「你自由去审、审完给结果」= 授权自主执行；但**红线不因此放宽**（写操作/攻击载荷仍按 pentest-safety 走）。
