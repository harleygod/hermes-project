---
name: burp-mcp
description: "Use when driving BurpSuite via MCP for pentesting."
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, burp, mcp, automation, web]
---

# Burp MCP — AI 直驱 BurpSuite

通过 MCP（Model Context Protocol），AI Agent 直接操控 BurpSuite 的 27 个工具。

## 连接

Burp MCP 扩展默认 SSE 端点：`http://127.0.0.1:9876`

连接脚本：`scripts/burp_mcp_call.py` — 封装 SSE + JSON-RPC 双向通信。
完整工具列表：`references/burp-mcp-tools.md`

快速验证连通性：
```bash
curl -s -N --connect-timeout 5 --max-time 5 "http://127.0.0.1:9876/"
# 应返回: event: endpoint / data: ?sessionId=xxx
```

## 核心工具矩阵

| 工具 | 阶段 | 说明 |
|-----|------|------|
| `send_http1_request` | 全阶段 | 通过 Burp 发 HTTP/1.1 请求，自动处理 cookie/session |
| `send_http2_request` | 全阶段 | HTTP/2 版本，现代站点默认用这个 |
| `create_repeater_tab` | 手工验证 | 在 Burp Repeater 创建 Tab，用户可手动跟进 |
| `send_to_intruder` | 爆破 | 丢给 Intruder 自动化爆破 |
| `get_proxy_http_history` | 攻击面分析 | 读取代理历史全部流量 |
| `get_proxy_http_history_regex` | 攻击面分析 | 正则搜索历史（搜敏感接口/参数/凭据） |
| `get_proxy_websocket_history` | WebSocket分析 | 读取 WebSocket 历史 |
| `generate_collaborator_payload` | SSRF/XXE | 生成 Collaborator payload URL |
| `get_collaborator_interactions` | SSRF/XXE 确认 | 检查是否有 DNS/HTTP/SMTP 回调 |
| `get_scanner_issues` | 漏洞发现 | 读取 Burp Scanner 结果 |
| `url_encode/decode` | Payload | URL 编解码 |
| `base64_encode/decode` | Payload | Base64 编解码 |
| `generate_random_string` | Payload | 生成随机字符串 |
| `set_proxy_intercept_state` | 流量控制 | 开关拦截 |
| `set_task_execution_engine_state` | 任务控制 | 暂停/恢复任务引擎 |
| `get/set_active_editor_contents` | 上下文 | 读写当前编辑器 |

## 渗透流程（MCP 驱动版）

### 阶段 1：流量收集
```
Playwright 浏览器 → Burp Proxy → 浏览目标站 → 所有流量进 Proxy History
```

### 阶段 2：攻击面分析（Agent 通过 MCP）
```
get_proxy_http_history_regex("login|register|api|admin|token|password")
get_proxy_http_history_regex("\.do$|\.action$|\.json$")  # Java/JSON 端点
get_proxy_http_history_regex("userId=|id=|uid=|user=")   # IDOR 候选
```

### 阶段 3：验证
```
对每个可疑接口：send_http1_request 发探测包 → 分析响应
```

### 阶段 4：爆破
```
登录接口 → send_to_intruder（Payload 位置：用户名+密码）
IDOR 候选 → send_to_intruder（Payload 位置：ID 参数）
```

### 阶段 5：OOB 确认
```
发现 URL 参数 → generate_collaborator_payload → 插入请求 → get_collaborator_interactions 确认回调
```

## 与 Playwright/curl 的分工

| 场景 | 工具 |
|-----|------|
| 需要浏览器环境（SPA、JS签名、反爬） | Playwright（挂 Burp 代理） |
| 纯 HTTP 请求，无前端依赖 | Burp MCP `send_http*_request` |
| 需要 Burp 的 Session/Cookie 处理 | Burp MCP |
| 需要 Collaborator OOB 检测 | Burp MCP |
| 需要 Repeater 手动调试 | Burp MCP `create_repeater_tab` |
| 需要 Intruder 多参数爆破 | Burp MCP `send_to_intruder` |

## 注意事项

### 流量可见性（重要！）
- **`send_http1_request` / `send_http2_request` 走 Burp 内部 HTTP 引擎，不经过 Proxy Listener，Proxy HTTP History 里看不到。** 用户打开 Burp 界面会发现 Proxy History 是空的——这不是 Bug，是设计如此。用 `create_repeater_tab` 代替才能在 Burp UI 里看到请求。
- `create_repeater_tab` 创建后用户在 Burp Repeater 里可以看到和手动操作——适合需要人工判断的复杂场景，也适合向用户展示"我发了什么请求"。
- **Proxy HTTP History 需要浏览器挂 Burp 代理（127.0.0.1:8080）才会产生记录。** 纯 MCP 发包不走这条路径。

### API 参数名陷阱
- `get_proxy_http_history` 参数是 `count` + `offset`，**不是** `maxRequests`
- `set_proxy_intercept_state` / `set_task_execution_engine_state` 只有 **setter**，没有 `get_` 版本——要读状态用 `output_project_options` 或 `output_user_options`
- 参数名错误会导致 `unknown key` 或 `Tool not found` 错误

### Proxy Intercept 默认开启（高频踩坑）
- Burp 默认 **Intercept 是 ON**（`do_intercept: true`），浏览器挂代理后第一个 HTML 请求被卡住，页面白屏
- **必须先关**：`set_proxy_intercept_state(intercepting=False)`
- 验证 Proxy Listener：`output_project_options` → 搜 `request_listeners` → 确认 `listener_port: 8080, running: true`

### 流量双通道（让 Burp UI 可见）
想让用户在 Burp 界面看到流量，两条路可并行：

| 通道 | 工具 | 用户可见位置 |
|------|------|------------|
| MCP 直发 | `create_repeater_tab` | Burp **Repeater** 标签页 |
| 浏览器代理 | Chrome 挂 `--proxy-server=127.0.0.1:8080` | Burp **Proxy HTTP History** |

- Repeater 通道：用户可手动改包重放，适合需要人工判断的复杂场景
- Proxy 通道：对 SPA/前端签名场景最有用——Playwright 处理 JS，Burp 自动捕获全部流量
- Chrome 专用配置避免干扰主浏览器：`--user-data-dir=<pentest-profile> --proxy-server=127.0.0.1:8080 --ignore-certificate-errors`

### 其他
- 需要 TLS 指纹/JA3 伪装 → 仍用 Playwright
- Collaborator 是 SSRF/盲 XXE 杀手锏，任何 URL 参数/文件导入/回调地址立即用它
