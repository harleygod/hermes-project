# Burp MCP 完整工具列表（27 个）

## HTTP 请求
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 1 | `send_http1_request` | content, targetHostname, targetPort, usesHttps | 发 HTTP/1.1 请求，返回响应 |
| 2 | `send_http2_request` | headers, pseudoHeaders, requestBody, targetHostname, targetPort, usesHttps | 发 HTTP/2 请求 |

## Repeater
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 3 | `create_repeater_tab` | content, tabName?, targetHostname, targetPort, usesHttps | 创建 HTTP/1.1 Repeater Tab |
| 4 | `create_repeater_tab_http2` | headers, pseudoHeaders, requestBody, tabName?, targetHostname, targetPort, usesHttps | 创建 HTTP/2 Repeater Tab |

## Intruder
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 5 | `send_to_intruder` | content, tabName?, targetHostname, targetPort, usesHttps | 发送请求到 Intruder |

## 编码工具
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 6 | `url_encode` | content | URL 编码 |
| 7 | `url_decode` | content | URL 解码 |
| 8 | `base64_encode` | content | Base64 编码 |
| 9 | `base64_decode` | content | Base64 解码 |
| 10 | `generate_random_string` | characterSet, length | 生成随机字符串 |

## 配置
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 11 | `output_project_options` | (无) | 导出项目级配置 JSON |
| 12 | `output_user_options` | (无) | 导出用户级配置 JSON |
| 13 | `set_project_options` | json | 设置项目级配置 |
| 14 | `set_user_options` | json | 设置用户级配置 |

## Scanner
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 15 | `get_scanner_issues` | count, offset | 读取 Scanner 发现的漏洞 |

## Collaborator（OOB 检测）
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 16 | `generate_collaborator_payload` | customData? | 生成 Collaborator payload URL |
| 17 | `get_collaborator_interactions` | payloadId? | 轮询 Collaborator 回调 |

## Proxy History
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 18 | `get_proxy_http_history` | count, offset | 读取代理 HTTP 历史 |
| 19 | `get_proxy_http_history_regex` | count, offset, regex | 正则搜索代理 HTTP 历史 |
| 20 | `get_proxy_websocket_history` | count, offset | 读取代理 WebSocket 历史 |
| 21 | `get_proxy_websocket_history_regex` | count, offset, regex | 正则搜索代理 WebSocket 历史 |

## Organizer
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 22 | `get_organizer_items` | count, offset | 读取 Organizer 项目 |
| 23 | `get_organizer_items_regex` | count, offset, regex | 正则搜索 Organizer 项目 |

## 控制
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 24 | `set_task_execution_engine_state` | running | 暂停/恢复任务引擎 |
| 25 | `set_proxy_intercept_state` | intercepting | 开关代理拦截 |

## 编辑器
| # | 工具 | 参数 | 说明 |
|---|------|------|------|
| 26 | `get_active_editor_contents` | (无) | 读取活跃编辑器内容 |
| 27 | `set_active_editor_contents` | text | 设置活跃编辑器内容 |
