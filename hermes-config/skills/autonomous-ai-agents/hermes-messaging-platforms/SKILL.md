---
name: hermes-messaging-platforms
description: "接微信/QQ/Telegram 等到 Hermes gateway：QR 扫码登录、凭证配置、排障。"
version: 1.0.0
---

# Hermes 消息平台接入 (Messaging Platforms)

把微信/QQ/Telegram/Discord 等聊天平台接到 Hermes gateway，让代理能在 IM 里收发消息、用全部工具。

## 触发场景
- 用户问"能不能接微信/QQ/Telegram 聊天"
- 配置 gateway 平台凭证、扫码登录、平台收发不工作排障
- 平台 token 过期需要重新扫码

## 平台清单
适配器在 `hermes-agent/gateway/platforms/`（Windows 上 HERMES_HOME 通常为 C:\Users\user\AppData\Local\hermes）：
- `weixin.py` — 微信个人号（腾讯官方 iLink Bot API，**原生支持，非第三方 hack**）
- `qqbot/` — QQ 机器人
- `telegram`/`discord`/`whatsapp_cloud`/`signal`/`bluebubbles`(iMessage) 等
平台注册名与配置键用 `hermes_cli/web_server.py` 里 grep 平台名确认（env_vars / required_env）。

## 微信 iLink 接入（2026-08 实测流程）

### 原理
- 走腾讯官方 iLink Bot API：`https://ilinkai.weixin.qq.com`，long-poll `ilink/bot/getupdates` 收消息，`sendmessage` 回话，媒体走加密 CDN
- 凭证 = `WEIXIN_ACCOUNT_ID` + `WEIXIN_TOKEN`（放 .env），**必须通过 QR 扫码获取**，不能手动注册/申请——扫码后 iLink 自动下发
- dashboard（web 界面）能填/管理这两个变量，但凭证本身得先扫一次码拿到

### 扫码流程（二维码有效期极短，务必快）
1. 起后台进程跑 `scripts/weixin_qr_login.py`（用 hermes venv 的 python，需 aiohttp+qrcode+PIL）
2. 脚本调 `ilink/bot/get_bot_qrcode?bot_type=3` 拿二维码 → **立即生成 PNG 并 os.startfile 弹到屏幕** → 轮询 `get_qrcode_status`
3. 用户手机微信"扫一扫"扫屏幕上的图 → 微信里确认绑定
4. 轮询到非 wait 状态 → 脚本打印凭证（token/account_id）→ 写入 .env

**铁律：二维码有效期短（实测复制链接→微信打开→确认必过期），必须生成二维码图片弹屏让用户扫，不能只给链接。** 轮询窗口 90s/轮，脚本自动刷新最多 3 次。

### 凭证写入与验证
```bash
# .env 追加（用打码验证）
grep WEIXIN_ACCOUNT_ID .env | sed 's/=.*/=***/'
# gateway 重启后 hermes doctor 应显示平台在线；平台列表 hermes platforms
```

## 接入后必配：白名单（不配 = 全拒）
gateway 默认拒绝未知发送者。.env 必须配 `WEIXIN_ALLOWED_USERS=<ilink_user_id>`（QR 确认响应里的 `ilink_user_id`，形如 `o9cq8...@im.wechat`）。不配的日志特征：
```
WARNING gateway.run: Unauthorized user: o9cq8...@im.wechat (...) on weixin
```
白名单配好重启 gateway 后即静默放行（日志不再出现 Unauthorized）。

## pairing 配对机制（首次消息触发）
- 新用户首条消息触发配对：用户微信收到"hermes pairing approve weixin <code>"提示
- 主控侧：`hermes pairing list` 看 pending 码（注意：list 显示的码可能是小写 hex；approve 内部转大写 + salt+hash 比较）→ `hermes pairing approve <platform> <code>`
- **坑：list 显示存在但 approve 报 "Code not found or expired"** —— pending.json 里 legacy 明文格式条目被 approve_code 静默忽略（只认 salt+hash 条目）。处理：`hermes pairing clear-pending` 清掉，让用户微信重发消息触发新码；或直接依赖白名单放行（白名单用户无需配对）
- 用户转述的配对码可能不准（如说 "JG" 实际是别的），以 `hermes pairing list` 的 pending 码为准

## 凭证有效性验证（token 失效排查）
调 iLink `ilink/bot/getconfig`（POST，headers: `AuthorizationType: ilink_bot_token` + `Authorization: Bearer <token>`，body: `{"ilink_user_id": <user_id>}`），返回 `ret: 0` 即 token 有效（响应含 typing_ticket）。

## Pitfalls
- **二维码短效**：链接复制太慢必过期。生成 PNG 弹屏（qrcode.QRCode + os.startfile）让用户手机扫，全程 <10s
- **qrcode 库安装**：hermes venv 无 pip，用 `uv pip install --python "C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" qrcode`（--python 必须 Windows 反斜杠路径，MSYS /c/ 路径 uv 不认）
- **凭证无法手填伪造**：WEIXIN_TOKEN/ACCOUNT_ID 只能来自 QR 登录流程（web_server.py 注释原文 "obtained through QR login in hermes gateway setup"）
- **iLink 有反滥用限制**：bot_type=3 是个人号；扫码用用户自己的微信，注意确认页面是腾讯官方 liteapp.weixin.qq.com 域
- 平台接入后消息经 gateway 路由，工具权限与 CLI 会话一致；私聊/群策略用 WEIXIN_DM_POLICY / WEIXIN_GROUP_POLICY / WEIXIN_ALLOWED_USERS 控制

## 脚本
- `scripts/weixin_qr_login.py` — 微信 iLink QR 登录（取码→PNG 弹屏→轮询状态→打印凭证），复制即用
