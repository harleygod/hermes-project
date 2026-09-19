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
# gateway 重启后 hermes gateway status 应显示 running；日志出现 ✓ weixin connected 即在线
# 注意：`hermes platforms` 这个命令**不存在**（2026-09-18 实测报 invalid choice），别照抄
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

## 排障：连不上/发不出（2026-09 实测）

### 1. gateway 没在跑（最常见）
症状：微信里发消息没反应。`gateway_state.json` 里写着 `"gateway_state":"running"` 也是**过期数据**——它不随进程退出更新。
```bash
hermes gateway status    # 会明确报 "✗ Gateway is not running" + "Stale gateway_state.json"
hermes gateway run       # 前台/后台起（本会话 background=true）
hermes gateway install   # 装 Windows 计划任务，开机自启（否则关了终端就断）
```
判断凭证是否还有效（不用重启 gateway）：
```bash
# POST https://ilinkai.weixin.qq.com/ilink/bot/getconfig
# headers: AuthorizationType: ilink_bot_token / Authorization: Bearer <WEIXIN_TOKEN>
# body: {"ilink_user_id": "<WEIXIN_ALLOWED_USERS>"}
# → {"ret":0,"typing_ticket":"..."} = token 有效
```
真连上的日志特征：`✓ weixin connected` + `[Weixin] Connected account=... base=https://ilinkai.weixin.qq.com`

### 2. `hermes send --to weixin:<dm_id>` 解析失败（实测坑）
微信 DM id 形如 `o9cq801...@im.wechat`，但 `_WEIXIN_TARGET_RE`（tools/send_message_tool.py:36）只认
`wxid_/gh_/v1_/wm_/wb_` 前缀、`*@chatroom`、`filehelper` → DM id 匹配失败 → chat_id 为空 → 报
`No home channel set for weixin ...`（**误导性报错，别去查 token**）。
解法：在 .env 加 `WEIXIN_HOME_CHANNEL=<dm_id>`，然后裸平台名发送：
```bash
printf 'WEIXIN_HOME_CHANNEL=o9cq...@im.wechat\n' >> ~/AppData/Local/hermes/.env
hermes send --to weixin "文本"
```

### 3. 主动发消息被 iLink 限流（ret/errcode -2）——**这是硬机制，不是配置错，别浪费时间重试**
症状：`hermes send --to weixin "..."` → `Weixin send failed: iLink sendmessage rate limited; cooldown active for 30.0s`
（30.0s = 适配器本地熔断刚打开，不是服务端让你等 30s）。
**实测结论（2026-09-18）：个人号 bot 不能主动发起会话。** 用户最后一次说话隔了 1 个多月后，
连续两次主动外发（间隔 35s）都是同一个 rate limited —— 等冷却没用，重启 gateway 也没用。
真正的门是**会话窗口**：必须用户在微信里先发第一句，bot 才能在该会话内回复。
排查时别连发刷接口，会持续触发熔断：`_rate_limit_circuit_threshold` 次命中即熔断 `_rate_limit_circuit_open_seconds`。

**"用户找不到微信里跟 bot 的会话"怎么办**（2026-09-18 踩到）：
- bot 不能在微信里主动弹消息，所以无法"发一条把他叫过来"，只能靠他翻到那个会话
- 最有效：让他在**微信顶部搜索框**搜上次对话里的独特词（从 `logs/gateway.log` 的
  `inbound message: platform=weixin ... msg='...'` 里捞他历史说过的话，挑个特征词给他去搜），
  搜索结果点"聊天记录"即可直达该会话
- 备选：聊天列表翻到对应日期；通讯录里找（iLink bot 以联系人形态存在）
- 会话 ID 可从 `channel_directory.json` 或 `weixin/accounts/<account_id>@im.bot.context-tokens.json` 的 key 拿到
  （形如 `o9cq801...@im.wechat`，是用户维度 DM id，**不是**给他看的入口）
- 彻底删了会话/找不到 → 才需要重扫码（走上面的 QR 流程），此时凭证会换新

### 4. `getaddrinfo failed` 持续刷屏 = gateway 进程内部 resolver 烂了，重启进程（2026-09-18 实测修正）
症状：日志每 30s 一轮刷 `[Weixin] poll error (1-3/3): Cannot connect to host ilinkai.weixin.qq.com:443 ssl:default [getaddrinfo failed]`，
偶夹 `[WinError 1236] 由本地系统中止网络连接`。**微信端表现 = 发消息没反应、也不回**（容易误判成"token 失效要重新扫码"）。

判别（30 秒内做完，别急着重扫）：
```bash
# 1) 旁边新起进程测同一域名：能解析+能 TLS 就是网关进程的问题，不是网络
python -c "import socket,ssl;s=socket.create_connection(('ilinkai.weixin.qq.com',443),timeout=8);print(ssl.create_default_context().wrap_socket(s,server_hostname='ilinkai.weixin.qq.com').version())"
# 2) 看 gateway 进程已跑多久
cat gateway.pid   # {"pid":...,"start_time":...}；powershell Get-Process -Id <pid> 看 StartTime
```
**根因：gateway 长跑（实测 27h+）后 asyncio 的该 resolver 状态失效**，进程内解析全挂，外部网络一切正常。
→ 解法：`hermes gateway stop && hermes gateway run`（凭证不用动、不用重扫码）。
修复成功特征：`gateway.run: Connecting to weixin...` → `[Weixin] Connected account=... base=https://ilinkai.weixin.qq.com` → `✓ weixin connected`。

**别踩的坑**：skill 旧版写"是本机 DNS 抖动、3 次重试会自愈、无需处理"——错。只有零星一两次才叫抖动；
连续多轮（间隔 30s 反复出现）就是进程坏了，干等不会好，必须重启。判断是否还在刷：`tail -3 logs/gateway.log` 看时间戳是否比当前时间新。

预防：gateway 别长跑，或者 `hermes gateway install` 装计划任务（顺带解决"关终端就断"）。

## 凭证有效性验证（token 失效排查）——`getconfig ret:0` **不足以**判定可用
调 iLink `ilink/bot/getconfig`（POST，headers: `AuthorizationType: ilink_bot_token` + `Authorization: Bearer <token>`，body: `{"ilink_user_id": <user_id>}`），返回 `ret: 0` 即 token 有效（响应含 typing_ticket）。

**重要修正（2026-09-19 实测）**：`getconfig ret:0` 只证明 token 通过了配置层校验，**不代表收消息的长轮询 session 还活着**。
当天实测：getconfig 返回 ret:0，但旧凭证实际已死，重启 gateway 后 8 分钟就打出
`ERROR gateway.platforms.weixin: [Weixin] Session expired; pausing for 10 minutes`，微信端发消息照样没反应。

**判断要不要重扫码的决策树**：
1. 日志刷 `getaddrinfo failed` / `WinError 1236` → 进程 resolver 坏，先重启 gateway（见下面第 4 条）
2. 重启后出现 `✓ weixin connected` 但随后 `Session expired` → **token 层面已失效，必须重扫码**，重启多少次都没用
3. 能收到 `inbound message: platform=weixin ...` → 通道真的活着，别动
**唯一可靠的"活着"证据 = 日志出现 inbound（用户消息进来）。** 只要没 inbound，就不要拿 getconfig 的 ret:0 当通关凭证。

## 重扫码后的善后（2026-09-19 实测，必做）
重扫码会下发**新的 `ilink_bot_id`**（实测 `f8fb89567e0d@im.bot` → `40b280a5a0b0@im.bot`），**旧的作废**。.env 要改两个：
- `WEIXIN_ACCOUNT_ID` = 新的 `ilink_bot_id`
- `WEIXIN_TOKEN` = 新的 `bot_token`（完整串，形如 `<account_id>@im.bot:<32位hex>`，长度约 58）
`WEIXIN_ALLOWED_USERS` / `WEIXIN_HOME_CHANNEL` **不用改**：`ilink_user_id` 是用户维度，同一个微信号重扫不变（实测恒为 `o9cq801KnpnIQYKNKvjVAIabGfMY@im.wechat`）。
改完必须重启 gateway 才生效。改 .env 前先备份：`shutil.copy2` 到 `.env.bak.<时间戳>`；验证时打码输出（`v[:12]...v[-6:]`）别把 token 明文打到聊天里。

成功特征（三条齐了才算通）：
```
gateway.run: Connecting to weixin...
[Weixin] Connected account=<新 account 前8位> base=https://ilinkai.weixin.qq.com
gateway.run: ✓ weixin connected
```
然后**让用户在微信里发一句话**，日志出现 `inbound from=...` 才算真通（bot 不能主动发起会话，见下面第 3 条）。

## Pitfalls
- **二维码短效**：链接复制太慢必过期。生成 PNG 弹屏（qrcode.QRCode + os.startfile）让用户手机扫，全程 <10s
- **qrcode 库安装**：hermes venv 无 pip，用 `uv pip install --python "C:\Users\user\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" qrcode`（--python 必须 Windows 反斜杠路径，MSYS /c/ 路径 uv 不认）
- **凭证无法手填伪造**：WEIXIN_TOKEN/ACCOUNT_ID 只能来自 QR 登录流程（web_server.py 注释原文 "obtained through QR login in hermes gateway setup"）
- **iLink 有反滥用限制**：bot_type=3 是个人号；扫码用用户自己的微信，注意确认页面是腾讯官方 liteapp.weixin.qq.com 域
- 平台接入后消息经 gateway 路由，工具权限与 CLI 会话一致；私聊/群策略用 WEIXIN_DM_POLICY / WEIXIN_GROUP_POLICY / WEIXIN_ALLOWED_USERS 控制

## 脚本
- `scripts/weixin_qr_login.py` — 微信 iLink QR 登录（取码→PNG 弹屏→轮询状态→打印凭证），复制即用
