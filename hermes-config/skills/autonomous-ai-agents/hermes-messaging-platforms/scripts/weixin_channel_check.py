#!/usr/bin/env python
"""微信 iLink 通道只读自检 —— 不重启、不发消息、不改配置。

用法（在 HERMES_HOME 下，如 C:\\Users\\user\\AppData\\Local\\hermes）:
    python scripts/weixin_channel_check.py            # 默认 ~/AppData/Local/hermes/.env
    python scripts/weixin_channel_check.py D:/some/.env

它做什么（全部只读）:
  [1] 读 .env，打码输出 WEIXIN_* 凭证，确认四项齐全
  [2] 新进程独立测 DNS + TLS 到 ilinkai.weixin.qq.com（用来区分"本机网络问题" vs "gateway 进程 resolver 坏"）
  [3] 调 ilink/bot/getconfig 验证 token 是否通过配置层校验

重要判据（读 SKILL.md 排障章节）:
  * getconfig ret:0 **不等于**长轮询 session 还活着，不能当"通道正常"的结论
  * 通道真活着的唯一证据 = gateway.log 出现 `inbound from=<uid 前缀>`
  * 本脚本不会也无法替用户"打开发会话"：个人号 bot 不能主动发起，
    `hermes send --to weixin` 报 rate limited 属预期行为，别连发重试（会持续触发本地熔断）

标准收尾动作：检查完，请用户在微信里给 bot 的会话发一句话，然后
    tail -5 ~/AppData/Local/hermes/logs/gateway.log
看有没有 `inbound message: platform=weixin`。
"""
import json
import os
import socket
import ssl
import sys
import urllib.request

HOST = "ilinkai.weixin.qq.com"
DEFAULT_ENV = os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes", ".env")


def load_env(path):
    env = {}
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def mask(val, head=12, tail=6):
    """打码：只露头尾，别把 token 明文写进聊天/日志。"""
    if not val:
        return "NONE"
    if len(val) <= head + tail:
        return val
    return "%s...%s(len=%d)" % (val[:head], val[-tail:], len(val))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ENV

    print("[1] 读 .env: %s  -> %s" % (path, "存在" if os.path.exists(path) else "MISSING"))
    if not os.path.exists(path):
        print("    -> 路径不对，先确认 HERMES_HOME")
        return 1
    env = load_env(path)
    account_id = env.get("WEIXIN_ACCOUNT_ID", "")
    token = env.get("WEIXIN_TOKEN", "")
    user_id = env.get("WEIXIN_ALLOWED_USERS", "")
    home = env.get("WEIXIN_HOME_CHANNEL", "")
    print("    ACCOUNT_ID=%s" % (account_id or "NONE"))
    print("    TOKEN=%s" % mask(token))
    print("    ALLOWED_USERS=%s" % (user_id or "NONE"))
    print("    HOME_CHANNEL=%s" % (home or "NONE"))
    if not (account_id and token and user_id):
        print("    -> 缺项：凭证只能来自 QR 登录（scripts/weixin_qr_login.py），不能手填")
        return 1

    print("[2] 新进程独立测 DNS/TLS -> %s" % HOST)
    try:
        ip = socket.gethostbyname(HOST)
        sock = socket.create_connection((HOST, 443), timeout=8)
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=HOST)
        print("    OK ip=%s %s" % (ip, tls.version()))
        tls.close()
    except Exception as exc:  # noqa: BLE001
        print("    FAIL: %s" % exc)
        print("    -> 本机网络/代理问题。若 gateway 日志同时在刷 getaddrinfo failed，先重启 gateway 再判。")

    print("[3] token getconfig")
    req = urllib.request.Request(
        "https://%s/ilink/bot/getconfig" % HOST,
        data=json.dumps({"ilink_user_id": user_id}).encode(),
        headers={
            "Content-Type": "application/json",
            "AuthorizationType": "ilink_bot_token",
            "Authorization": "Bearer " + token,
        },
    )
    try:
        body = urllib.request.urlopen(req, timeout=15).read().decode()
        ret = json.loads(body).get("ret")
        print("    ret=%s   (ret:0 = 凭证层通过；**不等于**长轮询存活)" % ret)
    except Exception as exc:  # noqa: BLE001
        print("    FAIL: %s" % exc)
        print("    -> token 可能已失效，考虑重扫码（见 SKILL.md「重扫码后的善后」）")

    print("[4] 别忘了:")
    print("    * 唯一可靠的\"活着\"证据 = gateway.log 出现 inbound from=%s..." % (user_id[:8] or "<uid>"))
    print("    * bot 不能主动发起会话 -> 必须让用户在微信里先说话")
    print("    * `hermes send --to weixin` 报 rate limited 属预期，不要连发重试")
    return 0


if __name__ == "__main__":
    sys.exit(main())
