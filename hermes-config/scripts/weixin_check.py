import json, urllib.request, pathlib, re

env = pathlib.Path.home() / "AppData/Local/hermes/.env"
vals = {}
for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
    m = re.match(r"\s*(WEIXIN_ACCOUNT_ID|WEIXIN_TOKEN|WEIXIN_ALLOWED_USERS)\s*=\s*(.+)\s*$", line)
    if m:
        vals[m.group(1)] = m.group(2).strip().strip('"').strip("'")

print("account_id:", vals.get("WEIXIN_ACCOUNT_ID", "<none>")[:12] + "***")
print("allowed_users:", vals.get("WEIXIN_ALLOWED_USERS", "<none>")[:14] + "***")

body = json.dumps({"ilink_user_id": vals.get("WEIXIN_ALLOWED_USERS", "")}).encode()
req = urllib.request.Request(
    "https://ilinkai.weixin.qq.com/ilink/bot/getconfig",
    data=body,
    headers={
        "Content-Type": "application/json",
        "AuthorizationType": "ilink_bot_token",
        "Authorization": "Bearer " + vals.get("WEIXIN_TOKEN", ""),
    },
)
try:
    with urllib.request.urlopen(req, timeout=25) as r:
        print("HTTP", r.status)
        print(r.read().decode("utf-8", "ignore")[:800])
except Exception as e:
    print("ERR", type(e).__name__, e)
    r = getattr(e, "read", None)
    if r:
        try:
            print(r().decode("utf-8", "ignore")[:800])
        except Exception:
            pass
