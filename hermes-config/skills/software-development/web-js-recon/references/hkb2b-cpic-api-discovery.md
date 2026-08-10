# Case Study: hkb2b.cpic.com.cn — API 发现 & 认证逆向 & IDOR 猜解

**日期**: 2026-07-31
**目标**: https://hkb2b.cpic.com.cn/ (中国太平洋保险香港 B2B 平台)
**技术栈**: uni-app (Vue 3.4.21) + uniCloud + nginx + AES-CBC 加密

## 发现过程

### 1. 首页分析
标题 "InsuranceMiniProgram"，uni-app 编译到 web。页面结构：底部 tab "产品"/"我的"。
用户 "Hi 185****6527"，状态 "未认证"。

### 2. FindSomething 提取 API 列表

用 FindSomething 浏览器扩展一键提取所有 API paths：

| 端点 | 来源 JS | 方法 |
|------|---------|------|
| `/api/auth/loginByPhone` | request.js | POST |
| `/api/auth/sendCode` | authenticate.js | POST |
| `/api/auth/verify-old-phone` | request.js | POST |
| `/api/captcha/token-generate` | authenticate.js | GET |
| `/api/product-page/details` | tabBar-product.js | GET |
| `/api/profile/info?userId=` | index.js | GET |
| `/api/signature` | request.js | POST |
| `/api/users/change-phone` | request.js | POST |
| `/api/users/submit-authentication` | request.js | POST |
| `/api/users/submit-authentication?userId=` | authenticate.js | POST |

### 3. 认证机制逆向 (request.js)

**GET 请求**：
- Header: `X-User-Token` (from localStorage.userToken)
- Header: `X-User-Id` (from localStorage.userId)

**POST/DELETE 请求**：
- 以上 header +
- 额外签名 header: `X-API-KEY`, `X-TIMESTAMP`, `X-NONCE`, `X-SIGNATURE`

**签名豁免白名单**（代码硬编码数组 `S`）：
```javascript
["/api/auth/loginByPhone","/api/auth/sendCode",
 "/api/users/submit-authentication","/api/auth/verify-old-phone",
 "/api/users/change-phone","/api/signature"]
```

这些 POST 接口**不需要签名**，但数据需 AES-CBC 加密。

### 4. 未授权端点

| 端点 | 状态 |
|------|------|
| `/api/captcha/token-generate` | ✅ 无需认证，返回 base64 验证码 + captchaToken |
| `/api/product-page/details` | ✅ 无需认证，返回产品列表 |
| `/api/profile/info?userId=1` | ❌ 需要 Token |

### 5. IDOR 候选参数

以下端点出现 `userId` 在 URL query string：
- `/api/profile/info?userId=X` — GET，改 userId 读他人资料
- `/api/users/submit-authentication?userId=X` — POST，在签名豁免列表

攻击思路：先获取有效 Token → 改 userId 遍历 → 敏感信息泄露。

### 6. uniCloud 底层
JS 中发现 uniCloud 内部域名：
- `https://api.bspapp.com`
- `https://api.next.bspapp.com`
- `https://tcb-api.tencentcloudapi.com/web`
- `wss://wshzn.gepush.com:5223/nws` (WebSocket 推送)

说明后端使用腾讯云 CloudBase (TCB) + uniCloud serverless。

## 关键教训

1. **FindSomething 扩展 = JS recon 加速器**：手动 grep 需要下载所有 chunk，扩展一键提取
2. **userId 参数出现 → 全站 IDOR 猜解**：不限于 JS 中已暴露的接口，按 MVC 约定猜
3. **签名豁免白名单 = 直接攻击面**：无需签名 → 可 curl 直接调
4. **GET 通常不受签名保护**：只需 Token 即可调用，IDOR 风险最高
