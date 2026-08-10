# hkb2b.cpic.com.cn IDOR 案例

## 目标概况
- 平台：太保财险香港B2B平台 (uni-app Vue 编译)
- 认证：手机号+验证码，Token `USER_{userId}_{timestamp}.{base64_HMAC}`
- 签名：POST需 X-SIGNATURE/X-NONCE/X-TIMESTAMP/X-API-KEY（部分接口豁免）

## 已确认漏洞

### IDOR-1: POST /api/profile/address (高危)
- **漏洞**：可修改任意用户的联系地址
- **请求**：`POST /api/profile/address?userId=<victim>` + Token-A + X-User-Id: A
- **响应**：`{"success":true,"message":"联系地址更新成功"}`
- **对比**：GET `/api/profile/info?userId=<victim>` 返回 `您没有权限查看此用户信息`
- **结论**：GET做了鉴权，POST没有

### IDOR-2: POST /api/profile/email (高危，需AES加密)
- **漏洞**：可修改任意用户邮箱（需AES加密数据）
- **请求**：`POST /api/profile/email?userId=<victim>` + Token-A
- **响应**：`"邮箱数据格式错误，解密失败。请确保邮箱已正确加密"`
- **说明**：走到了业务校验而非权限拒绝，破解AES加密后即可利用

## 关键技巧

1. **FindSomething插件提取了12个API端点**，包括JS未暴露的 `/api/auth/loginByPhone`
2. **Token结构分析**：`USER_{userId}_{timestamp}.{HMAC}` → 签名绑定了userId，无法伪造
3. **GET vs POST差异**：`/api/profile/info` 的GET做了权限校验，但 `/api/profile/address` 的POST完全没做
4. **批量撞接口**：用REST惯例猜测，过滤404快速定位有效端点
5. `/api/users/{id}` 返回403而非404 → 端点存在但需角色权限

## 接口清单

| 端点 | 鉴权 | 备注 |
|------|------|------|
| `/api/captcha/token-generate` | 无需 | 验证码 |
| `/api/product-page/details` | 无需 | 产品列表 |
| `/api/profile/info?userId=` | GET有鉴权 | 用户信息 |
| `/api/profile/address?userId=` | **POST无鉴权** | IDOR |
| `/api/profile/email?userId=` | **POST无鉴权** | IDOR(需加密) |
| `/api/auth/loginByPhone` | 签名豁免 | 登录 |
| `/api/auth/sendCode` | 签名豁免 | 发验证码 |
| `/api/users/submit-authentication` | 签名豁免 | 提交认证 |
| `/api/users/{id}` | 403需角色 | 用户管理 |
| `/api/signature` | 需Token | 签名生成 |
| `/api/admin/user` | 独立auth | 管理后台 |
