# Case Study: aiot.cpic.com.cn — 供应链/供应商信息泄露

**日期**: 2026-07-31
**目标**: https://aiot.cpic.com.cn/ (太平洋保险智能物联网数据应用平台)
**技术栈**: Vue.js SPA + nginx + Spring Cloud Gateway + Spring Boot

## 发现过程

### 1. 首页分析
首页是标准 Vue SPA，标题"太平洋保险智能物联网数据应用平台"。
CSP 头声明了后端端口 31008、31009，以及第三方域名（萤石、3dnest、百度地图、Mapbox）。

### 2. JS 文件下载
```bash
curl -k -s https://aiot.cpic.com.cn/js/app.95254852.js -o app.js  # 313KB
# 提取出 18 个 chunk 的 hash 映射
```

### 3. 供应链泄露发现
在 app.js 中搜索外部 URL：
```bash
grep -oP 'https?://[a-zA-Z0-9._-]+(:\d+)?/' app.js | sort -u
```

**发现的非 CPIC 域名**：
- `http://hwj.huazhu.com:8080/HQuestionCRM?qNo=AD163E8A-...` — 华住酒店集团内部 CRM
- `https://omsjapi.huazhu.com/` — 华住 OMS API
- `https://oms-cos-1258646913.cos.ap-shanghai.myqcloud.com/static/imgs/hz-tqm/...` — 华住质量管理 (TQM) 图片
- `https://htone.feishu.cn/docs/doccnBpUmKxQzqd6iCCs45iLbcb` — 飞书内部文档
- `https://test12dclog.ys7.com/` — 萤石云测试日志服务器

**结论**：CPIC AIoT 平台前端代码从华住酒店集团项目直接复制，未做域名/URL 隔离。
供应商可能是同一家（htone/合通？飞书租户名为 htone）。

### 4. API 网关发现
```bash
curl -k -s -I https://aiot.cpic.com.cn/gateway
# → 301 Location: http://aiot.cpic.com.cn:31006/gateway/   ← 泄露端口 31006

curl -k -s https://aiot.cpic.com.cn/gateway/
# → {"msg":"404 NOT_FOUND","code":500}   ← 确认后端存活
```

### 5. 接口探测
```
/gateway/api/user/login    → 401 {"code":401,"message":"非法请求,未携带token信息！"}
/gateway/api/user/register → 401 (同上)
/gateway/api/user/info     → 401 (同上)
/gateway/auth              → 401 {"msg":"访问此资源需要完全的身份验证","code":401}
```

两种不同的 401 格式说明网关后至少两套后端服务（业务系统 + Spring Security 认证）。

### 6. 路由枚举
从 Vue Router 提取出完整路由树，揭示该平台实际是一个**酒店质量管理系统**（工程检查、周检查、硬件检查、整改流程），与标题"智能物联网数据应用平台"的名头不完全匹配——进一步印证了代码复用。

### 7. 安全加固项
- Actuator 被 nginx 403 拦截
- .git 不可访问
- .env 等配置文件 404
- swagger-ui.html 403
