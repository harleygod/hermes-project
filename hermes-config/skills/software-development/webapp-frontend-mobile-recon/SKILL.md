---
name: webapp-frontend-mobile-recon
description: "Use when 前端SPA/APK侦察：接口发现、混淆JS还原、nginx绕过、帆软指纹、移动端信息提取。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, recon, frontend, apk, spa, js-obfuscation]
---

# 前端 SPA 侦察与移动端（APK）信息提取实战

Web 渗透中前端静态分析/移动端反编译的高价值技巧。适用于：SPA 站点接口发现、混淆 JS 还原、APK 敏感信息提取、绕过网关访问控制。与 web-pentest-methodology（方法论）互补，本技能聚焦前端/移动端侦察的实操细节。

## 1. SPA fallback 陷阱（判断真实 200 vs 假 200）

- nginx SPA 配置 `try_files ... /index.html`：**不存在的路径也返回 200**（内容是 index.html）
- 假 200 特征：Content-Length 固定（如 410B）、title 相同、下载后 `file` 类型是 HTML、`-o /dev/null` 显示 0B
- 接口真实存在的信号：404（Tomcat 404 页）、400、405、401、406 都比假 200 可信
- 探到"200 0B"先下载看一眼内容，别当成功也别当失败

## 2. API 前缀/网关发现

- 业务接口常不在页面同路径：抓最大的 JS（`chunk-vendors.js`）搜 `BASE_URL` / `baseURL` / `axios.create`——如 healthtpa 的 `BASE_URL:"/gateway"` 就是完整 API 前缀（接口实际是 /gateway/external/xxx 而非页面路径 /xxx）
- 页面路由路径（/xxx/login）≠ API 路径（/gateway/xxx/login）
- GET 被 fallback 吞掉时试 POST（nginx 可能按方法分流）；接口返回 405/406 提示存在但方法/Content-Type 不对
- 网关统一 401（如 /api/* 全 401）时找白名单例外（如 /api/auth 返回 200）——认证接口常漏在拦截外
- UmiJS 应用：页面业务代码在异步 chunk（`p__<route>__index.async.js`），umi.js 里只有路由表+框架；chunk map 在 umi.js 的 `{id:"p__xxx__index"}` 对象里

## 3. 混淆 JS 处理

- obfuscator.io（`_0x2a97f8(0x74a)` 十六进制表）：字符串在**单引号**大数组里，`re.findall(r"'([^'\\]{3,120})'")` 直接提取明文（注意它不用双引号，双引号提取结果可能为 0）
- babel-obfuscator base64 变体字符串表（乱码如 `5A+g56cb`）：手解成本高，直接浏览器自动化让前端自己执行
- 前端加密交互（请求/响应 `{"_rs":"base64密文"}`）：curl 硬刚不现实，浏览器方案是正路

## 4. computer_use 驱动浏览器填表坑（Windows）

- **set_value 不触发 Vue/React 的 v-model 事件**——值填了但校验看到的还是旧值（曾导致密码"强度太弱"误报）；必须真实键盘输入（click → 清空 → type）
- Chrome 的 key_combo（ctrl+a）和 scroll 后台驱动被拒（`background_unavailable`），单键 click/type 可用；组合键逐键处理或让用户手动
- 图形验证码/短信验证码：让用户看屏幕报码最快，Tesseract 对干扰验证码识别率低（实测 4 种预处理方法成功率仅 ~20-30%）
- cua-driver 会话会过期（list_apps 返回空/capture 报 session ended）——重新 capture 会自动建新会话

## 5. nginx 403 双斜杠绕过

- location 规则可被路径规范化绕过：`/path//xxx`（双斜杠）常绕过 `location /path/ { deny }` 类规则
- 实例：`/ability/webjars//springfox-swagger-ui/swagger-ui-bundle.js` 403→200；`/ability//admin/api/xxx` 403→到达后端
- 绕过后应用层可能还有兜底（统一返回业务异常 code），但规则缺陷本身可写报告；actuator 类独立规则双斜杠不一定有效

## 6. 帆软 FineReport/FineBI 版本区分

- `/WebReport/ReportServer` → FineReport 8/9（老 POC：`op=fr_base&cmd=evaluate_formula` + SQL ATTACH DATABASE 写 shell，武器库 POC 属于此类）
- `/webroot/decision/` → FineReport 10/11 或 FineBI（v11 插件体系，pluginId 含 `v11`）
- `/webroot/decision/v5/` 存在 → FineBI 6.x（CVE-2023-46079 getTableData 链）
- 版本指纹：`/webroot/decision/file?path=/com/fr/web/ui/fineui.min.js&type=plain&parser=plain` 注释泄露 `branch: final/11.0` + commit hash；登录页 `tag=` 时间戳
- 老版 POC 对 11.x 无效，先判版本再选 POC
- 11.x 未授权接口：`/login/config`（LDAP/AD 字段 fWords）、`/login/password/strategy`（密码策略）、`/login/slider/info`（滑块 JWT，HS256 密钥随机时不可伪造）
- WAF 常拦 `/WEB-INF/`、`/etc/passwd`（阿里云盾 405 页/断连）

## 7. APK 反编译信息提取（信息泄露水洞）

- 流程：下载 APK（zipfile 解包）→ classes*.dex → `re.findall(rb'[\x20-\x7e]{6,}', data)` 提取 ASCII 字符串 → grep 域名/IP/接口/密钥
- **Flutter App 业务代码在 `lib/arm64-v8a/libapp.so`，不在 classes.dex**（dex 只有框架壳）——对 so 文件提字符串
- 重点提取：内部域名（`*.cpic.com.cn` 类）、内网 IP（10.x/192.168.x）、公网老系统 IP:port、`/api/...` 接口路径、`.json` 配置 URL
- **供应链线索**：配置从第三方域名拉取（gitee.com 公开仓库、第三方 API）→ 抓配置常有意外收获（机构列表、内网 IP、多环境域名）；应用市场包名 `com.example` 是第三方开发/测试包信号
- 新域名必测：DNS 解析 + 常见端口 TCP 扫描，区分 防火墙 DROP（超时）/ refused / 握手后切断（发数据被 RST=安全网关应用层过滤）；报告写实测结果比"内网不可达"可信
- 串行扫端口会超时，用 ThreadPoolExecutor 并行（20 线程 + 2s 超时，38 端口约 1 分钟）

## 8. 报告交付

- 金管局检查报告模板：`references/jinguanjian-report-format.md`
- 多客户/多子公司目标按公司分组出独立报告文件
- 每个漏洞列出完整可访问地址（URL/接口/IP/域名）+ 证据文件路径 + 复现步骤
- 生成 docx：docx-js（npm install docx --legacy-peer-deps），宋体 SimSun 24（12pt），表格 WidthType.PERCENTAGE，生成后验证（zip 结构 + 关键内容 grep）

## 输出铁律

- 只出能拿权限/信息的漏洞，不写修复建议（金管局模板需填整改建议栏目时除外）
- 每条漏洞：URL + 数据包 + 截图
- 写接口（删除/重置/修改）一律不探测；添加类接口需用户明确授权
