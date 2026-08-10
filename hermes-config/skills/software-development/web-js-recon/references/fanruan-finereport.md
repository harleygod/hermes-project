# 帆软（FineReport / FineBI）黑盒渗透速查

帆软是国内保险/银行/政企最常见的 BI/报表产品，路径特征是 `/webroot/decision/`（10.x/FineBI）与 `/WebReport/`（8-9 老版本）。武器库常备 POC 多为老版，**版本不匹配会全打空**，必须先指纹。

## 1. 版本指纹（先做）

| 指纹来源 | 方法 | 判读 |
|---------|------|------|
| 登录页资源 | 页面引用的 fineui.min.css / login.bi.min.css | login.bi.* = FineBI 特征 |
| 构建注释 | file 接口读 `fineui.min.js`，注释头有 `branch: final/11.0; commit: xxx` | 精确到分支+构建时间 |
| 插件 ID | 页面 script 引用的 `pluginId=com.fanruan.fs.s3.repository.v11` | v11 = FineReport 11 插件体系 |
| 信创插件 | 页面引用 migration 插件（gauss200/kingbase/oceanbase/tidb/opengauss） | 新版（信创适配），老洞大概率已修 |
| 路径探测 | `/webroot/decision/v5/...` 404 vs `/webroot/decision/...` | v5 = FineBI 6.x 接口；404 = 非 FineBI6 或已移除 |

## 2. 版本 → 攻击面映射

| 版本 | 路径 | 可用攻击面 |
|------|------|-----------|
| 8.0-9.0 | `/WebReport/ReportServer` | `op=fr_base&cmd=evaluate_formula` + SQL ATTACH DATABASE 写 JSP（武器库 fanruan_fr_rce.py） |
| 10.x | `/webroot/decision/` | 历史任意文件读取/上传链（2024 前） |
| 11.0（2024 后） | `/webroot/decision/` | 老洞全修；未授权配置接口仍可读（见下） |
| FineBI 5.x | `/webroot/decision/remote/design/saveRemoteDesignResource` | RCE 链 |
| FineBI 6.x | `/webroot/decision/v5/design/optimize/control/getTableData` | CVE-2023-46079 未授权 RCE（2025 新版已修/移除） |

## 3. 未授权可读接口（11.0 实测有效）

```
GET /webroot/decision/login/config            → 登录配置，含 LDAP/AD 字段(fWords: sAMAccountName/cn/userPrincipalName/uid/displayName...)
GET /webroot/decision/login/password/strategy → 密码策略（长度/符号/定期更新/初始密码强制改）
GET /webroot/decision/login/slider/info       → 滑块验证码 JWT(HS256) + imageId
GET /webroot/decision/file?path=/com/fr/...&type=plain|class&parser=plain → classpath 资源读取（版本/常量）
```

- 这些接口即使未授权，也是"登录配置/密码策略/认证架构"级信息泄露，可直接交差
- `login/usernames`、`login/captcha`、`login/admin` 常被 WAF 拦（见下）

## 4. WAF 拦截特征（实测）

| 请求 | 现象 | 判断 |
|------|------|------|
| `/webroot/decision/file?path=/WEB-INF/web.xml` | 阿里云盾风格 405 错误页（`saved from url=...1.mdb`） | WAF 拦 WEB-INF |
| `path=/etc/passwd` 或 `..%2f` 穿越 | 000 断连 / 空白错误页 | WAF 断连 |
| `POST /webroot/decision/login` | 拦截页 | 登录防爆破规则 |
| 正常资源请求 | 正常返回 | WAF 只拦敏感特征 |

绕法：`WEB-INF` 大小写/无前导斜杠/`%2f` 编码都无效（新版本 file 接口本身也只支持 classpath）。**别在文件读取上死磕**，转未授权配置接口。

## 5. 滑块验证码 token（JWT）

- `slider/info` 返回 `sliderToken`：HS256，payload `{"iss":"fanruan","iat":..,"exp":..,"sub":"imageId#imageId2","jti":".."}`
- 验签方法（本地，不碰目标）：`hmac.new(secret, b"h.p", sha256)` 对比签名，先试 fanruan/finebi/secret/123456 等弱密钥
- 实测弱密钥未命中（随机生成）→ 伪造路不通，放弃滑块绕过

## 6. 登录接口

- `POST /webroot/decision/login`（JSON username/password）—— 生产环境被 WAF 拦 POST 时，`/webroot/decision/authentication` 302 是通用认证入口
- 登录成功后的 RCE 链：插件上传、定时任务（`/webroot/decision/v5/api/...`）—— 需要合法账号，未授权进不去就到此为止

## 7. 经验

- 新版本（2025 构建）帆软：公开 RCE 基本打不动，价值点 = 未授权配置接口信息泄露 + 登录侧（滑块/弱口令，爆破需授权）
- 武器库 POC 有版本局限：用之前先比对目标路径（`/WebReport/` vs `/webroot/decision/`）和构建时间
- 帆软数据源配置在 11.x 存在内置/外部数据库而非 datasource.xml，读 datasource.xml 拿密码的老思路不适用
