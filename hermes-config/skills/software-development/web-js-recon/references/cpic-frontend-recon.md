# CPIC 前端侦察案例（wxcd / aiuavs / resmanage / healthtpa / 寿险供应链）

2026-08 对太平洋保险（cpic.com.cn）多目标的 JS 侦察记录。技巧层面已提炼进 SKILL.md 第 11-16 节，这里是具体路径、响应特征和坑。

## 目标 1: wxcd.cpic.com.cn — 太保应用资源平台（Vue SPA）

入口：用户提供的一批 `install.html?appId=NNN` 链接。

- 首页/子路径 403/502 但 body 是完整应用 HTML（网关状态码与 body 不一致，别只看状态码）
- **未授权接口**：`GET /ability/api/ability-application-resource/page?current=1&size=500`
  零认证返回全部应用资源：包名、版本、APK/IPA 下载地址、开发者用户ID（100038x 编号）、发布备注
- 其他 `/ability/api/{module}/{resource}/page` 猜测全部返回 `{"code":10004,"msg":"系统服务异常"}`（兜底异常，非 404）→ 只有放行的接口可用，猜测无效
- `/ability/swagger-ui.html` 200（springfox 2.10.5 静态 webjars），但 `/ability/swagger-resources`、`v2/api-docs` 被网关拦（返回业务 JSON）
- 前端 JS 泄露：`cxwx-dev/sit.cpic.com.cn`、`wechat.property.cpic.com:31003`、`wechat-dev.property.cpic.com`（公网全部超时 = 内网）
- `admin/manage/publish/upload.html` 是**另一个应用**（"太平洋产险"标题，时间戳 chunk 名 `app1780999884626...`），但 chunk-vendors 下载返回 fallback HTML = 资源未部署，攻击面关闭
- CDN `wxcd.cpiccdn.com`：目录列举 403，`..%2f` 405，但具体文件 URL 可直接下载
- APK 反编译（E动专享赔 26MB、财富U保 45MB）→ dex 字符串挖出：
  - `wxcd.cpic.com.cn/api/w/ability/link/get-token`（POST 空 body 返回业务响应"token 不存在"，带 `{"token":"abc"}` 返回"token 过期"→ 是 token 校验接口，无合法 token 无法利用）
  - 内网域名 9+ 个（td/td-sit/zjxlft/pushdev/pushsit/cmpsit.ecpic.com.cn 等，公网 DNS 均不存在）
  - 内网 IP `10.38.162.35:9085`、公网老系统 `202.108.103.163:7001`

## 目标 2: aiuavs.cpic.com.cn — 农业无人机查勘定损系统（UmiJS SPA）

- F5 BIG-IP：`BIGipServerPT21UAVS_produce_WEB_HTTPS_443_POOL_10` cookie 泄露后端池名（新版值已加密，解不出 IP，但池名是明文信息泄露）
- `/checkHealth` → `health ok`（无认证探活）
- 响应头 `Apptrace-TraceID/SpanID` = SkyWalking APM 追踪 → 技术栈指纹
- **SPA fallback 全覆盖**：`/tmui/login.jsp`、`/geoserver/rest/`、`/manifest.json`、`/umi.js.map` 全是 200 + index.html；只有 `/geoserver/gwc/service/tms/1.0.0/` 返回 400（GWC Error 页面）暴露真实 GeoServer GeoWebCache
- GeoServer 面：WMS/WFS/ows 全被 nginx fallback 挡，仅 TMS 可达；图层名动态获取（枚举 uav/drone/tb/map 全 Unknown layer）
- `/api/` 网关统一 401（"令牌失效，请重新登录"），无法区分路由存在性；**唯一白名单 `/api/auth` 200**
- `/api/auth/login` 存在：username→password→captcha 逐级校验，验证码字段名试了 captcha/code/verifyCode/captchaId/uuid 全"验证码不能为空"；`/api/auth/captchaImage` 等 500（后端验证码服务异常，但校验仍激活）
- UmiJS chunk map：`{79:"p__block-division-new__index",80:"p__shed-loss__index",...}` → 16 个页面 chunk 全部 `/p__xxx__index.async.js` 可下载，业务 API 只在 chunk 里：
  - `/ability/api/ability-application-resource/checkUpdate`（同 wxcd 的 ability 服务）
  - `/dronetb/api/restBuildPathplan?version=1000`、`restBuildSamplePathplan`
  - `/api/restTdiKey?version=100`、`/api/restIstdtenable?version=100`（全 401）
  - 环境切换逻辑泄露：`aiuavs-dev.cpic.com.cn`（不可达）、`aiuavs-sit.cpic.com.cn`（不可达）、`aiuavs-sjyz.cpic.com.cn`（DNS 无）、**`sh2.iearthtime.com:8095`（外部第三方环境，可达！同构部署，`/dronetb/api/auth/login` 同样验证码保护）**
- 结论：登录验证码挡住、API 全 401、TMS 图层未知 → 无可利用入口，挂起

## 目标 3: resmanage.cpic.com.cn — 资源共享管理平台（Vue + ElementUI，F5 PT20VCTPMS 池）

- 注册页真实表单字段：资源类型(下拉)/登录账号/密码/确认密码/联系人姓名/联系人手机号/统一社会信用代码(+OCR营业执照)/邮箱/图形验证码/手机验证码/隐私协议
- 密码规则提示：大小写+数字+特殊字符，8-16 位
- **app.js 是 obfuscator.io 混淆**（a0_0x 系列，字符串全单引号，双引号仅 5 个）；chunk 是 base64 变体表混淆（`5A+g56cb`=验证码）
- 单引号字符串提取挖出：
  - 接口：`/ext/login/mobile`、`/ext/login/register`、`/ext/v2/login/sendNewCheckCode`（注册/登录走 /ext/ 独立网关）
  - 疑似测试凭据串：`VSEHmydo%3Apassword`（url 解码 `VSEHmydo:password`，非 base64，疑似 username:password 拼接格式）、`Password123!`
  - 登录后接口前缀 `/rm/res/v2/`：`bUserManage/saveAccountInfo`、`bUserManage/checkSafePars`、`bUserManage/queryAgreeAuthority`、`baseInfoOut/findServiceableArea`、`extExclude/uploadImage`、`extExclude/examineImage`
- **所有 /ext/ 接口响应加密**：`{"_rs":"base64..."}`，AES-CBC + 运行时密钥（vuex getters）+ ZeroPadding → 放弃 curl 手搓，改用 computer_use 驱动桌面 Chrome 操作注册表单
- 注册流程卡点：图形验证码 + 手机短信验证码（短信发到用户手机，需人工中转）

## 目标 4: healthtpa.cpic.com.cn — 责意险作业平台（Vue，Ant Design Pro）

- 前端 app.js 未混淆，92 个接口路径直接可见，API 前缀 **`/gateway`**（chunk-vendors 里 `BASE_URL:"/gateway"`）；泄露内部云盘 `clouddisk-gp19peicp.group.cpic.com`
- 未授权接口（读）：`GET /gateway/external/admin/slideCaptcha`（无限获取图形验证码 base64）、`POST /gateway/external/admin/getSystemInfo`（GET 405 → **POST 200** 返回系统信息，Spring 系接口方法敏感）
- **写接口全部 401**（users/add、sysCode/add、comment/add、impairment/saveImpairment、evidence/upload、users/edit、users/resetPwd 全部 `000401 未授权`）——读/写鉴权分离，写接口防护到位
- 登录：`POST /gateway/external/admin/login` 参数 `username/password/captcha`（先试 phone/account/loginName 全"用户名或密码错误"，username 才触发"验证码为空"）；统一错误"用户名或密码错误"无用户枚举
- `POST /gateway/external/admin/sms/loginSend` 未授权可达（需图形验证码，"图形验证码错误"）
- 验证码 OCR：160x40 JPEG，干扰强，Tesseract 灰度+二值化+放大 4 倍后识别率仍低（约 20-30%）→ 放弃爆破
- 报告时写接口 401 是"正面结论"（防护到位），不要硬测——用户红线：删除/重置/修改类接口一律不碰

## 目标 5: taibao_sale.apk — 小米市场"太保销售App"供应链泄露（重点案例）

- 包名 `com.example.taibao_sale_app`（com.example = 测试/第三方标记），19.8MB
- **Flutter App**：classes.dex 几乎无业务字符串（只有 sqflite/tika 库引用）；业务字符串全在 `lib/arm64-v8a/libapp.so`（8.5MB，19706 字符串）
- libapp.so 挖出供应链链：
  1. `https://gitee.com/hzaxun/sale-api/raw/master/taibaosale.json` → **公开 Gitee 仓库返回机构配置**：内网 IP `192.168.110.57:8081`（local）、公网 `114.215.183.66:8083`（颐养通）、4 个合作域名（yltzwx / yltzwxtest-sit / ytyuyue / ytyuyue-sit .cpic.com.cn）
  2. `http://zhyly_api.yytong.com/ccrc_taibao.json` → App 更新配置（version/force/下载 URL）
  3. 隐私协议 `www.zjwawl.com` → 开发商身份（浙江万威隆）
- 实测：ytyuyue.cpic.com.cn（103.144.66.104）在线但全路径 403（IP 白名单）；其余不可达
- 结论：第三方开发商公开仓库泄露合作方资产 = 可复现的供应链信息泄露，直接进报告（重点漏洞）

## 目标 6: 寿险下载页批次（m25 / lf21sbib / dlsx / stkb / hkapp）

- m25（智慧团险）：`kjtxUtils.js` 泄露环境切换/签名开关 localStorage 键（`KJTX.ENVIRONMENTAL`/`KJTX.sign`/`KJTX.isDebug`）+ 未授权接口 `kjtx/main/api/utils/environmentName`（200）、`appVersion/checkVersion`（400 缺参，type 为枚举猜不出）
- lf21sbib（营销 H5）：6 个 API 域名，网关 `lf21sbib-jhs.cpic.com.cn`→103.230.110.148 **TCP 80/443 开放**（443=nginx 502、80=503，网关在线后端故障）；API 格式 `/route/rest/{module}/{action}`
- dlsx（太好钉+）：泄露 OSS 桶 `delivery-platform-online/daily.oss-cn-beijing.aliyuncs.com`——online 列举 AccessDenied；daily 静态网站模式（公共读但列举被 index.html 吞）
- stkb（双录通）：HTML 注释泄露内网更新域名 `sxtbupdate.cpic.com.cn`
- hkapp（太保香港）：APK 泄露 dev/sit/uat 环境域名 + 保单接口 `/policy/pdf_file_get_download`（未认证统一 406 网关拦截）
- 域名资产验证：cxwx-dev/sit、pushsit 解析到 101.204.252.x——80/443 等 35 端口 DROP、**25/110/143 邮件端口 TCP 握手成功但发数据被切断**（WinError 10053）= 太保邮件/安全网关段，非白名单来源不可用；xizbi 源站 103.230.111.60 与域名响应头一致 = 无 CDN，WAF 在应用层

## 通用教训

1. 状态码 200 不可信（SPA fallback），先看 Content-Type 和 body 特征
2. 网关统一 401 时，白名单路径（200）是唯一入口
3. 混淆 JS 用单引号提取；base64 变体表不手解
4. 加密 API 用浏览器自动化（computer_use）而不是破密
5. APK dex 字符串 = 硬编码端点金矿，多个包互相印证
6. 环境切换三元表达式 = 内部环境域名清单
7. 用户给的清单先逐站分析完再定点打；一个站没入口就换下一个，不恋战
