---
name: web-js-recon
description: "JS recon: URL leaks, API discovery, vendor exposure."
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, web, js-analysis, recon, info-leak, supply-chain]
---

# Web JS 静态分析 — 信息泄露侦察

前端 JS 文件（主 bundle + chunk）是黑盒渗透最容易被忽略的信息金矿。

## 触发条件

- 打任何一个 Web 目标的登录页之前
- SPA（Vue/React/Angular）应用必做
- 发现目标只有 nginx/Apache 默认页 → 先拉 JS 分析再下结论

## 1. JS 文件收集

```bash
# 从首页 HTML 提取所有 JS 引用
curl -k -s "$SITE" | grep -oP 'src="([^"]+\.js[^"]*)"' | sort -u

# 下载主 JS bundle
curl -k -s "$SITE/js/app.*.js" -o app.js

# 从 webpack bootstrap 提取 chunk hash 映射
grep -oP '"chunk-\w+":"[a-f0-9]+"' app.js | sort -u

# 逐个下载 chunk（不要并行 — Windows git-bash 不支持 &）
while IFS=: read -r name hash; do
  curl -k -s "$SITE/js/$name.$hash.js" | analysis_pipeline
done < chunks.txt
```

## 2. 供应链/供应商泄露检测

```bash
# 提取所有完整 URL，过滤 CDN/公共库
grep -oP 'https?://[a-zA-Z0-9._-]+(:\d+)?/' app.js | sort -u | \
  grep -v 'alicdn\|mapbox\|map\.baidu\|bdimg\|npmjs\|github\|axios'

# 提取 JSON 字符串中的 URL
grep -oP '"[a-z]+://[^"]+"' app.js | sort -u
```

**关注信号**：

| 发现 | 含义 |
|------|------|
| 非目标企业的域名 | 供应商/客户内部系统泄露 |
| `10.x` / `192.168.x` / `172.16-31.x` | 内网拓扑暴露 |
| `test*.xxx.com` / `dev*.xxx.com` | 测试/开发环境 |
| COS/OSS bucket URL | 云存储 — 尝试列目录 |
| 飞书/钉钉/企微文档 | 内部协作内容 |

**真实案例**：CPIC (aiot.cpic.com.cn) 前端 JS 中发现华住酒店内部 CRM、OMS API、飞书文档、萤石测试日志 — 代码从华住项目直接复制，供应链信息泄露。详见 `references/aiot-cpic-supply-chain-leak.md`。

**真实案例 2**：CPIC (hkb2b.cpic.com.cn) uni-app 前端通过 FindSomething 扩展发现 10 个 API 端点，逆向 request.js 获得签名豁免白名单和认证 header 格式，定位两个 IDOR 候选端点。详见 `references/hkb2b-cpic-api-discovery.md`。

## 3. API 端点发现

```bash
grep -oP '(baseURL|BASE_URL|apiUrl|VUE_APP_\w+)\W*[=:]\W*["\x27][^"\x27]+["\x27]' app.js
grep -oP '"/api/[a-zA-Z0-9/_-]+"' app.js | sort -u
grep -oP '\.(get|post|put|delete)\s*\(\s*["\x27][^"\x27]+["\x27]' app.js | sort -u
```

## 4. API 网关发现 — 末尾斜杠差异

```bash
for p in api gateway prod-api api-gateway bff; do
  curl -k -s -I "$SITE/$p"        # 无斜杠 → 看 Location 头
  curl -k -s "$SITE/$p/"          # 有斜杠 → 看 JSON 响应体
done
```

- `/gateway` → 301 重定向到 `http://xxx:31006/gateway/` → **泄露后端端口**
- `/gateway/` → 返回 JSON 错误 → 确认后端存活
- CSP 头中 `connect-src ... :31008 :31009` 也是端口线索

## 5. 网关响应指纹

不同错误格式 = 不同后端服务：

| 响应格式 | 技术栈 |
|---------|--------|
| `{"timestamp":"...","status":404,"error":"Not Found","requestId":"..."}` | Spring Cloud Gateway |
| `{"code":401,"message":"非法请求,未携带token信息！"}` | 业务后端 |
| `{"msg":"访问此资源需要完全的身份验证","code":401}` | Spring Security |

**多种 401 格式 = 多套后端**，可分别尝试绕过。

## 6. 未授权接口快速枚举

```bash
for ep in \
  api/user/login api/user/register api/user/info \
  api/captcha api/public/key api/sms/send swagger-resources doc.html; do
  body=$(curl -k -s "$SITE/$GATEWAY/$ep")
  echo "$ep → $body"
done
```

- `401 未携带token` → 接口存在 → 找注册或绕过
- `404 Not Found` (Spring JSON) → 不存在
- `403` (nginx HTML) → nginx 拦截，非后端拒绝

## 7. 路由枚举

```bash
grep -oP 'path\s*:\s*"[^"]*"' app.js | sort -u
```

揭示隐藏页面、未在导航中出现的管理功能。

## 8. 浏览器扩展辅助（FindSomething）

安装 FindSomething Chrome 扩展后，用 `computer_use` 点击扩展图标即可一键提取：
- 所有 domains/URLs
- API paths (包括 chunk 里的)
- 敏感信息（JWT/secret/key/password）
- Vue 路由列表
- 静态资源路径

省去手动下载所有 chunk 的步骤，适合快速初筛。

## 9. 发现 userId 参数 → 启动 IDOR 猜解

JS 中一旦出现 `?userId=` 或 `?userId:` 参数模式，说明开发者习惯用 URL 传参做权限判断。此时**不限于 JS 已暴露的接口**，按 MVC/REST 约定猜：

```bash
# 假设已知 /api/profile/info?userId=，猜其他
for ep in \
  api/user/info api/user/detail api/user/profile \
  api/order/list api/order/detail api/policy/list api/policy/detail \
  api/address/list api/vehicle/list api/certification/info; do
  echo -n "$ep: "
  curl -k -s "$SITE/$ep?userId=1001879" | head -c 200
done
```

**关键**：GET 接口通常只需 header token 不需要签名，一旦拿到有效 token 即可全量测试。

## 10. 认证弱点 — 豁免签名白名单

JS 中常出现"以下接口不走签名"的数组 — 这些是攻击面：
- 发送验证码、登录接口 → SMS 轰炸、暴力破解
- 提交认证接口 → 如果 userId 在 URL 上 → IDOR
- 签名接口本身 → 可伪造签名

```bash
# 搜签名豁免列表
grep -oP '\["[^"]*"[^]]*\]' request.js | grep -i 'api'
```

**真实案例 3**：CPIC 三站前端侦察（wxcd 低代码平台 / aiuavs 无人机 / resmanage 资源共享平台）— SPA fallback 陷阱、obfuscator.io 混淆提取、UmiJS 异步 chunk、加密响应转浏览器、APK 字符串挖掘。详见 `references/cpic-frontend-recon.md`。

## 11. SPA fallback 陷阱 — 区分真实端点与静态兜底

nginx history 模式 SPA 对**任何不存在的路径**都返回 200 + index.html（不是 404）。
`curl -o /dev/null -w "%{http_code}"` 的 200 全是假象，会浪费大量时间（tmui/login.jsp、manifest.json、/geoserver/rest/、/swagger-ui.html 全假 200）。判断真实端点：

```bash
# 1. 看 Content-Type 和 body 长度：410B 左右 + text/html = fallback
curl -skI "$SITE/anypath" | grep -iE 'content-type|content-length'
# 2. 看 body 是否含前端骨架（<div id=root> / <script src=umi.js> / <title>...平台</title>）
curl -sk "$SITE/anypath" | head -c 300
```

- 与真 404（nginx `<title>404 Not Found</title>`）对比：fallback=200，真 404=404
- **真实后端的信号**：非 HTML Content-Type（application/json、image/*）、业务错误码（400/401/500 而非 200）、专用错误页标题（如 GeoServer "GWC Error"）
- **405 Method Not Allowed = 接口存在但方法不对**：换 POST/GET 再试——实测 Spring 系接口 GET 405 时 POST 可能未授权可调（healthtpa `/gateway/external/admin/getSystemInfo` GET 405 → POST 200 返回数据）；nginx 405 页（`<title>405 Not Allowed</title>`）与业务 JSON 405 要区分
- `-w %{size_download}` 对 fallback 可能显示 0B（压缩统计问题），别据此判断
- 下载 chunk 返回 fallback HTML（而非 JS）= 该 chunk 未部署/资源缺失 → 该功能线关闭
- **401/白名单探测**：网关对 /api/ 下所有路径统一 401 时无法区分存在性；扫出返回 200 的路径（如 /api/auth）= 网关白名单，从那里切入

## 12. 混淆 JS 提取（obfuscator.io 系）

`_0x2a97f8(0x74a)` 风格 = obfuscator.io 字符串表混淆。字符串表在文件里是明文，可直接提取：

- **用单引号提取**：a0_0x 混淆器把字符串存为单引号数组（双引号可能为 0 个，先 `js.count('"')` 确认）
```python
import re
strs = re.findall(r"'([^'\\]{3,120})'", open('app.js',encoding='utf-8',errors='ignore').read())
# 再按关键词过滤: http /api login register sms token password mobile captcha
```
- chunk 可能用 base64 变体表（如 `5A+g56cb` 是中文"验证码"的换表 base64）→ 手解成本高，直接用浏览器跑页面
- 请求封装里 `_0x...(0x601)` 拼接 URL 的，搜 `url:`/`method:` 附近的字面量片段；`VSEHmydo:password` 这类拼接串可能是测试账号格式

## 13. UmiJS 异步 chunk 挖掘

UmiJS 单文件 umi.js 只有框架+路由表，**业务 API 在异步 chunk**（`p__{route}__index.async.js`）：

```bash
# 1. 从 umi.js 找 chunk map（webpack runtime）
grep -oE '\{[0-9]+:"p__[a-z-]+__index",?' umi.js
# 2. 直接下载：/p__download__index.async.js、/p__shed-loss__index.async.js ...
curl -sk "$SITE/p__download__index.async.js" -o chunk.js
# 3. chunk 里 grep API 路径、地图/瓦片 URL 模板、环境切换逻辑
cat p__*.async.js | grep -oE '"/[a-zA-Z0-9_/?=&.-]{3,70}"' | sort -u
```
- 路由表本身泄露功能面（fly-route/shed-loss/ndvi-loss = 农业无人机查勘定损），指导后续 API 猜测
- 环境切换逻辑（`x()==="SIT"?"https://xxx-sit...":"https://xxx-dev..."`）泄露 dev/sit/第三方环境域名，逐个探测公网可达性
- 前端地图 URL 模板（如 TMS `/geoserver/gwc/service/tms/1.0.0/{layer}@EPSG:900913@png/`）→ 探测 GeoServer/瓦片服务

## 14. 加密响应 → 别破密，上浏览器

接口响应为 `{"_rs":"base64..."}` = 前端自研加密（AES-CBC + 运行时密钥 + 全量混淆）。破解成本 >> 价值：

- 直接用 computer_use 驱动桌面 Chrome 操作页面（填表单、过验证码、登录），前端自己加解密，F5 等网关的防爬也一并绕过
- 需要观察流量时用浏览器 DevTools/抓包，不要手搓解密脚本
- 前提：目标允许浏览器交互（注册/登录/翻页类任务）；用户已开好表单时直接接手，不要重复下载工具

### 14.1 computer_use 填表 pitfalls

- **set_value 不触发 Vue v-model 事件**：AXValue 设置后 Vue 表单校验仍报"格式错误/强度不足"（字段值为旧值/空）——注册密码框 set_value "Abc@123456" 仍报错就是这个原因。真实键盘输入（click 聚焦 + type）才触发 input 事件
- Chrome 后台模式限制：key_combo（ctrl+a）和 scroll 不可用（background_unavailable → 前台也被 Windows 焦点锁拒），click/type/set_value 可用
- 清空输入框：click 聚焦 → 多次 key 'backspace'（单键可用）→ type 新值
- 图形验证码：vision 接口不可用时让用户报验证码（用户就在电脑前），或截取图片区域本地 OCR

## 15. APK 字符串挖掘（移动端配套侦察）

低代码平台/应用商店泄露 APK 后，dex 字符串提取是硬编码凭据/内网地址的金矿：

```python
import zipfile, re
z = zipfile.ZipFile('app.apk'); [z.extract(n) for n in z.namelist() if n.endswith('.dex')]
data = open('classes.dex','rb').read()
strs = re.findall(rb'[\x20-\x7e]{6,}', data)
open('strings.txt','w').write('\n'.join(s.decode('ascii') for s in strs))
# 然后 grep: 域名(.cpic.com/.com.cn) 内网IP(10./172./192.168) http(s):// URL 接口路径
```
- 多个 APK 出现相同域名 = 共享 SDK/框架，证据互相印证
- 关注：`/api/w/.../get-token` 类取 token 接口（需合法 token 时价值低）、pass/v2/register 类注册路径、push/dev/sit 三环境域名
- 反编译工具本地常备：jadx-gui / jd-gui（D:\Pentest\反编译工具\）；纯字符串挖掘不需要完整反编译
- 一键脚本：`scripts/extract_apk_strings.py app.apk 输出目录`（自动处理 dex + Flutter libapp.so，并提示供应链配置线索）

### 15.1 Flutter APK：字符串在 libapp.so 不在 dex（taibao_sale 案例）

Flutter 开发的 APK（特征：assets 有 flutter_assets/、依赖 sqflite、包名常带 com.example 测试标记）**classes.dex 里几乎没有业务字符串**，业务代码编译进 `lib/<abi>/libapp.so`：

```python
import zipfile, re
z = zipfile.ZipFile('app.apk')
data = z.read('lib/arm64-v8a/libapp.so')
strs = re.findall(rb'[\x20-\x7e]{8,}', data)
# 再 grep https?:// 域名 gitee/github raw 配置
```

- 判定 Flutter：`z.namelist()` 里有 `lib/arm64-v8a/libapp.so` + `libflutter.so`
- 只提取 arm64 即可（32/64 位内容重复）

### 15.2 供应链配置 URL → 公开仓库泄露（重点模式）

App 内出现第三方域名/配置 URL 时，**直接拉取配置本身**——第三方开发商常把配置放公开渠道：

- 例：App 内 `https://gitee.com/{vendor}/sale-api/raw/master/xxx.json` → 公开 Gitee 仓库直接返回机构配置，泄露合作方内网 IP（192.168.x）、公网服务器（114.215.x）、多环境域名（prod/sit 全套）
- App 内更新接口 `http://{第三方域名}/ccrc_taibao.json` → App 更新配置（版本/强制更新/下载 URL）
- 隐私协议链接指向第三方域名（如 www.zjwawl.com）= 开发商身份线索
- 结论：**第三方开发商 App 的配置泄露 = 供应链信息泄露**，内网 IP + 合作方环境域名都可复现验证，是能交差的硬信息泄露

## 16. 泄露域名的资产验证（CNAME / 真实 IP / 存活语义）

JS 挖出的 dev/sit/uat/内网域名不要直接标"不可达"就完事，逐个做三层验证，结论完全不同：

```bash
# 1. DNS 解析 + CNAME 链（别名本身泄露接入架构）
nslookup xxx.cpic.com.cn     # CNAME → xxx.sjgtm.cpic.com.cn = 集团 CDN/网关别名
# 2. 常见端口 TCP 探测（不依赖 HTTP）
python3 - <<'EOF'
import socket
for port in (80, 443, 8080, 7001, 31003):
    s = socket.socket(); s.settimeout(3)
    try: s.connect((ip, port)); print(port, "开放")
    except Exception: pass
    finally: s.close()
EOF
# 3. HTTP 语义确认
curl -skI "https://$host/"   # 502/503 = 网关在线后端故障（活资产）；000/超时 = 防火墙丢包
```

- **DNS 可解析 + 端口全关** = 公网资产段存在但防火墙全封（如 101.204.252.x），记录为"公网可解析资产段"
- **502/503 页** = 网关/nginx 在线，后端故障 —— 活资产，后端恢复后可再测（lf21sbib-jhs 案例：443=nginx 502、80=503，TCP 80/443 开放）
- **000 立即失败**（0.03s 内）= DNS 解析失败 = 真内网域名
- **000 超时**（6s+）= DNS 可解析但 TCP 被防火墙丢弃
- 响应头与域名访问完全一致 = 无 CDN 前置，该 IP 即源站（绕 WAF 的"真实 IP"无意义，WAF 在应用层）
- 同网段聚类：多个域名解析到同段（如 103.230.110.x/111.x）说明是集中网关段

## 17. 帆软（FineReport/FineBI）专项

见 `references/fanruan-finereport.md`：版本指纹 → 版本与漏洞面映射 → 未授权接口清单 → WAF 拦截特征 → 滑块 token 分析。

## 注意事项

- `curl -k` 忽略自签证书
- SPA fallback 200 陷阱见第 11 节：任何路径都可能假 200，先看 Content-Type/body 再下结论
- 混淆 JS 用单引号提取字符串（第 12 节），双引号提取会得到 0 结果
- Windows git-bash 下 `/tmp` 不可写，用 `$HOME/tmp_js/` 或管道直接分析
- 本 skill 是"前端侦察"层；拿到接口清单后的验证/利用流程见 web-pentest-methodology
- **验证码 OCR**：先下图片看尺寸（160x40 左右 = 4 位验证码），Tesseract 直接识别乱码 → 预处理：灰度 → 中值滤波/锐化 → 二值化 → 放大 4 倍（LANCZOS）→ `--psm 7` + 白名单 `tessedit_char_whitelist`。识别率仍低（干扰线强）就放弃爆破，改为人工配合或换目标
- **代理排查（socks5 vs socks5h）**：认证通过但 connect 阶段挂起/超时（连代理自身 IP 都超时）→ 换 `socks5h://`（远程 DNS）模式立即可用；`curl -x "socks5h://user:pass@host:port"`。现象：TCP 通 + 手动握手 05 02 → 01 00 认证成功 → connect 无应答
