# 泛微 e-cology /dispatch/invoke 反序列化 0day 操作案例（2026-08）

状态：用户定性 0day，payload 数据严禁外传（只留 `D:\Pentest\攻防\武器库\泛微oa漏洞\`，不上传/不搜索/不入公共渠道）。载荷静态取证方法见 `java-deserialization-payload-forensics.md` 第 8 节。

## 漏洞要点（一句话）

e-cology 远程调用分发器 `/dispatch/invoke/{类}/{方法}` 对 `_SYS_ARGS.value`（base64 序列化流）做反序列化；声明调无害静态方法（`java.lang.String/copyValueOf`）作"过桥"，**类型错配（声明 String、实际传 [B）就是漏洞点**。CB1 链 → TemplatesImpl → 恶意 translet 写 `{webroot}/static/static.jsp`（AES 内存马加载器，密钥 `1a1dc91c907325c6`，POST base64→AES 解密→defineClass→内存马）。

## 版本适用（从载荷推，非官方，别空口断版本表）

- 硬约束：JDK ≤8（载荷引用 `sun.misc.BASE64Decoder`，JDK9+ 删除）；classpath 需 commons-beanutils + commons-collections（CB1）+ jackson-databind（translet 借 `POJONode` 的 CodeSource 反推 webroot）；标准 WEB-INF 布局
- e-cology 8/9 典型部署（Resin+JDK8）大概率满足；e-cology 10 待实测
- **版本混合部署常见**：根页 `_wev8.js`（8 风格）+ `/wui` cloudstore SPA（9+）可同时存在（zlq 案例），指纹要 OR 不要互斥

## 指纹查询集（圈资产用）

FOFA 主查询：
```
(header="ecology_JSessionid" || body="/wui/index.html" || body="cloudstore/resource/pc/com/v1") && country="CN"
```
- `header="ecology_JSessionid"`：登录响应 Set-Cookie，最硬几乎无误报
- `body="/wui/index.html"`：9+ SPA 入口；`body="cloudstore/resource/pc/com/v1"`：9/10 cloudstore 资源
- 产品库：`app="泛微-ecology"` / `app="泛微OA"` / `app="e-cology"`（三个都试，哪个出量用哪个）

版本细分：8 = `body="/js/jquery/jquery_wev8.js" || body="/login/Login.jsp"`；9/10 = `body="/wui/index.html" || body="cloudstore/resource/pc/com/v1"`

Hunter：`web.header="ecology_JSessionid" || web.body="/wui/index.html" || web.body="cloudstore/resource/pc/com/v1"`；`app.name="泛微 e-cology"`

## 影响范围扫描工作流

1. 平台导出 URL/ip:port 列表 → `sort -u urls.txt | grep -v '^$' > targets.txt`
2. `python weaver_dispatch_scan.py -f targets.txt -o result.json`（只读：版本指纹 + dispatch 空值 POST 非 404 = POTENTIAL；末尾自动汇总分类计数）
3. 先小批量（1-2k 条）验证输出格式再放量；脚本串行约 20-40 分钟/2k，要提速加 --threads
4. e-cology 10 命中单独标记（payload 大概率不适用）

## 实战假阳性案例（zlq.grassict.cn:8893）

- 用户从浏览器分享链接带 `#/?logintype=1&time=...&_key=hax1dh` → norm_url 不剥 fragment → 所有探测实际打到 `/wui/index.html`（SPA 恒 200）→ dispatch/static.jsp 全误报"存在"，POTENTIAL 假阳性
- 修 norm_url（剥 fragment+query+登录页后缀回到根）后重跑：真 404，ECO_ONLY
- 教训：分享链接当目标必须先剥干净；status 200 要结合响应体核对（软 404 服务器存在）

## 公网验证结论（2026-08 数百目标实测，重要）

- **数百个 e-cology 目标（FOFA 批量导出）dispatch 0 命中** → 公网标准部署上 `/dispatch/invoke/java.lang.String/copyValueOf` 入口 ≈ 不存在
- 排除项：方法/路径变体全 404（GET/POST、短路径、`/ecology/` 前缀）；**裸 Resin 部署（无保护层）同样 404** → 不是 WAF/保护层吞 404，是接口真的不存在
- 样本版本同质（根页同为 2021-05-06 build 时代模板）→ 可能是版本线/模块限定；e-cology 10 样本可能未覆盖到，属最后未排除项
- 源头无样例可校准 → "影响范围广"说辞存疑。定性前最后两件事：① 版本细分重跑看分布 ② 问源头验证环境版本号

## 版本指纹（实测细化，已进 scan.py 版本细分）

- `ecology_JSessionid` Set-Cookie：8/9 最强特征；`/wui/index.html`+`/cloudstore/resource/...`：9/10 SPA；`/js/jquery/jquery_wev8.js`/`/login/Login.jsp`/`/js/ecology8.0`：e-cology 8
- 9 vs 10 靠内容标记：`ecology9`/`e-cology9`/`/js/ecology9.0`/`9.00.`/`wui/theme/ecology9` vs `e-cology10`/`ecology10`/`10.00.`/`wui/theme/ecology10`
- 根页 3235B 产品模板（ETag `HCPGHF5c4V7` 全版本相同），Last-Modified 区分安装时间 → **同 ETag ≠ 蜜罐**
- 登录页 JS 跳转 `#/?logintype=1&time=...&_key=<6位随机>`：浏览器端行为，**不影响服务器端测试**（fragment 不发服务器）；`_key` 格式一致 = 版本线同质信号

## 蜜罐/保护层信号（修正结论 2026-08）

- Server: `WVS` 在 80%+ 目标出现（跨阿里云/腾讯云/华为云）= **统一前置保护层（CDN/WAF/反代，具体产品未定）**，不是蜜罐——根页内容真实且裸 Resin 部署同样存在
- 群分享/卖家链接带 `_key=` 参数 = 诱饵嫌疑仍成立，发载荷前交叉验证目标真实性（多路径、部署细节自洽性）

## 工具位置

`D:\Pentest\攻防\武器库\泛微oa漏洞\`
- `weaver_dispatch_scan.py`：只读影响范围扫描（不读载荷文件，可批量）
- `weaver_dispatch_exploit.py`：写马版（--send 门控+二次确认；载荷从 value.txt 读，后续实时更换不写死进代码）
- `value.txt`：第三方载荷 base64（严禁外传）
