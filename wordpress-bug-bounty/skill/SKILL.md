---
name: wordpress-plugin-bug-bounty
description: "WordPress 插件漏洞挖掘→靶场复现→Wordfence 赏金提交。只出能拿权限/敏感信息的洞，默认配置优先。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, wordpress, bug-bounty, wordfence, php, code-audit, exploit]
---

# WordPress 插件漏洞挖掘与 Wordfence 赏金

## 触发条件
- 审计 WordPress 插件（源码在手，或从 wordpress.org 下载目标插件）
- 挖可提交 Wordfence Bug Bounty 的漏洞（未认证 RCE/提权/任意文件操作/敏感信息）
- 需要在本地靶场端到端复现 WP 插件漏洞（提交硬性要求）

## 目标选择（赏金规则导向）
- **⚠️ 开工第一件事 = 核实官方范围（2026-08 血泪教训，用户明确纠正）**：范围规则会变，以 `wordfence.com/threat-intel/bug-bounty-program#rewards` 页面为准。**curl 被 Cloudflare 拦 → 必须申请 computer_use 浏览器看或请用户截图，绝不用知识库旧数据顶替**（本会话曾用旧规则挖 10+ 插件全超范围白干）。页面信息与知识库冲突时以页面为准，并主动向用户确认
- **2026-08 完整规则(用户贴官方文档确认,wordfence.com/threat-intel/bug-bounty-program#rewards)**:
  - **High Threat >=25 装**(25-999 需 wp.org 仓库):任意 PHP 文件上传/读取、任意 PHP 文件删除、Arbitrary Options Update、RCE、认证绕过到 Admin、提权到 Admin(未认证或订阅者可利用)
  - **Common & Dangerous >=500 装**:Stored XSS、SQL Injection(500-999 需仓库;premium <1000 排除)
  - **其他漏洞按 tier**:Standard >=50k / Resourceful >=10k / 1337 >=500
  - **Explicitly In-Scope 列表**:Stored/Reflected XSS、CSRF(重大影响)、Missing Authorization(重大 CIA 影响)、任意内容删除、SQLi、IDOR、任意文件上传/下载/删除、LFI/RFI、目录穿越、提权(Admin/Non-Admin)、认证绕过(Admin/Non-Admin)、RCE、信息泄露、PHP Object Injection、开发者后门
  - **Explicitly Out of Scope(白干清单,血泪教训)**:
    - **Business Logic Flaws:payment bypass/定价/折扣/优惠券滥用/order workflow abuse 等纯业务影响 → 全排除**(支付插件"免费订单"类洞别挖!)
    - **所有 DoS**
    - **SSRF(含 DNS rebinding)、Open Redirect**
    - API Key Updates/Overwrites/Reads
    - Private/Hidden/Draft/Pending/Password Protected Post Access(内容保护绕过类注意!)
    - 需 PR:H 的洞;Contributor/Author 级利用(非默认注册角色)
    - 低 CVSS(<4.0)无法升级的洞
    - **Common False Positives**:CSV/CSS/HTML 注入、Self-XSS、SVG XSS、双扩展名上传、安全类型上传(正常功能)、nonce 保护完整且不暴露给低权限用户的授权缺失、无重大 CIA 影响的授权缺失、纯配置/环境问题、依赖漏洞不可验证利用
  - **推论**:1k-10k 装插件上的"授权缺失/信息泄露/业务逻辑"全部超范围(sliced-invoices P2 接受报价=order workflow abuse 排除、ERE 邮件轰炸、hitpay 取消订单、restrict-user-access XML-RPC=private post 排除、smart-auto-upload SSRF 排除、FEA P0-1 部分)→ **主攻:真实文件操作(上传/删除/下载)未认证可触发 × 老维护插件;SQLi/Stored XSS(500+装);RCE/提权/认证绕过(25+装)**
- 类型优先（High-Threat）：未认证 RCE/提权/任意文件上传删除 > SQLi > 认证绕过 > 高敏信息泄露
- **用户方向偏好（2026-08）**：优先找**预认证（未认证）**的洞，其次**权限绕过/提权**，最后才其他类型——审计时按此顺序投入精力
- **配置依赖减分**：优先"默认配置即可利用"的洞；带开关/表单配置前提的降级
- 新插件（wordpress.org/plugins/browse/new/）0 安装也 in-scope，但基本只有 $5-25，只适合练手**不适合破零赚钱**

### 找目标插件（2026-08 新范围版：High Threat 类型 × 25-5000 装）
- **新范围下目标画像**：文件上传/删除/管理器/备份/重置/Options/角色类插件（High Threat 类型命中面）× 25-5000 装 × 老维护（150+ 天未更新）
- wordpress.org 按分类浏览：`/plugins/browse/` 与 `/plugins/tags/`（表单/上传/导入/文件管理类 tag 是 RCE 高发区）
- 插件页 "Active Installations" 显示档位（100+ / 1,000+ / 10,000+...），快速人工筛选
- API：`https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=new|popular&request[per_page]=N`（国内需 socks5h 代理；browse=new 不稳时抓 HTML `https://wordpress.org/plugins/browse/new/` 更稳）
- **关键词搜索 + 本地过滤**（最实用）：`action=query_plugins&request[search]=<关键词>` 拉 80-100 个，本地过滤 `active_installs` 25-5000；关键词用 High Threat 面大的词（file manager/upload/backup/attachment/download/reset/option/role/zip）→ `scripts/find_plugins.py`（可加关键词参数）；**新范围专用筛选器 `scripts/wp_filter_highthreat.py`**（25-5000 装 + 文件操作关键词 + 120+ 天未更新，2026-08 实战验证出 66 个候选）
- 筛选信号：文件操作类**老插件**优先（RCE 高发）；**更新时间 150-500 天**（维护差 = 出洞率高，新范围下不追活跃更新的）；避开被审烂的超热门（elementor/woocommerce/CF7/yoast）
- **下载类插件防护模式（kp-zip-downloader/lana-downloads-manager，2026-08 连审 2 个结论）**：文件路径来自**管理员配置的 post meta / option**（lana_download_file_url），攻击者只能控制 ID/slug（枚举已发布下载项 = 正常功能）→ 无洞。**判定法：追文件路径/URL 的源头——来自管理员配置 = 安全；来自用户输入（$_GET['file'] 等）+ 无 realpath 校验 = 任意文件读取硬洞**
- **固定路径生成文件半洞评估法（export-media-as-zip 2026-08-11 案例）**：插件把生成文件写到 web 可访问目录+固定文件名（uploads/media-images.zip）→ 存在窗口内未认证可下载（管理员导出后 5 分钟内）。**评估三要点**：① 触发条件（谁触发生成——manage_options 管理员触发=攻击者不可控 → 大幅降级；攻击者可自己触发 = 硬）② 内容敏感性（媒体库图片本来就公开 vs 私有附件/含 PII 文档）③ 窗口（5 分钟过期 + cron 清理）。三要素都弱 = 不交；私有附件场景 + 攻击者可触发 = 可交候选
- **High Threat 方向七插件防护规律总结（2026-08）**：上传类用 media_handle_upload / wp_handle_upload 标准函数 = WP 内置 MIME 白名单（订阅者无 unfiltered_upload，php 传不了）；管理类 = manage_options + nonce + 白名单；下载类 = 路径来自管理员 meta。**真正要找的 = 自写文件逻辑**：move_uploaded_file / rename( / file_put_contents（非 wp 函数）/ readfile( + $_GET、上传检查顺序错误、MIME 误判、临时文件/缓存文件暴露——用 WP 标准函数 = 大概率没洞，手工处理 = 重点

### 下载后粗扫评估（6 步判定值不值得深挖，30 分钟内出结论）
1. 规模：`find . -name "*.php" | wc -l`，>300 文件 = 大插件，新手慎选
2. 未认证面：`grep -rn "wp_ajax_nopriv"` + `register_rest_route`
3. 危险函数：`grep -rn "wp_remote_get\|wp_remote_post"`（SSRF）/ `file_put_contents` / `unserialize` / `$wpdb->query` 拼接
4. 关键 AJAX 权限：`grep -rn "current_user_can\|wp_verify_nonce"` 看每个 wp_ajax_ 处理器
5. **判定**：全有权限+nonce = 维护好，换目标；有遗漏/未认证副作用函数 = 深挖
6. changelog 交叉验证：修过 security/XSS/CSRF/injection/escalation = 被挖过，**找绕过**（1day 变体）；只有泛泛 "improved security" = 没被深挖，竞争少；周更 = 维护好难挖
- 实战：advanced-form-integration 2.7.0（修过未认证提权）粗扫后判定防护到位（后端全 manage_options+nonce、triggers 要配置依赖、附件随机 token 目录）→ 放弃深挖
- 实战：survey-maker 5.2.3.5（6000 安装甜区，修过 Stored XSS）粗扫全 nopriv 端点后放弃：submission_report（读提交 PII 但 nonce 后台专属不可达）、show_results/author_search（有权限）、template（白名单只读）、live_preview（自反射）、ays_survey_ajax（提交+投票，nonce 在前端但输入全 sanitize + SQL 参数化）→ 存储侧也全 sanitize → 维护质量高，放弃
- 实战：wp-user-manager 2.9.18（10000 安装，changelog 修过 csrf/injection，无已披露 CVE）粗扫后放弃：所有 AJAX（roles-editor/registration-forms-editor/fields-editor/emails/stripe）全 `nonce + current_user_can + is_admin()` 三件套；表单（注册/登录/密码/密码找回/资料）固定 `wp_get_current_user()`、注册角色白名单校验、密码重置走标准 WP key 流程；上传 `wp_check_filetype_and_ext` + MIME 白名单（图/pdf/doc，无 php/svg）→ 防护到位放弃。**用户管理类插件不一定有提权洞，别默认它有**
- **粗扫加两个判定维度（wp-user-manager 案例沉淀）**：① 后端 AJAX 检查 `is_admin()` 是否与 current_user_can 成对出现（少一个 = 可疑）；② 上传面看 `wpum_get_allowed_mime_types` 类白名单函数的默认列表是否含 php/svg/可执行（严格白名单 + wp_check_filetype_and_ext 内容校验 = 上传面关闭）
- **批量粗扫案例（2026-08，一天 5 个全防护不错）**：
  - essential-real-estate 5.3.3（7000 装）：注册/上传/删除/属性操作全 nonce+归属校验；仅发现 contact_agent nopriv 未认证任意邮件（target_email POST 可控+nonce 前端可拿，中低危 $25-100 保底）。自定义角色模式：`add_role('ere_customer')` + `ere_is_cap_customer()` 检查 = 能力门，上传面用 `wp_handle_upload` 默认 MIME（无 unfiltered_upload 传不了 php）
  - image-upload-for-bbpress 1.1.23（3000 装，420 行小插件）：**上传面最强防御模式 = GD 重编码 + 32 位随机文件名**（imagecreatefromjpeg/png/gif → imagejpeg/png/gif，内容重建不可能传 shell；随机名不可预测防 CSRF）→ 放弃
  - smart-auto-upload-images 1.2.3（5000 装）：SSRF 面真实（wp_remote_get 下载文章/REST 字段里的 URL）但双限制：URL 必须外部（is_external_url 只排同站）+ 内容必须真图片（wp_check_filetype_and_ext+getimagesize）→ 认证（作者+）受限 SSRF，价值低
  - import-xml-feed 2.1.6（2000 装）：**XXE 面真实（simplexml_load_string 无 LIBXML 选项 + 叶子节点 value 回显 + maybe_unserialize 输出）但 nonce 只在 manage_options 设置页输出**（add_options_page）→ Contributor+(edit_posts) 拿不到 → 不可利用。second nonce 不可达案例（survey-maker 之后），判定法同上
  - job-postings 2.8.1（10000 装，191 天没更新）：无 nonce 未认证 AJAX（jobslisting_apply_now）创建 publish 的 job-entry post + media_handle_upload 文件上传（WP 默认 MIME 拦 php）+ relocate_file 移附件到安全目录。发现：① 下载端点 `/job-postings-get-file/<文件>` 需登录（auth_redirect）+ basename/sanitize 防穿越 + realpath 目录校验 = 防护不错，但**文件名 = `时间戳-原文件名`（relocate_file）不可枚举 → 任何登录用户可下载任意简历但拿不到文件名 = 实际利用弱**；② 未认证批量申请+上传 = 垃圾数据/磁盘 DoS（中低危不收）。**新教训：文件下载/访问端点必查文件名可枚举性——`时间戳-原名`/随机名 = 不可枚举 = 弱洞；可枚举（如 `attachment_id` 递增或 `user_id` 前缀）才是硬洞**
  - **规律**：NVD 干净 + 正常更新（近 3 个月）的插件维护质量普遍不错——"缺陷存在但 nonce 不可达"和"防护齐全"占大多数；真出洞的是半年多不维护的类型。批量粗扫不出洞时，优先按"更新时间 200 天+"标准换批目标，别在维护良好的池子里耗
- **支付类插件审计模式（hitpay / woocommerce-other-payment-gateway，2026-08）**：
  - hitpay-payment-gateway 4.2.1（4000 装/253 天）：webhook（订单完成）三件套 = 官方 SDK HMAC（salt 是插件设置、保存时强制非空）+ 金额 == 订单总额 + 货币 == 订单货币 → 安全；但 `return_from_hitpay`（`/?wc-api=wc_hitpay&hitpayreturn=1&hitpay_order_id=<ID>&status=canceled`）**未认证取消任意订单**（仅需订单 ID，无签名无登录，订单非 processing/completed 即 update_status('cancelled')）→ 业务 DoC 中低危（$25-100 档，不是免费购买别高估）
  - woocommerce-other-payment-gateway 1.4.2（8000 装，FOFA 存活多）：302 行纯手动确认型支付网关（process_payment 只 update_status+empty_cart，**无回调/webhook/签名/金额逻辑**）→ 攻击面≈0 无洞可挖
  - **判定流程：支付类先看有没有"自动流程"**（webhook/IPN/回调/状态确认端点）——没有 = 手动确认型 = 直接跳过；有 = 查三件套（签名/金额/货币校验），齐全则安全，缺任一件 = 伪造回调/金额篡改硬洞。**回调 GET 型端点（hitpayreturn/return 页）是验证薄弱区，必查状态变更参数**
  - **FOFA 存活量判定（必要非充分条件）**：存活多 ≠ 有洞（手动型网关 302 行无面可打）；存活少 = 白审（restrict-user-access 4 站）。真正理想目标 = 存活量多 × 代码面大 × 有自动流程（回调/上传/导入/前端提交）
  - bangladeshi-payment-gateways 4.0.4（5000 装）：同手动确认型（bKash/Rocket 人工核对交易号），无自动流程 → 直接跳过（第二例验证：支付类粗扫无 wc-api/webhook/nopriv 即可放弃，别逐字段深挖）
- **发票/订单类端点审计模式（pepro-ultimate-invoice 2.2.6，2026-08）**：
  - 结构：`admin_init` 钩子里的 "public methods" 区域（注释即表明意图）——`?invoice=<订单ID>` / `invoice-pdf` / `invoice-pos` / `invoice-slips` / `invoice-inventory` 等 GET 参数直接处理，**admin-ajax.php 未认证可触发 admin_init** → 表面看是未认证面
  - **但内部有 has_access() 认证函数（class-print.php）**：已登录用户=归属校验（只能看自己订单,admin/shop_manager 除外）；未认证=guest 分支,默认拒绝（allow_guest_users_view_invoices 默认 "no"）；create_pdf 的 "S" 模式跳过认证但未认证入口不传 "S" → **默认配置安全**
  - 利用条件 = 管理员开启 "Allow Guests view invoices"（发票类插件常见需求,开启率可能不低）→ 未认证枚举任意订单发票（金额/客户 PII）→ 配置依赖的中危洞
  - **教训：admin_init 端点 ≠ 未认证可利用——必须追到内部认证函数看默认值/归属校验/guest 分支**（has_access 模式：admin 放行 → 归属校验 → 配置开关三层）。审计顺序：找处理钩子 → 找内部认证函数 → 看默认配置分支
  - 附带发现：订阅者 save-resid AJAX 任意订单写 meta（`_shipping_puiw_invoice_track_id`，低危不交）
- **Block 插件审计模式（pdf-viewer-block 1.0→1.1，2026-08-10）**：
  - block 插件 PHP 端极小（主文件+admin+public 各几十行），攻击面在 **JS save/render 函数 + post_content 可写性**——block HTML 由 JS save 函数生成存进 post_content，前端 JS 再读 DOM 处理。审计顺序：block.json（有无 render 字段）→ public/ 前端 JS → 谁能写 post_content
  - 案例: pdf-viewer-block 前端 JS 把 `.uploaded-pdf > a` 的 href 直接拼进 iframe src（`'?file='+href`）→ 属性注入 DOM XSS；1.0.1 修复 = `encodeURI(href)`（编码 `"`/`<`/`>` 防住属性注入；`'` 不编码但拼接用双引号、javascript: 在参数位不执行 → 修复有效单点，全文件仅此一处拼接无漏修）
  - **触发面判定 = 谁能写 post_content**：block 属性漏洞先问"写 block 的人什么权限"——edit_posts=作者级 → 存储 XSS 作者级写 → 超 Wordfence 范围不交（即使访客触发）
  - 附带: 插件打包旧版 pdf.js（CVE-2024-4367 类）也属依赖漏洞不交
  - **zip 下载失败替代方案（实测）**：SVN tags 单文件拉取 `https://plugins.svn.wordpress.org/{slug}/tags/{ver}/{path}`——先 curl tags/ 拿版本列表 → 拉核心文件（主文件/admin/block.json/public.php/JS）。block 插件核心 3-5 个文件，比等 zip 快得多；修复前/后各拉一份 diff 即可

### 看更新日志（changelog 攻防信号）
- wordpress.org 插件页 → "Development" tab → Changelog
- 直接读 readme.txt：下载 zip 或 SVN `https://plugins.svn.wordpress.org/{slug}/trunk/readme.txt` 的 `== Changelog ==` 段
- 对比版本间差异：SVN tags 目录 `https://plugins.svn.wordpress.org/{slug}/tags/` 列出历史版本，diff 相邻版本看安全修复
- 从 changelog 判断攻击面：出现"security fix / XSS / authorization / nonce"条目 = 新版本有补丁 → 对比补丁找绕过（1day 变体）；近期版本改动频繁 = 攻击面大
- **★ changelog 语义盲区（2026-08-11 bdvs-password-reset 案例）**：安全修复不一定写 security/XSS 词——bdvs 0.0.16/0.0.17 修"重置码生成不安全"(4位弱随机→8位安全随机+random_int)+"admin 角色默认不可重置"+码长 4→8，changelog 写的是 cryptographic/administrator/length，**无任何 security 词** → "changelog 无 security 词" ≠ "没修过"。判定法：读 changelog 同时留意 random/cryptographic/length/role/administrator/code/validation 等语义词；筛选器产出（"维护差/干净"）投入前抽查 changelog 全文。实战：wp_filter_highthreat 筛出 57 个"维护差"候选，连审 5 个（wordpress-reset=2025重写版、bdvs=2025安全修复）全防护完整——**刚重写/刚做安全修复的插件 = 防护好的概率极高，优先挑"多年未动的老代码"**
- **"修过洞"要区分维护勤度（2026-08 两案例修正）**：
  - 修复历史 + **更新频率高（周更/月更）** = 作者响应快、防护到位 → 绕过难，别抱期望（advanced-form-integration 2.7.0 修过未认证提权但后端全 manage_options+nonce；survey-maker 5.2.3.5 修过 Stored XSS 但 nopriv 端点全查无洞，存储全 sanitize）
  - 修复历史 + **更新不勤（半年以上才动）** = 绕过空间大，优先目标
  - 1 年以上没更新但还有 1k+ 安装的老插件 = 代码旧没人管，最优目标
- **筛选工具（2026-08）**：`scripts/wp_filter_vuln.py` = "修过安全洞 + 更新间隔 60-400 天"双条件筛选器（理想目标画像：修复历史 + 不勤快），跑一次出 40+ 候选；`scripts/find_plugins.py` 只按安装量过滤。用法 `python wp_filter_vuln.py [关键词...]`（默认攻击面关键词：upload/import/booking/form/directory/listing/subscription/invoice/membership）。**实战验证有效**：筛出的 sliced-invoices（5000 装/238 天没更新/修过 SQLi+CSV 注入）→ 挖出未认证读发票 + 未认证接受报价两洞
- **维护差筛选器（2026-08-11 优化）**：`scripts/wp_filter_highthreat_v2.py`（25-5000装 + 文件操作关键词 + 120+天未更新；15s 超时/实时进度/Windows 路径，跑一次约 3 分钟出 50+ 候选）。**注意 changelog 语义盲区**：筛出的"维护差"候选里混着"刚重写/刚做安全修复"的插件（wordpress-reset 1.5.0 重写、bdvs 安全修复都没写 security 词）——投入前抽查 changelog 全文，优先挑多年未动的老代码
- **换标准重筛（2026-08-09 实战）**：当"NVD 干净 + 正常更新"的池子连审 5 个全防护不错时，把间隔放宽到 **150-500 天** + 轮换关键词（booking/membership/subscription/invoice/payment/auction/loan/job），组合出 15 个理想目标 → 命中 restrict-user-access（10000 装/307 天没更新/权限控制类）→ 出 XML-RPC 内容保护绕过。**权限控制/内容保护/会员类插件 = 权限绕过洞高发区**，契合用户"预认证+权限绕过"偏好，优先于普通 CRUD 插件

### 查重（选目标后、投入审计前必做——2026-08 sliced-invoices 白干教训）
- **已披露 = 占坑**:NVD/Patchstack/WPScan 已报的洞,Wordfence 不收重复(P1 读发票被 Patchstack 的 CVE-2025-31628 占坑,白挖)
- 选目标后先批量查 NVD:`scripts/wp_check_cve.py [slug...]`(keywordSearch 查 CVE,输出已披露/干净两组)
- 判定:已披露 → 排除或只找**不同根因**的洞(不同影响=可争,但被拒风险高);干净 → 投入审计
- 注意:NVD keywordSearch 可能漏(slug vs 显示名),关键目标再手动搜 Patchstack/WPScan

### 装量档位预筛（选目标后先算可交类型——2026-08-10 FEA 白审教训）
- **开工先按 active_installs 算这个插件只允许交什么洞，再决定审哪些面**：
  - <50k 装（Standard tier）：删除/信息泄露/IDOR/缺失授权/任意内容删除等"其他类"洞**全部超范围**，审了也白审
  - 唯一可交：High Threat 类（25装门槛：任意 PHP 文件操作/RCE/认证绕过到 Admin/提权到 Admin/Arbitrary Options Update）+ SQLi/Stored XSS（500装）
- 实战（FEA acf-frontend-form-element 9000装）：已审出未认证删除链 CVSS 8.1（删 post_author=0 文章，靶场复现）+ 未认证提交 PII 泄露（靶场复现），**因 9000 装 < 50k 全部超范围不能交**；该插件唯一 High Threat 面（未认证提权链）是朋友已提交的成果不能重复交。**教训：选目标后先查装量 → 直接筛掉"超范围面"，别在删除/泄露类面上花靶场时间**
- 推论：1k-10k 装插件上，只有"文件操作/RCE/提权/认证绕过/Options 写/SQLi/StoredXSS"值得深挖；"这插件能删对象/泄露数据"类发现直接标注超范围（除非 50k+ 装）

## 漏洞价值三层评估（决定交不交）
每个洞按三层逐步降级，三层全过才算硬洞，**任何一层失败就果断放弃或降级提交**：
1. **源码机制成立**（静态）：代码层面缺陷存在（nopriv 端点/权限缺失/令牌铸造）
2. **靶场复现可达**（运行时）：实际请求链无拦截器——静态成立的洞可能被无条件 do_action 订阅者抢先 die()、或 conditions_logic 在令牌铸造时把目标 ID 置 'none'（见 wp-lab-setup.md）→ 复现时如实记录可达范围
3. **真实场景验证**（配置开启率）：配置依赖重的洞（如"保存提交"开关）即使机制+复现都过，真实站点开启率可能极低 → 价值接近零
- 实战案例（FEA 3.29.10）：P0-3 提交泄露靶场复现成功，但真实站点探测（jobs.vas.org.uk 等）未命中 → 保存提交默认关、开启率低 → **放弃提交**；P0-1 从"任意对象删除 9.1"降为"post_author=0 文章删除 8.1"（conditions_logic 拦截）
- **实战案例（restrict-user-access 2.8，2026-08）**：XML-RPC 内容保护绕过（静态链完整：authorize_access 只在 template_redirect + 全项目无 xmlrpc 拦截 + wp.getPost 返回 publish 全文）→ 靶场卡点（WPCA 条件 SQL 级集成+缓存，手动 meta 不生效需 UI）→ **真实场景验证失败**：FOFA `body="restrict-user-access"` 只搜到 4 个真实站，3 个可达站里 0 个同时满足触发条件（xmlrpc.php 可达 + 注册开放）——404/503（禁用）和注册 302（关闭）占绝大多数 → 触发面窄，放弃提交
- **内容保护/会员类洞的真实场景检查清单（只读）**：① FOFA 先看使用面（站点 <10 个 = 插件本身小众，洞价值打折）② 触发条件逐站验证：`/xmlrpc.php` 状态（200+XML=开；404/503=禁）③ `/wp-login.php?action=register`（200+表单=开；302/404=关）④ 安全习惯：**大量站点禁 xmlrpc**（WAF/插件），验证前先测，别假设默认开启
- 用户会问"实际场景会这样吗/这本来就是公开的吧"——先自己用真实站点证据回答，别用构造数据说服

## 审计方法论
**★ 代码审计执行法（2026-08-10 用户升级，替代"纯关键字 grep"）**：
- **关键字搜索的局限**：grep 危险函数（file_put_contents/unserialize/$wpdb->query）只能找到"用了危险函数"，找不到设计/逻辑层缺陷：IDOR（权限判定对象≠操作对象）、检查时机（权限检查在哪个分支被跳过）、nonce 语义（只证明登录不证明授权）、默认配置值。**人类的审计 = 一行一行读调用链**，读得越多一眼扫过去就知道洞在哪。**grep 只用于定位（函数定义/钩子注册），分析必须 read_file 读完整函数上下文**
- **六阶段流程**：① 功能地图（目录+钩子注册表→功能线）→ ② 入口点枚举（所有 add_action/add_filter/REST/admin_post/nopriv，按可达性分级：未认证>订阅者>作者>管理员，产出 audit-map.md 入口点清单）→ ③ 调用链阅读（对高价值入口 read_file 连续读完整处理函数，关注 输入→检查→处理→输出 全数据流）→ ④ 危险终点倒推（文件写/选项写/删除/SQL/输出，每个终点问：谁能到达？中间检查是什么？检查的对象对吗？）→ ⑤ 开发者意图对抗 7 问 → ⑥ 运行时验证+证据落盘
- **开发者意图对抗 7 问**（抓设计/逻辑漏洞）：① 功能设计上给谁用？权限门在哪？② 权限判定依据的对象 = 实际操作的对象吗？（IDOR 检测器）③ nonce 绑定 action 名还是对象 ID？④ 默认配置是什么？配置改变信任边界吗？⑤ 多个入口到达同一操作吗？（补丁只改主路径、兄弟分支漏改）⑥ 状态变化有验证吗？⑦ 谁的数据会流到这里？（跨权限数据流）
- **逻辑反向检查模式（2026-08-11 bdvs-password-reset 案例）**：读到"时间/条件判断反向"的代码 = 可疑——`if ($now > $code_expiry) $expired = false`（当前时间超过过期时间反而标记"未过期"）→ 过期码永久有效。判定法：布尔逻辑代入具体值推演（now=过期后1秒，expired 应为 true 还是 false，与代码结果对照）；反向检查单点通常不构成可利用洞（需正确 code 配合），但记录待用并检查兄弟分支是否同款
- **人机分工**：用户手动读代码用直觉发现可疑点；我方负责系统性覆盖（枚举全部入口、追调用链验证、查同类兄弟点、查默认配置、证据落盘）。用户发现一处 → 我方把这一类全部扫一遍
- **审计疲劳防护**：连续 5+ 插件防护好时，不敷衍粗扫——切换策略（换批目标/换攻击面/换插件类型），或停下来汇报让用户决策
- **工具+多Agent 流水线（2026-08-10 用户要求，治"人工一行行读太累"）**：
  - 阶段0 准备(我): 下载插件 + 修复前后 diff + NVD 查重
  - 阶段1 工具层(零人工): **skill 内置 `scripts/wp_entry_map.py`**（副本在 D:\Pentest\wp_entry_map.py）跑 `<插件目录>` 出入口点地图(钩子/危险函数/权限函数/未过滤输入四类清单, 用法见脚本 docstring); semgrep(清华镜像 pip 装, `semgrep scan --config p/php <目录>`) 出机械层候选(XSS/SQLi/危险函数/污点流)。工具产出=候选清单, 不是结论
  - 阶段2 Agent层(并行3个, delegate_task, 上下文隔离): Agent A 未认证面(nopriv/init/admin_init/REST/短代码); Agent B 登录用户面(wp_ajax/页面处理器/表单); Agent C 数据流链(文件操作/输出渲染/配置)。**每个 agent 只发现不判定**: 对分配入口读完整调用链, 输出 [FILE:LINE+代码原文+输入→检查→处理→输出+可疑点+7问对照], 限 10 个可疑点防 token 爆炸。传足上下文: 插件绝对路径+功能地图+7问清单+输出格式模板
  - 阶段3 我验证: 汇总去重→逐个验证静态链→逻辑层分析(IDOR/时机/nonce语义/默认值)→补 agent 盲区(跨面数据流)→三层评估+四问→候选洞报告
  - 阶段4 决策门: 用户拍板→靶场复现→提交材料
  - 规模判断: <20 文件小插件直接我读(agent 协调开销>收益); >50 文件才上 3 agent
  - Agent 坑: 子 agent 会幻觉/浅尝辄止(只发现不判定, 判定权在验证者); 漏跨面数据流(验证者补); 不能依赖 agent 自报"安全"(必须抽样验证)
  - **三角色架构（2026-08-10 用户朋友建议 + 采纳）**: 思考者(我方, 出审计方案+验证标准) / 执行者(2-3 并行 agent, 各打一个攻击面, 只发现不判定) / 检查者(我方收尾复核: 验证静态链+补跨面盲区+三层评估; 插件大或发现多时起独立检查 agent)
  - **上下文管理原则（用户提供, delegate_task 天然实现）**: 开头精准(给执行者的 context=目标+插件路径+功能地图+7问+输出格式) → 中间压缩(agent 完整推理只在自身上下文, 不进主上下文, live_transcripts 可查) → 结尾精准(agent 只回结构化可疑点清单 [FILE:LINE+代码原文+推理], 限 10 条)
  - **semgrep 实测结论（2026-08-10 回测 gdbb）**: 工具(p/php+security-audit+owasp-top-ten)报 0 发现——机械层确实干净(全转义/WP标准上传/无SQL拼接), 但对 IDOR(逻辑层)完全失明。**工具说"没洞"只代表机械层干净, 不代表逻辑层安全**。工具=机械层可信+出候选; AI=逻辑层(7问)+验证
  - **国内工具下载**: pip/uv 装包用清华镜像 `--index-url https://pypi.tuna.tsinghua.edu.cn/simple`(pypi.org 直连超时); semgrep 装于 `D:\Pentest\semgrep-venv\`(命令: `D:/Pentest/semgrep-venv/Scripts/semgrep.exe scan --config p/php <dir>`); semgrep 拉规则集走代理(export HTTPS_PROXY=http://127.0.0.1:7890)


2. **报告污染陷阱**：项目目录里的旧审计报告 = 知识污染。读完会把目标链划为"已知"不再独立推导。旧报告当"验证清单"而非"划掉清单"；开工先花 5 分钟倒推"如果要拿权限，最短路是什么"
3. WP 插件特有攻击面：
   - `wp_ajax_nopriv_*` 端点清单 = 未认证攻击面（grep `nopriv`）
   - **匿名 nonce 全站共享**（uid 0 + 空 session token）：任何渲染插件脚本的公开页面 HTML 可提取（`"nonce":"..."` 正则）→ nopriv 端点 + 共享 nonce 实际等同未认证
   - **nonce 可达性验证（survey-maker 案例）**：nopriv 注册 + 无权限检查 ≠ 可利用。若 nonce 是 `wp_localize_script` 在**后台插件页**输出（admin_enqueue_scripts + 菜单 capability=manage_options），订阅者访问 403（wp_die 在 admin_enqueue_scripts 之前）→ nonce 不可达 → 不可利用。判定法：grep `wp_create_nonce('<action>')` 的所有位置，确认至少一处输出在**公开前端页面**；否则该"洞"只是代码缺陷，排除
   - 加密令牌（wp_hash 密钥）不可伪造，但**服务端端点可铸造任意对象令牌**（如 change_form 任意 item_id → absint）
   - 表单配置是信任边界：若攻击者可伪造表单配置（save_to_*/new_*/login_user 等）→ 角色覆盖/自动登录/任意对象操作
   - **post type 公开性审计（sliced-invoices 案例）**：业务 post type（发票/报价/订单/预约）若 `register_post_type` 带 `public=true` + `capability_type='post'`，且前端单页模板（single_template filter）只查 `post_password_required()`（而业务 post 创建时不设密码）→ 未认证直接读全站业务数据。审计加一步：grep `register_post_type` 的 public/capability_type + 前端模板的权限检查
   - **nonce 只防 CSRF，不防"未认证用户自己操作"**：前端公开页面渲染的表单 nonce（wp_nonce_field 在模板输出）= 未认证可提取且验证通过（uid 0 共享 nonce）→ 处理器只要有 wp_verify_nonce 但**无 current_user_can**，业务操作（状态修改/接受报价/转发票）即未认证可利用。判定法：搜"前端输出 nonce + 处理器仅 nonce 无 capability"的 AJAX/POST 处理器
   - **nonce 通用机制教学（2026-08-10 FEA 讲解，用户已懂）**：nonce = 哈希(动作名+用户ID+会话+12h 时间窗)，是"这请求是本站用户主动发的"防伪标签（防 CSRF），**不是资格证明**；未登录用户 uid=0+空 token → 全站访客共享同一 nonce 值；不绑定操作对象（动作名是字符串，key 可控即换校验对象）。**判断口诀：`wp_verify_nonce(存在)` 只说明防了 CSRF；`current_user_can(存在)` 才说明查了权限；两者缺一不可，nonce 永远不能替代权限检查**——审计时"只有 nonce 无权限检查"的端点一律当未认证可打来验证
   - **前端表单插件删除链模式（FEA P0-1 教学案例，2026-08-10）**：ACF Frontend/Frontend Admin 类"前端表单"插件（前端发帖/编辑/删自己的内容）的删除功能 = 4 环节组合洞：① nopriv 删除端点 + **共享 nonce**（fea_delete_{key}，key 自己传）只证明"你是访客"；② 权限检查短路（表单可见即 `$allowed_by_settings=true`，删谁由令牌决定）；③ **令牌可铸造**（change_form 端点任意 item_id → absint → 服务端铸造加密 _acf_objects 令牌）；④ **修复的作者校验对象错位**（`post_author == $user->ID`，未认证 $user->ID=0 匹配 post_author=0 的文章）。判定法：凡"nopriv 端点 + 固定前缀共享 nonce + 权限检查引用表单配置/被短路 + 操作对象来自可铸造令牌" = 前端表单插件删除/编辑链，逐环节验证；修复版本重点看"校验对象"是否与操作对象错位（作者 ID vs 对象归属）
   - 上传/导入/CSV/备份类插件：文件操作 RCE 高发；但注意 WP `get_allowed_mime_types()` 对匿名用户剔除 html/js/php\n   - **内容保护/会员插件绕过（restrict-user-access 案例，2026-08）**：核心保护常只在 `template_redirect` 触发（level.php authorize_access）→ 绕过面 = 不触发前端模板的通道：**XML-RPC / REST / feed / admin-ajax / 短代码**。**XML-RPC 最干净**：WP 核心默认开启，wp.getPost/getRecentPosts 对 publish 文章返回完整 post_content，插件若无 xmlrpc 拦截 → 订阅者凭证直接读会员文章全文（CWE-862，击穿插件核心价值）。判定法：全项目 grep `xmlrpc` 无拦截即成立；REST 可能已有 rest_authentication_errors 保护（默认拒绝未认证+非 edit_posts）但 XML-RPC 完全不受影响。靶场注意：WPCA/content-aware-engine 类插件条件为 SQL 级深度集成+缓存（option `_ca_condition_type_cache`），手动写 meta 不生效，需 UI 配置或走保存接口，静态链完整时记录卡点交用户决策
4. **静态分析 ≠ 运行时**（本 skill 最重要教训）：
   - 子 Agent 静态读码会漏"运行时拦截"：某端点可能注册了无条件的 do_action 订阅者抢先 `die()`（本案例 related-items 拦截 add_form → 提交数据读取主链不可达）；3.29.10 的 conditions_logic 在令牌铸造渲染时把目标 ID 置 'none'（用户删除被拦）
   - **每个链必须靶场端到端验证**，静态成立的洞可能实际不可达
   - 复现时区分"机制成立"（代码层面缺陷存在）vs"实际可达"（无运行时拦截、默认配置可用）

### 补丁分析流水线（2026-08-10 固化，防上下文压缩/健忘/幻觉/粗心/执行力衰减）
- **全局状态文件（单一事实来源）**：`D:\Pentest\审计进度\00_全局状态.md`——候选池进度/已审结论/待决策/方法论红线。每轮开始先读它 10 秒恢复全局；每轮结束必须更新（收尾仪式，不更新不算完）
- **每插件固定五步（不许跳步）**：① 功能分析（插件干嘛的+设计思路+信任边界，讲给用户）→ ② 粗扫（端点/权限/危险函数）→ ③ 决策门（停下来等用户拍板深挖/放弃）→ ④ 深挖（带证据）→ ⑤ 证据落盘（进度文件）
- **证据锚点制度**：进度文件强制含 FILE:LINE + 关键代码原文 + 判定理由。"无洞"必须写清哪层防护挡住了（函数名+检查名+默认值），不写理由=未完成。静态结论必须能追溯到代码，不靠记忆复述
- **候选洞上报前三层评估 + 四问**（防把配置依赖洞当成果抬出来）：
  ① 源码机制成立？② 靶场复现可达（默认配置 or 需配置）？③ 真实场景开启率？
  四问: 默认配置能用吗？真实站点开启率高吗？会不会被判定 out of scope（业务逻辑/SSRF/private post/作者级）？NVD/查重过了吗？
  任何一问不过 = 降级标注或放弃，不许直接报"发现洞"
- **工具防呆清单（已踩坑固化）**：
  - curl 下载必须 `-f`（404/5xx 返回非 0，避免 && 链短路）；`-o` 后必查 `stat -c%s` 和 zip 文件头（PK\x03\x04）
  - 解压 zip 用 python zipfile（MSYS 路径坑：Windows 原生 unzip 吃 /d/ 格式路径会失败）
  - search_files/rg 对中文路径会 IO error → 用 terminal grep 代替
  - 版本号 zip 404 = 该版本无 tag（trunk 版）→ 下 `{slug}.zip` 最新版或查 SVN tags 列表
  - 命令链避免 `A && B && C`（中间失败会留下错误状态），分步执行
  - 代理不稳时（SSL exit 35）重试/后台下载 + notify_on_complete
  - **python 脚本内文件路径也要 Windows 格式**（`D:/...`）：`/d/...` 在 bash 里能跑但 Windows 原生 python 报 FileNotFoundError（2026-08-11 筛选器 v2 踩坑）；脚本默认输出路径同理
  - **python 长任务重定向到文件 = 块缓冲**：中间 print 不落盘、无法中途看进度 → `python -u` 或 print(flush=True)（wp_filter_highthreat.py v2 已内置实时进度）
  - **api.wordpress.org 走 HTTP 代理可通**：urllib 脚本跑前 `export HTTPS_PROXY=http://127.0.0.1:7890` 即可（不必 socks5h）；筛选器已升级 v2（15s 超时，跑一次约 3 分钟出 50+ 维护差候选）
- **收尾三件事（每轮结束强制）**：更新 00_全局状态.md + 更新候选池文件（划掉已审）+ 插件进度落盘。三件做完才允许结束
- **跨电脑同步（2026-08-10 用户启用 git 方案，多项目聚合仓库）**：仓库 = GitHub 私有 `https://github.com/harleygod/hermes-project.git`（多 Hermes 项目聚合，本项目在子目录 `wordpress-bug-bounty/`）。本地：`D:\Pentest\hermes-project\wordpress-bug-bounty\`（含 审计进度/ skill/ tools/ MEMORY导出.txt）。凭证：`~/.git-credentials`（harleygod + token，credential.helper store）；GitHub push 走代理（`git -c http.proxy=http://127.0.0.1:7890 push`）。**定时自动同步已挂 cron**（job 3626c3a11615，每小时跑 `~/AppData/Local/hermes/scripts/audit_sync.sh`：同步进度/skill → 有改动 commit → push，无改动静默）。**收工四件事 = 收尾三件事 + git 同步**（脚本自动做，手动 `bash /d/Pentest/audit_sync.sh`）。开工：`git pull` + 读 00_全局状态.md。**新项目加入**：`D:\Pentest\hermes-project\` 下建子目录，git add 推上去。**仓库根还有 `hermes-config/`（2026-08-11 用户要求同步 Hermes 环境给下班电脑）**：skills 全量 + SOUL.md + cron/ + scripts/ + **脱敏模板 .env.example/config.yaml.example（真实 .env/config.yaml 永不入库，密钥用户自己填）**；下班电脑装好 Hermes 后按 `hermes-config/README.md` 恢复（skill 拷到 skills 目录 + 模板填密钥 + MEMORY 导入）。cron/jobs.json 含运行时时间戳已 gitignore（否则每次 tick 产生 diff）**坑：GitHub fine-grained token（github_pat_ 开头）无"创建仓库"权限（Resource not accessible）——建仓需网页手动建私有空仓或换 classic token（勾 repo）；push 认证用 token 当密码；token 进过聊天记录后提醒用户轮换**

**先讲功能再讲代码（2026-08-10 用户明确纠正）**：开工先给用户讲清楚"插件是干嘛的"——功能流程（上传/下载/管理/配置四条线）、开发者的设计思路、信任边界（哪些输入用户可控、权限模型怎么设计）。**"跟开发做对抗"= 先理解开发者设计的功能和思路，再针对性地分析背后可能存在的漏洞**。用户需要知道源码绝对路径（下载后放在哪个目录），不是相对路径。讲判断要带"为什么"（为什么这层设计挡住了攻击）。

对 changelog 里修过 security 洞的插件，下载修复前/后两版 diff 补丁，判断修复质量决定值不值得挖：
1. 从 changelog 定位修复版本：找 "fixed SQL injection issue CVSS 9.3 from Patchstack" 类条目所在版本号，取**上一版**为修复前版本
2. 下载两版：`https://downloads.wordpress.org/plugin/{slug}.{version}.zip`（版本 zip 直接可下，无需 SVN）
3. `diff -rq dirA dirB` 找改动文件 → `diff` 具体文件看补丁内容
4. **判定修复质量**：
   - 单点修复（只参数化 1 处/只过滤 1 个参数）= 同款拼接大概率漏修 → 挖：grep 同文件同模式 `WHERE xxx = '<var>'`、`SELECT ... .$var` 找其余拼接点
   - 完整修复（参数化 + 输入长度限制/类型校验双保险）= 难挖 → 换目标
5. **检查修复是否附带长度/格式限制**：即使找到漏修的同款注入点，若入口参数被强制长度（如 uniqueuploadid `strlen==10`），payload 空间被压成 `' OR 1=1 #`（恰 10 字符）级布尔注入 → 利用价值骤降，别交
- 实战（wp-file-upload 5.1.7→5.1.8，2026-08）：SQLi 补丁只参数化 1 处（wfu_functions.php:4722），同文件 wfu_log_action:3898 同款 `uploadid = '.$var` 拼接 5.1.10 仍未修 → 漏修点坐实；但 5.1.8 同时给 uniqueuploadid 加 strlen==10 限制 → 只够布尔注入 → 放弃。细节：references/patch-diffing.md
- **实战（sliced-invoices 3.8.16→3.8.17，2026-08，挖洞成功）**：SQLi 补丁是 prepare+esc_sql 完整修复（admin/shared 两处都修）→ **补丁质量好 ≠ 无其他洞**——同插件完全没被审过的面反而出洞：① 发票/报价 post type `public=true`+publish+无密码 → 未认证 `/?p=<ID>` 直接渲染金额+客户姓名/公司/地址/邮箱（CWE-200）；② 报价页"接受/拒绝"按钮 wp_nonce_field 前端输出（未认证可见）+ client_accept_quote 仅 wp_verify_nonce 无 current_user_can → 未认证 POST 任意报价 ID 即接受并自动转成发票（CWE-862 写操作）。两洞默认配置、无前置条件，靶场端到端复现。补丁分析找不到绕过时，**转向未审面**（post type 公开性/前端业务操作/支付回调）往往更出成果
- **实战（2026-08，补丁分析 3 连：download-after-email / simple-membership-wp-user-import / moving-media-library）**：
  - **changelog 安全词筛选 = 免费攻击面地图（不需要 Wordfence key，2026-08 主力打法）**：wp.org API 的 `sections.changelog`（不是顶层 changelog key！）含作者修复记录——正则去 HTML 后 grep 安全词（security/vulnerability/xss/sql injection/csrf/nonce/arbitrary/bypass/sanitize/escape/cross-site/injection/auth）过滤 = 筛出"修过安全洞"的插件（攻击面已证实 + 单点修复漏修概率高）。流程：query_plugins 搜文件操作类关键词（25-10000 装）→ plugin_information 拿 sections.changelog → 安全词过滤 + 120+ 天未更新 → 下载修复前/后两版 zip diff。一次筛出 20 个候选，见 `references/patch-analysis-candidates-2026-08.md`
  - download-after-email 2.1.9→2.1.10（7000装，修"arbitrary file download"）：修复 = 新增 `dae_is_file_allowed_for_download` 白名单（文件必须为媒体库附件 _wp_attached_file meta 匹配 + 被发布的 dae_download 引用）+ 原有 basename + nonce（wp_hash(file|time|session_token) 不可伪造且 option 名绑定 file+email）→ **修复完整无漏修，放弃**。下载端点修复后必查 3 点：路径回退（uploads 根目录兜底）、nonce 是否与 file 绑定（换 file 参数 nonce 是否仍有效）、白名单绕过（LIKE 匹配/引用检查完整性）
  - simple-membership-wp-user-import 1.9.1→1.9.2（4000装，修"added nonce to import all wp users"）：修复 = add_all 批量导入加 check_admin_referer；**漏修 = add_selective 分支无 nonce**——但页面 manage_options（add_submenu_page 权限）+ 只 CSRF 且影响低（创建 SWPM 会员业务数据）→ 不值得交。**教训：nonce 修复常只加主路径、分支路径漏加——但漏修分支若在 admin 页 + 低影响，只是 CSRF 低危，别浪费提交名额**
  - moving-media-library 1.23→1.24（2000装）：diff 只有 ABSPATH 检查；导入上传功能（admin 页 + check_admin_referer + wp_check_filetype 类型检查 + sanitize_file_name + unfiltered_upload 门）防护完整 → 放弃
  - **NVD API 的坑（为何换数据源）**：`pubStartDate/pubEndDate` 日期参数 URL 编码不当返回 404（需 %3A 编码冒号，有时仍失败）；keywordSearch 按相关性排序返回 2008-2022 旧 CVE 占前，查"最近文件类漏洞"效率低。**wp.org changelog 免费且含 WP 插件专属修复记录，是补丁分析的首选数据源**
- **实战（2026-08-10，4 连审：gallery-lightbox-slider / bulk-media-register / wp-attachments / gd-bbpress-attachments）**：
  - **权限基线速判（省时关键）**：文件操作类插件若所有操作（页面处理器 + AJAX）都在 `upload_files`（作者级）权限门后 + nonce 全覆盖 → **作者级利用直接超 Wordfence 范围**，粗扫即可放弃，别逐字段深挖（bulk-media-register 8000装 案例：页面全 current_user_can('upload_files')+check_admin_referer、AJAX 全 nonce+upload_files+ABSPATH 校验 → 直接放弃）
  - **"修复引入的 nonce 绕过"先评估绕过后的实际影响**：wp-attachments 5.3.4 加 `noheader` 参数可绕过 nonce 验证（作者为 metabox 请求留的"Fallback"口子），但绕过后只是 `post_parent=0`（unattach 附件，不删除）→ 影响小 = 低危不交。判定法：绕过 nonce 后执行什么——物理删除/写 option/状态变更 = 硬洞；解除关联/排序/低影响 = 不交
  - **IDOR 判定公式：权限判定对象 ≠ 操作对象且无关联校验 = IDOR**。gd-bbpress-attachments delete_attachments（code/class.php:105，init 钩子任意请求触发）权限只看 `get_post($bbp_id)->post_author == $user_ID`，但 `$att_id`（要删的附件）**无归属校验** → 订阅者发帖（自己帖子当 bbp_id）→ 提取自己 nonce（固定 action 'd4p-bbpress-attachments'，按钮渲染时才输出）→ `wp_delete_attachment($att_id)` 任意媒体文件物理删除。三要素：① nonce 固定 action 共享（登录用户自己的 nonce 即可，前端渲染条件决定可达性）② 操作对象与权限判定对象分离 ③ 价值看配置默认值（delete_visible_to_author 默认 'no' → 配置依赖降级）。查重干净（NVD 无 CVE）→ 保留候选
  - **前端 XSS 修复 ≠ 后端逻辑安全**：gd-bbpress 4.7.3 修 "reflected XSS with attachment actions" 只动了 front.php 输出转义（sanitize_html_class/esc_url，$ext 扩展名拼 CSS class），**class.php 的 delete_attachments IDOR 完全没动、4.7.2→4.9.4 存活**。判定法：XSS 类修复 diff 若只在渲染/输出文件 → 同插件核心文件操作/权限逻辑单独查，别被"修过洞"带偏
  - **版本 zip 404 = trunk 版**：changelog 版本号在 SVN tags 里不存在（如 gallery-lightbox-slider 1.0.0.43 无 tag）→ 带版本号 zip 404，改下 `{slug}.zip`（无版本号 = 最新稳定版）
  - **大 zip 下载实操坑**：带 Freemius SDK 的插件 zip 达 1MB+，socks5h 代理 SSL 握手间歇失败（HTTP:000 exit 35）→ **后台下载 + 循环重试 + python zipfile testzip() 校验**（HTTP 200 但文件截断/损坏是常态，BadZipFile 必须重下）；解压用 python zipfile 别用 unzip（MSYS 路径坑：Windows 原生 unzip 对 /tmp/ 与中文路径目录处理出错）；SVN 单文件（plugins.svn.wordpress.org/{slug}/tags/{ver}/path）比整包 zip 轻量，适合快速 diff 关键文件
- **实战（2026-08-10，第 5-6 连审：pdf-viewer-block / media-library-helper）**：
  - **★ OR 逻辑 nonce 模式（可复用判定法）**：`if (!current_user_can('X') && !wp_verify_nonce(...))` 的 OR 逻辑 = **X 权限用户免 nonce** → 该权限用户的 CSRF 面存在。media-library-helper 1.3.0 \"CSRF 修复\"把硬 nonce（`!wp_verify_nonce`）改成 OR（作者为修 admin 功能 bug 牺牲 nonce）= **修复引入削弱**（同 wp-attachments noheader 模式）；后果 = admin CSRF 改附件元数据（title/alt/caption，低危不交）。对比同插件 attachment_save_bulk_edit：nonce 保持硬检查 + per-id current_user_can('edit_post') = 完整。**判定：见 OR 逻辑 nonce → 查免检权限用户的 CSRF 后果——元数据篡改/解除关联=低危不交；选项写/文件操作/权限变更=硬洞**
  - **wp_entry_map.py 实测（6 连审全程用）**：`python "D:/Pentest/wp_entry_map.py" <插件目录>` 出口点分类/危险函数/权限函数/未过滤输入四类清单（**MSYS 坑：Windows 原生 python 吃 /d/ 路径会解析成 D:\d\，必须用 D:/ 或 D:\ 原生路径**），比肉眼 grep 快且不漏入口；脚本已随 skill 内置 `scripts/wp_entry_map.py`
  - **★ wp_entry_map REST 盲区（2026-08-11 bdvs-password-reset 案例）**：工具只抓 add_action/add_filter，**register_rest_route 端点完全不显示**——bdvs 三个 REST 路由（reset-password/validate-code/set-password）地图里入口点全空、权限函数显示 0 个（实际每个都有 permission_callback）。**判定法：地图跑完必须手动补 `grep -rn "register_rest_route"`，逐个看路由的 permission_callback——`__return_true`/`return true` = 未认证开放，`is_user_logged_in`/`current_user_can` = 登录/权限门。REST 类插件的核心面全在路由文件（api.route.*.php 模式），地图工具+手动 grep 双覆盖**
- **实战（2026-08-11，第 7-11 连审：wordpress-reset / wp-migration-duplicator / csv-import-and-exporter / bdvs-password-reset / export-media-as-zip，全放弃）**：
  - **重置/重置码类插件审计顺序**（wordpress-reset + bdvs）：先数防护链层数——wordpress-reset 1.5.0 五层（hidden=true + 人工确认词 + nonce + activate_plugins + SQL 全参数化 %i）；bdvs 密码重置四层（8位随机码 + 3次尝试限制共享计数器 + 角色白名单 + email 指定目标）。**重置类插件的核心问题永远是：谁能触发 + 码/令牌空间 + 尝试限制 + 目标选择**——四者齐 = 安全；任一缺失 = 认证绕过/提权/任意重置硬洞。bdvs 的尝试计数器 validate-code 与 set-password 共享（同 user meta）= 无独立绕过
  - **密码重置类"修复到位"特征**：码长度+字符集+随机源（random_int）+管理员排除+尝试限制，五件全 = 修复完整难挖（bdvs 0.0.16/0.0.17 案例）；只改一件 = 大概率漏修（继续挖其余）
  - **查重拦截案例**：wp-migration-duplicator（WebToffee 系列）已有 CVE-2023-45636（Missing Auth）+ CVE-2025-24651（敏感信息写日志）→ 直接排除，别浪费时间——**"没修过洞"筛选器筛出的目标也要过查重，WebToffee/常见厂商系列优先怀疑已披露**
  - **nopriv 注册 ≠ 可利用（csv-import-and-exporter 案例）**：`wp_ajax_nopriv_download` 注册了但 handler 整个逻辑包在 `if (isset(type) && is_user_logged_in() && wp_verify_nonce && (admin||editor))` 内，else 只加错误 → 未认证进不来。**判定法：读到 nopriv 先兴奋前，读完整 if 条件——登录/权限检查挡在前面 = 只是代码异味，实际不可利用**；同理菜单 capability 用老式 level_N（level_7=editor+）也要映射确认是否超范围
  - **固定路径 ZIP 半洞**（见上文评估法）；**连续 15 个插件 0 可交 → 换面**：High Threat 小插件池子已被筛透（防护好/被挖过/入口超范围），SQLi/Stored XSS 面（500装门槛，10k-50k 大插件）未系统性打过且是 semgrep 强项 → 战略转向 SQLi/XSS 面
  - **SQLi/XSS 面工具（2026-08-11 已实测两单：search-filter 50k装 + acf-better-search 40k装）**：`scripts/wp_filter_sqlxss.py` = 10k-50k 装大插件筛选器（18 个表单/搜索/动态输出类关键词：contact form/search/table/directory/listing/booking/membership/donation/quiz/survey/event/gallery/ajax/import/export/shortcode/subscription/order，按装量降序输出）；`scripts/wp_rules_sqli_xss.yaml` = semgrep 自定义规则（三条：wp-sqli-string-interp = $wpdb 调用字符串插值无 prepare、wp-sqli-concat = query/sql/where 变量拼接、wp-xss-echo-input = echo/print 直接输出 $_GET/$_POST/$_REQUEST），跑法：`semgrep.exe scan --config "D:/Pentest/wp_rules_sqli_xss.yaml" <插件目录>`（**MSYS 坑：semgrep.exe 是 Windows 原生，传 /d/ 路径报 "Invalid scanning root: \d\..." → 必须 D:/ 原生路径**），**跑前先 `semgrep --validate --config <规则文件>` 验证规则语法；写规则 YAML 时 message 值含中文冒号会解析失败 → 值必须引号包裹**。目标画像：表单/搜索/查询类插件（SQL 拼接面大）+ 短代码/前端输出类（XSS 面大），装量 10k+（SQLi/XSS 500 门槛全在范围，不要求老维护）
  - **SQLi/XSS 面实测结论（2026-08-11）**：① search-filter——posts_where 日期过滤用 `DateTime::createFromFormat('Y-m-d')` 严格解析 + `->format('Y-m-d H:i:s')` 重写 → **注入字符被格式化解毒**（format 只输出数字/-/空格/:），值走 slug 白名单；唯一发现 = `wp_redirect(esc_url($_POST))` 开放重定向（esc_url 允许外域，但 **Wordfence out-of-scope 不收 open redirect，见到即跳过**）。② acf-better-search——搜索词（`/?s=`）`_real_escape` 转义后拼 LIKE/REGEXP 字符串字面量 → **单引号/反斜杠都被转义，无法逃出字符串** = 无 SQLi。semgrep 3 规则两插件均 0 发现，与手工一致 → 工具可信。③ **规律：10k-50k 装大插件机械层基本干净（phpcs/WPScan 盯得紧）——SQL 全参数化/_real_escape、XSS 全转义是常态；"SQL 用老式裸拼接"的插件在 10k+ 池子极少，逻辑层（IDOR/认证绕过/多步流程）才是高发区**。④ 大插件 zip 经代理下载可能 60+ 分钟跑不完（quiz-master-next 案例）→ 杀进程换 SVN 单文件拉取或换目标，别傻等

## 靶场复现（Windows/phpStudy）
- 详细步骤/坑/表单构造：references/wp-lab-setup.md
- 核心：WP 6.x + PHP 8 + 插件最新版；构造最小表单（admin_form post + acf-field posts）走真实渲染；未认证（无痕）跑 PoC
- ACF 字段 post 结构：**post_name=字段key，post_excerpt=字段name，post_content=serialize(设置数组)**

## Wordfence 提交
- **提交前必须研究者审批（2026-08 实测）**：Wordfence 提交仅限 approved researchers——新注册账号资料处于 pending，提交会被拦（"Vulnerability submissions are currently limited to approved researchers"）。流程：注册 → 编辑 researcher profile → 人工审核（页面声明最长 72 小时）→ 通过后才能提交。资料填写要点：真实姓名（与注册邮箱一致）+ 专业简介（安全研究员/渗透方向），避免公司名/商用/广告内容（违反条款会被拒并邮件通知）
- **Wordfence 官方 API（免费，2026-08 实测端点）**：`https://www.wordfence.com/api/intelligence/v3/vulnerabilities`（v1/v2 已移除返回 410），需 `Authorization: Bearer <key>`（401 提示 \"API key must be supplied using a Bearer token\"），key 在账号 My Account → API Access 免费生成。数据比 NVD 全（含 Wordfence 自己收录），拿到 key 后把 `wp_check_cve.py` 升级为官方 API 查重
- **提交表单的 Vulnerability Type 是固定下拉**（约 20+ 项带滚动条，容易漏看）：Remote Code Execution/Code Injection、CSRF、Stored/Reflected XSS、SQL Injection、LFI/RFI、**Arbitrary File Download/Read**、Directory Traversal、PHP Object Injection w/o Gadget、Arbitrary File Upload、**Missing Authorization**、Sensitive Information Disclosure、Arbitrary File Deletion、Arbitrary Options Update、Authentication Bypass to Admin/Non-Admin、Privilege Escalation to Admin、Basic Information Disclosure、Arbitrary Shortcode Execution 等——P2 类授权缺失选 **Missing Authorization**，认证级别选 Unauthenticated；对应关系：文件读取=Arbitrary File Download/Read、信息泄露=Sensitive Information Disclosure
- **赏金预估**：金额不公开只有区间；类型×安装量档位三步预估；Core 不在 Wordfence 范围（走 HackerOne，最高 $12,500）——完整档位表/对比见 `references/bounty-estimation.md`
- 材料结构：SECTION 1-5（软件信息/漏洞详情含 FILE:LINE/复现步骤/PoC/影响）+ 附加信息表
- 必须附靶场端到端复现证据（HTTP 响应/数据库前后对比）
- **已披露 CVE 但不同根因 → 材料里主动区分（sliced-invoices P2 实战，2026-08）**：插件已有公开 CVE 但本洞影响不同（如 CVE-2025-31628=Patchstack 报的读发票 IDOR，本洞=未认证写操作/状态修改），提交材料附加信息表显式声明 "Confirmed different root cause: CVE only covers X; this vulnerability is Y (write operation)"——防审稿人一句 "already disclosed" 拒收。注意这只能降低拒收风险，不保证收录（同源判定权在审稿人）
- **让用户亲手复现（增强证据可信度 + 协作体验）**：交付 3 步操作——① 建测试数据（如建报价的 new_quote.php）② 跑 PoC 脚本（输出攻击链每一步：提取 nonce→POST→成功）③ 数据库验证（`SELECT ID, post_type` 前后对比，post_type 变化 = 攻击成功）。用户自己跑通 = 端到端证据链 + 用户亲自验证（材料里写"independently reproduced Nx"）
- **真实站点红线**：只做公开页面浏览（与访客一致）佐证场景；**只读探测**（如 `?submission=1` GET）需用户明确授权，且绝不修改/增加/删除任何数据；未授权的利用请求 = 违规且站点非己所有
- 真实站点只读探测流程（FOFA + curl）：
  1. FOFA 特征搜真实使用站点（插件路径 `acf-frontend-form-element` / action 名 `frontend_admin/form_submit`）导出 CSV
  2. 公开页面浏览确认插件加载（HTML 含 `acf-frontend`/`frontend-admin` 资源）
  3. 找表单页：页面 href 枚举 `?page_id=N`，`_acf_form` 隐藏域 = FEA 表单渲染特征（Elementor 构建页无此特征，表单在别处）
  4. 只读探测 `?submission=1..N` 判断保存提交是否开启
  5. **误报坑**：`item-title` 可能是主题 JS 模板（JetSearch `{{{data.title}}}`）不是提交渲染——必须对比有无参数的两个页面字节级差异，或确认响应含真实提交标题/字段值
- 场景佐证：用 FOFA 特征（插件路径/action 名）搜真实使用站点，抽查公开页面表单类型

## 红线
- 写操作（删除/创建）复现前先说明影响范围（删什么、能否恢复）
- 朋友的成果不提交（ChainQ 案例：参考案例与自有成果要分清）
- 不确定的洞宁可标 UNCERTAIN 不编造

## 合作模式与用户偏好（重要）
- **分工**：用户选目标插件 + 靶场复现验证 + 提交 Wordfence；我方做源码审计（架构推理→多 Agent 并行→组合链）+ PoC 编写 + 提交材料。用户要"一起合作"而非纯依赖——方法要教给他（找插件/changelog/评估流程），他可能自己跑脚本验证
- **审计进度落盘（防上下文爆掉失忆，2026-08 用户确认）**：每个插件在 `D:\Pentest\审计进度\<插件>.md` 建进度文件——结构图 / 已查面+结论+关键行号 / 待查面 / 卡点。每查完一个面就写入；跨会话/上下文压缩后读文件 10 秒恢复，不用重新推理。用户随时可打开检查
- **决策门（省 token 关键）**：粗扫（结构+端点+危险函数，~15 分钟）→ 先给用户结论"值得深挖还是换目标"→ 用户拍板才进深挖。大部分插件粗扫就该放弃（survey-maker/wp-user-manager/AFI 都是），避免全面审计的冲动
- **汇报格式（用户要求参与检查）**：每步汇报必须说清楚——审的代码文件、位置（FILE:LINE）、问题代码行内容、逻辑链、卡住的点；用户自己也会去看代码做决策和检查。只给结论不给证据链 = 不合格
- **不要默认用户是老手（2026-08 用户明确纠正"不要默认我是老手，我们是一起的"）**：讲解判断时要把"为什么"讲透（为什么这个插件没洞、FOFA 存活量为何只是必要非充分、为什么手动确认型网关无攻击面），不默认他懂专业术语/流程；平等协作语气，讲不清楚的判断就是没讲
- **规则/范围信息必须实时核实，不用知识库顶替（2026-08 用户严厉纠正）**：用户给官方链接（wordfence 范围页等）时，这是任务地基——curl 爬不到（Cloudflare 拦截）必须当场说"爬不到"，并申请 computer_use 浏览器查看或请用户截图，而不是沉默后用自己过时的知识库当真实信息。本会话因此白挖 10+ 插件（旧"1k-10k 甜区"规则已过时）。**"curl 失败 → 申请浏览器/截图"是硬流程，不是可选优化**
- 一轮一总结：每轮结束一句话（已查 X → 结论 Y → 建议 Z），用户只需回答"继续/换/深挖"
- **用户价值取向**："主要就是要能rce"——要 High-Threat 硬洞（未认证 RCE/提权/任意文件操作）；低价值洞（配置依赖重的 PII 泄露、目标受限的删除）别浪费提交名额，诚实给出"可交可不交"的定位
- 用户会质疑"这有什么意义/实际场景会这样吗"——先自查:洞是否默认配置可利用？真实站点开启率高吗？用真实站点证据（FOFA+只读探测）回答，不用构造数据说服
- 只读探测可做（用户明确授权"看信息没事，别改增删"）；批量探测被嫌弃（"就一个网站就行嘛"）——先测 1 个代表性站点再决定是否扩展

## 相关技能
- penetration-code-audit：通用代码审计（多 Agent 并行验证流程），本 skill 是其 WP 专项 + 赏金提交延伸
