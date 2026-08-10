---
name: wordpress-plugin-audit
description: "WordPress 插件源码审计：未授权AJAX/上传直链/IDOR/用户枚举。只出漏洞不写修复。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, penetration, wordpress, code-audit, idor, unauthorized-access]
---

# WordPress 插件安全审计

触发场景：对 WordPress 插件目录（wp-content/plugins/ 或本地插件源码）做源码审计；用户给出具体漏洞假设要求逐条验证（"附件信息泄露""未授权上传""提交数据泄露""用户枚举"等）；查第三方插件未授权面。

## 核心原则

- 只出能拿权限/信息的漏洞（INFO_LEAK / CRED_LEAK / IDOR / UPLOAD），不写修复建议
- 输出格式：`FILE:LINE | 类型 | P0/P1 | 利用方式（≤200字符）`，最多 15 条，不确定标 `UNCERTAIN`
- 验证驱动：假设 → 定位函数 → 精准读行段 → 追鉴权 → 追数据流到输出
- 正面确认（有鉴权/安全）的项也列出，证明验证完整性；排除硬编码凭据时注明扫描范围（如"排除 freemius SDK 的 public_key，那是公开常量"）

## 工作流

1. **定位文件**：`find . -name "class-*.php" -o -name "crud.php" -o -name "list.php" -o -name "apis.php" -o -name "settings.php"`（插件命名规律：字段类 class-<name>.php、管理页 crud/list、第三方集成 apis/settings）
2. **端点注册全量列出**：`grep -n "wp_ajax" 文件` —— 一次看清 `wp_ajax_` 与 `wp_ajax_nopriv_` 同 action 注册
3. **函数行号**：`grep -n "function xxx" 文件` 再 read_file 精准读行段，不全读
4. **对每个假设端点四连问**：注册是否 nopriv？验证函数查什么？操作的对象是否可任意指定（ID 参数）？响应是否含敏感数据（URL/作者/字段值）？
5. **汇总**：去重、分级 P0(未认证) > P1(认证后可越权)、标 UNCERTAIN、给出根因条目（如共享 nonce 帮助函数）和正面排除项

## WordPress 特定检查清单

### A. AJAX 端点（最高频漏洞面）
- 同 action 名**同时查 wp_ajax_ 与 wp_ajax_nopriv_** 两行注册；nopriv = 未登录可达
- nopriv 存在 ≠ 有防护：必须追到实际验证函数看 nonce/权限逻辑
- ACF 字段类端点（gallery 取附件、文件上传、用户查询）是 nopriv 误注册高发区

### B. 共享匿名 nonce（判定关键）
- nonce 绑定 **uid 0 + 空 session token** → 全站共享且确定，任何渲染插件脚本的公开页面 HTML 可提取 → 只靠它的 nopriv 端点**实际等同未认证**
- 常见默认 action：`acf_nonce`（帮助函数如 feadmin_verify_ajax 默认值）
- 按字段 nonce：`wp_create_nonce('acf_field_<type>_<field_key>')` 渲染时生成，同样匿名共享；field_key 也出现在页面 HTML data 属性 → 可一并提取
- 判定规则：nonce 创建不绑定登录用户 ID/session → 共享 → 视为未认证

### C. 上传与直链
- 物理文件落在 `wp-content/uploads/<自定义目录>/` → 默认直链可下载（除非有 .htaccess/nginx 规则拦截，插件内 find 确认）
- 典型反模式：`maybe_mkdir` 类函数 mkdir 时加 index.php（只防列目录）**但 unlink 删除 .htaccess**（防直链失效）
- 文件名 `<原名>-<uniqid>.<ext>`：uniqid() 是 13 位十六进制时间戳，**可预测**（知道原名+时间窗可猜 URL）
- `wp_insert_attachment` 不设 post_author → 匿名上传附件 post_author=0
- **上传 mime/扩展名校验必须实证**，别凭记忆推断 WP core 语义：下载目标版本 WP 的 functions.php → `php scripts/wp-mime-sim.php` 跑插件判定逻辑。关键事实：get_allowed_mime_types() 返回完整映射（值=mime 类型）；匿名剔除 htm|html/js/swf/exe（WP≥4.7.4）→ 未认证传 html 的 XSS 链默认不成立；php 系扩展名不在映射 → 恒被拦；WP≥6.5 的 wp_check_filetype(null) 默认用 get_allowed_mime_types()（旧版用全表）。详见 `references/wordpress-upload-mime-verification.md`

### D. do_action 链上的 IDOR（高价值模式）
- 路径：nopriv handler → `do_action('xxx/ajax_add_form')` → 各模块 `add_action(同名, render_form)` → render_form **只比对 data_type 字符串、无 capability 检查** → 按任意 ID 取数渲染
- 数据加密存储（fea_encrypt 类）不构成防护：服务端解密后渲染出明文表单
- 钩同一 action 的同类模块（plans/subscriptions/related-items）逐一检查，可能全是洞

### D2. 鉴权短路绕过（capability 被设置变量短路，高价值）- 反模式：`if ( ! current_user_can( 'edit_user', $id ) && ! $allowed_by_settings ) { 拒绝 }` —— `!$var` 短路能力检查
- 审计 `$allowed_by_settings` 类变量**谁把它置 true**：常见根因 = 表单加载 + `apply_filters('show_form')` 放行；AJAX 上下文 Gutenberg/Bricks 构建器表单 `display=true` 无条件放行、`who_can_see='all'` 放行 → 未认证即可置 true
- **逐分支核对**：同函数有的分支用该变量、有的不用（如 term 分支改用字段配置 special_permissions）→ 不用的分支不构成绕过，报告必须区分成立/不成立分支
- 相邻分支能力对照：admin 分支有 `manage_options`、兄弟分支没有（options.php:60 vs 89-103）→ 缺失即漏洞
- 加密令牌（fea_encrypt 类）的**铸造端点**也要查：nopriv change_form 类端点 `is_numeric(item_id) → absint → save_to=edit_{type}` 可铸造任意对象令牌 → 令牌内容攻击者可控（delete_object 链的 _acf_objects 即此来源）

### D3. 渲染门控跳过（有数据即免检，高价值）
- 反模式：`if ( empty($form['submission']) ) { apply_filters('show_form'); if(!$form['display']) return; }` —— **特定字段非空时整段权限门控被跳过**
- 实例（ACF Frontend display.php:1328-1339）：提交记录渲染路径先置 `$form['submission'] = $id`，随后 render_form 因 submission 非空**跳过 show_form** → who_can_see 配置形同虚设 → 未认证读全站提交 PII（P0-3 链的二次放行点，与 do_action IDOR 叠加）
- 审计法：渲染函数开头找 `if ( empty($form['X']) ) { 权限检查 }` 模式，再追 X 在数据加载路径里是否必被赋值
- approval/审阅类 nonce 常见"无效仅降级不阻断"：`$nonce 无效 → $approval=false → 继续渲染`（不 return）→ 不是防护

### D4. 渲染参数直通（GET 参数进渲染函数，高价值但需实测可达性）
- 反模式：render_form 开头 `handle_get_params($form)` 处理 `$_GET` 参数（如 `?submission=<ID>`、`?edit=`），内部直接调数据加载函数（`submissions_handler->get_form($id)`）+ `get_all_fields_values` 输出全字段值——**无 nonce、纯 GET**，比 AJAX 入口更直接
- 实例：ACF Frontend display.php:1273-1304，`?submission=1,2,3...` 未认证枚举读取全站提交数据
- **必须实测可达性**：同端点其他 hook 订阅者可能抢先 `die()`（实例：add_form 的 do_action 被 related-items 组件（同 priority 先注册）无条件 `render_form→die` 拦截，submissions 渲染路径实际不可达——静态读码发现不了，靶场一跑即现形）。报告里标注"代码存在但被 XX 拦截/可达"

### D5. 新版本"修复"的边界误判（3.29.10 案例）
- 插件大版本补丁常以渲染阶段 conditions_logic 形式加闸门（current_user_can + special_permissions），**令牌铸造/删除端点受影响**——审计新版本必须先跑渲染链看闸门
- 典型误判残留：
  - 作者校验 `get_post_field('post_author', $id) == $user->ID`：未认证 `$user->ID=0`，**post_author=0 的文章（导入/迁移/CLI 创建）通过校验** → 未认证可删（配 force_delete 永久删除）
  - user 闸门无 is_author 豁免：渲染令牌时 `user_id` 被置 `'none'` → 删用户链默认不可达
  - 结论要写"能删 post_author=0 文章，删用户被拦"，不要笼统写"任意对象删除"

## 交付：Wordfence 提交材料（用户惯例）

审计目标产可上交漏洞平台（Wordfence）的材料。文件命名 `WORDFENCE_SUBMISSION_<漏洞名>_中文版.md`，结构：
- SECTION 1 软件信息表（slug/安装数/最新版本/受影响版本/修复版本）
- SECTION 2 漏洞详情：CWE、CVSS 3.1 向量、技术描述（编号引用代码行）、所需认证级别、前置条件统一清单（逐项标必需/可选）、受影响文件+代码片段
- SECTION 3 逐步复现（HTTP 请求逐条 + 验证方法）
- SECTION 4 PoC（浏览器控制台脚本，`URLSearchParams` 编码避免 + 号损坏，自动提取 nonce/枚举 ID/解析响应）
- SECTION 5 影响 + 附加信息表（与既有漏洞关系、是否已告知厂商、AI 辅助披露声明）
- **诚实标注**：静态审计未实跑必须写明"源码逐行确认，PoC 未线上执行"；写操作链（删除/创建）不擅自靶场实跑，等用户确认；CVSS 按未认证基准（删对象 9.1、PII 泄露 7.5、账户接管 9.8），非默认配置前提在材料中单列
- 分级参考：P0=未认证（对象删除/提交数据 PII/账户创建+自动登录），P1=登录低权限（订阅者越权 CRUD/附件枚举/用户枚举）

- nopriv 用户查询端点：search_columns 含 `user_email/user_login/user_nicename` → 邮箱/登录名前缀枚举
- 空搜索分页返回全部用户 ID + display_name；结果文本回退链 display_name → nicename → user_login

### F. 硬编码凭据扫描
- `grep -rn "password\|secret\|api_key\|token\|client_secret" main/ --include="*.php"`（排除 SDK 公开常量与语言包）
- 第三方 API 密钥存 option 且仅管理页明文显示 → 非漏洞（排除）；真正要查的是密钥是否被注入前端 HTML/JS（控件 default、localize、json_encode 输出）

## 工具陷阱（Windows 中文路径）

- `search_files`（ripgrep 后端）对含非 ASCII 字符的路径（如 `D:\Documents\sources\Wordpress插件\...`）**返回 0 结果**，不是没文件
- 改用 terminal：`find . -name "*.php"` 定位、`grep -n` 定位行号、read_file 精准读行段
- 内容搜索另一条路：execute_code + Python `subprocess.run(["rg","-n","-C",n,pattern,path], encoding="utf-8", errors="replace")` 直接传路径参数，可带上下文行
- 多文件独立读取可并行发起，减少往返

## 参考

- 靶场搭建（Windows/phpStudy 全坑：MySQL 自定义端口、PHP 版本兼容、fcgid 切换、active_plugins 序列化长度、after_setup_theme 双触发、acf-field post 结构、form_ 前缀加载差异、.maintenance 503）→ 见 wordfence-bug-bounty skill 的 `references/phpstudy-wordpress-lab.md`（本 skill 不重复维护）
- `references/acf-frontend-3-29-10-findings.md` — ACF Frontend (acf-frontend-form-element) 3.29.10 自由版 6 假设逐条验证明细（共享 nonce 根因、附件枚举链、submissions IDOR P0、上传直链、用户枚举、排除项）
- `references/acf-frontend-delete-object-chain.md` — delete_object 短路绕过链（nopriv 删任意用户/文章）、change_form 令牌铸造、options 分支对照、plans CRUD 缺能力检查，含精确行号
- `references/acf-frontend-submission-data-leak.md` — 未认证提交数据泄露链（P0-3）：add_form→do_action→get_form 无权限→render_form 跳过 show_form 门控，完整行号+同端点其他 data_type+第二期关联洞清单+Wordfence 提交材料指引
- `references/wordpress-upload-mime-verification.md` — 上传 mime 校验实证判定法：WP core 版本差异（get_allowed_mime_types 返回值/匿名剔除 html|js/php 系不在映射/wp_check_filetype(null) 语义）、双扩展名落盘取末扩展名、if-else 兜底恒执行陷阱、本会话 ACF Frontend 3.29.10 实证结论
- `scripts/wp-mime-sim.php` — 上传校验模拟器：下载 WP core functions.php 后跑 `php wp-mime-sim.php <path> [额外文件名...]`，输出每个扩展名的 wp_check_filetype type 与插件式判定 PASS/NO（含匿名/双扩展名/大小写变体）

## 陷阱

- 大文件先 grep 函数行号再读行段，不要全读（class-*.php 常 1000+ 行）
- 管理端页面（add_submenu_page + manage_options）默认有权限保护，别误报；重点查被 nopriv 化的端点
- **别信任务/公告给的利用链前提**：逐分支核对 if/else —— 反例：ACF Frontend validate_attachment 的 else 兜底在 mime_types 为空或非空时都执行，"mime_types 非空只做 in_array"是错误假设；上传校验结论一律用脚本实证
- 输出条目必须带 FILE:LINE；利用方式简述不写代码块/表格
- 不确定的写 `UNCERTAIN: 原因`，不编造结论
- **旧报告污染**：项目目录有历史审计报告时，读完会把已报告链划为"已知项"停止独立推导——把旧报告当"验证清单"而非"划掉清单"，对已报告根因强制做变体穷举
- **倒推优先**：端点正推（哪些 nopriv 端点→缺陷）容易漏提权链；先倒推"未认证拿权限的最短路"（权限来源→触发点→注入通道）再进端点扫描
- **子 Agent 静态盲区**：多 Agent 并行只能读码，执行顺序/注册顺序问题（同 hook 同 priority 谁先注册、谁抢先 die）必须靶场实测；静态结论标注"未实测"
