# Windows/phpStudy WordPress 插件靶场搭建与复现坑

本会话（2026-08-07）从零重建靶场并复现 FEA 3.29.10 两个漏洞，以下均为实测结论。

## 环境事实（本机）
- phpStudy: `D:\phpstudy_pro`（Apache2.4.39 + MySQL5.7.26 + Nginx1.15.11 + PHP）
- **MySQL 端口 = 6778**（my.ini `port=6778`，非 3306！wp-config 的 DB_HOST 必须 `127.0.0.1:6778`）
- 默认 PHP 7.3.4 太老：WP 7.x 要求 7.4+；ACF Frontend 捆绑 ACF 用了 PHP 8 语法（class-acf-site-health.php:23 parse error）→ 必须换 PHP 8
- 最终环境：PHP 8.0.30 + WordPress 6.6.2 中文版 + 插件 3.29.10

## 切换 PHP 版本
1. 下载 `php-8.0.30-nts-Win32-vs16-x64.zip`（windows.php.net/releases/archives/，走 socks5h 代理），解压到 `Extensions/php/php8.0.30nts/`
2. `cp php.ini-development php.ini`，启用 `extension_dir="ext"` + mysqli/curl/openssl/mbstring/gd/fileinfo 等
3. 改 `Extensions/Apache2.4.39/conf/vhosts/0localhost_80.conf` 里 FcgidInitialEnv/FcgidWrapper 指向新目录
4. 重启 Apache：**git-bash 杀进程必须 `MSYS_NO_PATHCONV=1 taskkill /F /IM httpd.exe /T`**（`//F` 写法不生效；`taskkill /F /IM` 不带转换会因路径转换失败）。杀干净（含 php-cgi.exe）再 `httpd.exe -d D:/... -f .../httpd.conf` 后台启动

## WordPress 安装
- 下载 `downloads.wordpress.org/release/zh_CN/wordpress-6.6.2.zip`（socks5h 代理）解压到 WWW
- wp-config.php：DB_NAME/USER/PASSWORD（root/root）/DB_HOST=`127.0.0.1:6778`
- 安装：`curl -X POST "http://localhost/wp-admin/install.php?step=2" -d "weblog_title=...&user_name=admin&admin_password=...&admin_email=...&blog_public=0"`
- 503 "维护" = `.maintenance` 文件残留（WP 维护模式），删除即可

## 激活插件（不走后台 UI）
- 直接 SQL 更新 `wp_options.active_plugins`：**序列化长度必须精确**（`s:42:"acf-frontend-form-element/acf-frontend.php"`，写错长度 → maybe_unserialize 失败 → 插件不加载，`wp_get_active_and_valid_plugins()` 返回 0）。验签：`a:1:{s:42:"...";s:42:"...";}`
- **每加一个插件重新数每个 slug 长度**（2026-08 两次栽坑）：`survey-maker/survey-maker.php` = 29（写过 28），`acf-frontend-form-element/acf-frontend.php` = 42（写过 41）。多插件时：`a:2:{s:42:"...";s:42:"...";s:29:"...";s:29:"...";}`。验证：`is_plugin_active('slug')` 为 true 才算激活成功
- **主文件判定坑（wp-file-upload 案例）**：active_plugins 的路径必须是"定义插件常量并 include loader 的主文件"，不一定是目录同名文件——`wp-file-upload/wordpress_file_upload.php` 定义 `WPFILEUPLOAD_PLUGINFILE` 并 require `wfu_loader.php`；而 `wfu_loader.php` 开头 `if (!defined("WPFILEUPLOAD_PLUGINFILE")) return;` 直接退出。把 `wfu_loader.php` 填进 active_plugins 会出现插件功能不加载（shortcode 不存在）但 is_plugin_active 可能显示正常的假象。判定插件真生效：`shortcode_exists('wordpress_file_upload')` 为 Y（或手动 include 主文件后类/短代码存在）

## 插件初始化链（FEA 特有）
- 插件 init 挂 `after_setup_theme` priority 11（include plugin.php → new Plugin），plugin_includes 挂 priority 12（include helpers.php 等）
- **wp-load.php 不触发 after_setup_theme** → 脚本里要 `do_action('after_setup_theme')` **两次**（一次只触发 priority 11，12 不会在 do_action 执行中途注册后补跑）
- 验证：`function_exists('fea_encrypt')` 为 Y 才算完整加载

## FEA 表单数据库结构（脚本构造，等价后台创建）
- 表单 = `admin_form` post：`post_content = maybe_serialize(配置数组)`，meta `form_key` = 唯一 key
  - 配置数组例：`['save_to_post'=>'new_post', 'who_can_see'=>'all', 'custom_fields_save'=>'post', ...]`
  - who_can_see='all' → 未认证可见（permissions.php 读 settings 直接放行）
- 字段 = `acf-field` post，post_parent = 表单 ID：
  - **post_name = 字段 key（field_xxx）**，**post_excerpt = 字段 name**，post_content = serialize(设置数组含 key/name/type/label)
  - 顺序：post_name=key 在前（get_field 按 key 查 post_name）
- 表单加载差异（关键坑）：
  - **数字表单 ID**：`get_form(数字)` → get_form_args 直接返回，**不触发 load_data**（post_id/user_id 不解析）
  - **form_ 前缀 key**（form_key meta 值以 form_ 开头）：走完整流程（get_form_args → validate_form → get_form_data → load_data）
  - 短代码 `[frontend_admin form="数字ID"]` → get_form_args(数字) OK；传非数字 key 字符串会 PHP 报错（post_type on string）

## 复现验证要点
- 匿名 nonce：`wp_create_nonce` 对 uid 0 + 空 token 全站一致 → 页面 HTML `"nonce":"(\w+)"` 提取即可复用
- 删除按钮 nonce：`fea_delete_{field_key}`，渲染按钮时生成（data-nonce 属性）
- **运行时拦截验证**（静态分析盲区案例）：
  - `frontend_admin/ajax_add_form` 有多个订阅者（related-items 先注册且**无条件 die()**）→ add_form 路径被抢先拦截，静态成立的 submissions 渲染链实际不可达
  - 3.29.10 的 conditions_logic（ActionUser/ActionPost）在令牌铸造渲染时校验权限：未认证 → user_id 置 'none'（删用户被拦）；post 的 is_author 校验 `post_author == $user->ID`，未认证 $user->ID=0 → **post_author=0 的文章误判为作者可删**（修复遗漏）
- curl -o /tmp/xxx 在 git-bash 下不稳定（Windows curl 不认 /tmp），用当前目录相对路径
- **localhost curl 301/503 坑（2026-08-14 实测）**：`curl http://localhost/?page_id=10` 直接 301/503（Apache 虚拟主机解析问题），必须 `curl -sL -H "Host: localhost" "http://127.0.0.1/?page_id=10"` 才 200；表单页面抓下来后 `grep -o 'data-key="[^"]*"'` / `grep -o 'name="_acf_nonce"[^>]*value="[^"]*"'` 验证渲染
- **MySQL CLI 直查（2026-08-14 实测）**：`/d/phpstudy_pro/Extensions/MySQL5.7.26/bin/mysql.exe -uroot -proot wordpress_test -e "SQL"`（本靶场 DB=wordpress_test，root/root；mysql 命令不在 PATH 需全路径；密码警告可忽略）。查表单配置：`SELECT post_content FROM wp_posts WHERE ID=<表单ID>;`（admin_form 的 post_content = serialize(配置数组)，看 save_to_post/who_can_see/no_kses）；查字段：`SELECT ID,post_title,post_type FROM wp_posts WHERE post_type='acf-field' AND post_parent=<表单ID>;`
- **FEA 表单 kses 默认值（2026-08-14 核对 display.php:289）**：`'kses' => isset($form['no_kses']) ? !$form['no_kses'] : true` —— 表单配置**没有 no_kses 键 = 清洗默认开启**；复现块注释注入类链必须让表单配置含 `no_kses=1`（模拟后台勾选 Allow Unfiltered HTML）。完整 ChainQ 提权链前置条件矩阵见 `references/fea-chainq-privesc-chain.md`

## FEA 表单提交重放四大坑（2026-08-14 ChainQ 端到端复现实测，每个都白耗过时间）

**方法论铁律：重放多步 AJAX 链时，第一步先完整复刻真实浏览器的请求**（抓页面全部 hidden 字段原样带上 + 按端点选对 nonce），不要凭报告手搓部分参数逐步试错——`_acf_objects`、nonce 类型、form_key 前缀这三个缺失都会造成"表单成功但没建对象"的假象，逐个排查极费时（本会话用户等到不耐烦）。

1. **★ 源码双副本陷阱（最耗时的坑）**：`D:\Documents\sources\Wordpress插件\<slug>\` 是审计用的**源码副本**，靶场真正运行的是 `D:\phpstudy_pro\WWW\wp-content\plugins\<slug>\` —— 两个独立目录！往源码副本里加 debug 日志/改代码**完全不影响靶场行为**。判同否：`ls -i` 对比 inode。改插件代码必须改**运行实例**那份（wp-content/plugins/ 下）。
2. **★ `_acf_objects` 隐藏字段必须带**：表单提交时服务端靠它决定保存目标。页面 `<div class="acf-form-data">` 里的 `_acf_objects` = fea_encrypt(JSON)，解密内容如 `{"post":"add_post"}`（渲染时由 post_id 决定，new_post 时=add_post）。**POST 提交不带它 → success=True 但 record['post'] 始终 false → ActionPost::run() 直接 bail，文章不建**（服务端没有任何报错，最坑的假象）。脚本要 `dict(hidden)` 全量带上所有 `_acf_*` 字段。
3. **★ nonce 分两种，别混用**：
   - `form_submit` 用页面 hidden 的 `_acf_nonce`（表单 id + '_form' 动作）
   - `change_form`（display.php change_form()）用页面 JSON 里的 `"nonce":"..."`（即 `acf.data.nonce`，`wp_verify_nonce(nonce,'acf_nonce')` 校验）——**用错返回 Authentication Error**
   - 抓页面时两个都要提取：`re.search(r'"nonce":"(\w+)"', html)` 与 `re.search(r'name="_acf_nonce"[^>]*value="([^"]+)"', html)`
4. **★ form_key 必须 `form_` 前缀**：页面渲染的 `_acf_form` 值来自表单 form_key meta。**form_key 无 `form_` 前缀（如 'public_submit'）→ 渲染正常但提交时 `get_form('public_submit')` 返回 false → "No Form Data"**；数字 ID 提交走 get_form_args 直接返回**不触发 load_data**（post_id 不解析）。正确组合：短代码用数字 ID（`[frontend_admin form="6"]` 渲染），form_key meta 设成 `form_xxx`（提交路径才走 validate_form→load_data→post_id='add_post'）。改库：`UPDATE wp_postmeta SET meta_value='form_public_submit' WHERE post_id=<表单ID> AND meta_key='form_key';`
- 改库新增 post_content 类型字段：`INSERT INTO wp_posts (...) VALUES (... 'field_pub_content' ..., 'acf-field', 6, ...)`，post_content 序列化数组含 `s:4:"type";s:12:"post_content"`（MySQL 5.7 严格模式 post_excerpt 无默认值会报 1364，INSERT 要带全列）

## 插件代码调试（2026-08-14 实测流程）
- **WP_DEBUG 默认 false → 没有 debug.log**：`wp-config.php` 加 `define('WP_DEBUG', true); define('WP_DEBUG_LOG', true); define('WP_DEBUG_DISPLAY', false);` 后 `wp-content/debug.log` 才产生
- 插件自带 `error_log('[FEA_PREVIEW_DEBUG] ...')` 埋点（submit.php/display.php）——直接看这些日志就能跟踪提交流程，比自己加日志快
- 要加临时日志：加在**运行实例**（wp-content/plugins/ 下），且 **PHP opcache 缓存旧代码 → 改完必须重启 Apache** 才生效
- 重启 Apache（phpStudy 非服务方式）：`taskkill /F /IM httpd.exe`（`//F` 写法无效）→ 后台起 `httpd.exe -d "D:\phpstudy_pro\Extensions\Apache2.4.39" -f "D:\phpstudy_pro\Extensions\Apache2.4.39\conf\httpd.conf"`——**必须原生反斜杠路径，`/d/...` 会被 MSYS 转换导致 "Could not open configuration file"**
- CLI 调插件函数：phpStudy 的 php.exe（PHP 7.3 太老跑不了 WP 7.x，用 `php8.0.30nts/php.exe`）require wp-load.php；但 CLI 环境 wp-load 可能因"requirements not met" 失败 → 用 HTTP 端点方式（临时 php 文件放 WWW 下 curl 访问）更稳
