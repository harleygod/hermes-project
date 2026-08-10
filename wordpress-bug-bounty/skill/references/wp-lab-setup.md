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
