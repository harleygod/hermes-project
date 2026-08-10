# phpStudy Windows 靶场搭建(WordPress 插件复现)

2026-08-07 实战验证环境:phpStudy_pro(D:\phpstudy_pro)+ WordPress 6.6.2 中文版 + PHP 8.0.30 + MySQL 5.7.26 + Apache 2.4.39。

## 全套坑(按踩坑顺序)

### 1. MySQL 端口不是 3306
phpStudy 自定义端口:查 `Extensions/MySQL5.7.26/my.ini` 的 `port=6778`。
wp-config.php 的 DB_HOST 必须是 `127.0.0.1:6778`,否则 PHP 连接被拒(即使 mysqld 在跑)。
启动:`Extensions/MySQL5.7.26/bin/mysqld.exe --defaults-file="D:/phpstudy_pro/Extensions/MySQL5.7.26/my.ini" --console`(background=true)。

### 2. PHP 版本必须 ≥ 7.4/8.0
- 新版 WordPress(7.x)要求 PHP ≥ 7.4,装完报 "requires at least 7.4"
- 用 PHP 8 语法(属性类型/构造器提升)的插件在 PHP 7.3 直接 Parse error(如 ACF Frontend 捆绑 ACF 的 class-acf-site-health.php)
- 解法:下载 PHP 8.0.30 nts 到 `Extensions/php/php8.0.30nts/`(解压 + cp php.ini-development php.ini 启用 mysqli/curl/openssl/mbstring 等扩展),改 `Extensions/Apache2.4.39/conf/vhosts/0localhost_80.conf` 的 `FcgidWrapper` 指向新 php-cgi.exe
- 下载源:`https://windows.php.net/downloads/releases/archives/php-8.0.30-nts-Win32-vs16-x64.zip`(socks5h 代理)

### 3. git-bash 杀 Windows 进程
`taskkill //F //IM httpd.exe` 在 git-bash 无效(旧进程仍占 80 端口);`cmd //c "taskkill ..."` 也失效。
正确:`MSYS_NO_PATHCONV=1 taskkill /F /IM httpd.exe /T`(以及 php-cgi.exe)。
改 Apache/PHP 配置后必须杀干净再重启,否则 fcgid 用旧 PHP。

### 4. WordPress 安装
- 下载:`https://downloads.wordpress.org/release/zh_CN/wordpress-6.6.2.zip`(downloads 域走代理可下;latest.zip 主域 SSL 常失败)
- 解压到 WWW,cp wp-config-sample.php wp-config.php,替换 DB_NAME/USER/PASSWORD/HOST(注意 6778 端口)
- 安装:`curl -X POST "http://localhost/wp-admin/install.php?step=2" -d "weblog_title=LAB&user_name=admin&admin_password=...&admin_email=...&blog_public=0"`
- 建库用 `CREATE DATABASE ... CHARACTER SET utf8mb4`(先 DROP 旧的避免重复安装)

### 5. 插件激活(序列化长度坑)
`UPDATE wp_options SET option_value='a:1:{s:42:"acf-frontend-form-element/acf-frontend.php";s:42:"...";}' WHERE option_name='active_plugins'`
- **序列化长度必须精确**:s:41 与 s:42 差一个字符,maybe_unserialize 失败 → active_plugins 是字符串 → 插件不加载(wp_get_active_and_valid_plugins 返回 0)
- 验证:`wp_get_active_and_valid_plugins()` count 应为 1

### 6. 插件初始化时机(wp-load 不触发)
- 插件主文件 `add_action('after_setup_theme', init, 11)`;init 里 new Plugin → 构造里 `add_action('after_setup_theme', plugin_includes, 12)` → helpers.php 才加载
- 用 web 执行 setup 脚本时,`require wp-load.php` 后需 `do_action('after_setup_theme')` **两次**(第一次触发 init/priority 11,第二次触发 plugin_includes/priority 12),fea_encrypt 等函数才可用
- 验证:`function_exists('fea_encrypt')`

### 7. FEA 表单数据库结构(ACF Frontend)
- 表单 = `admin_form` post:post_content = serialize(表单配置数组,含 save_to_post/save_to_user/who_can_see/form_conditions 等),meta `form_key`
- 字段 = `acf-field` post,挂在表单下(post_parent = 表单 ID):
  - **post_name = 字段 key**(field_xxx),**post_excerpt = 字段 name**,post_title = label,post_content = serialize(设置数组含 key/name/type)
  - 注意与直觉相反:key 在 post_name,name 在 post_excerpt(ACF 5.x acf_get_raw_field 逻辑)
- who_can_see=all 直接放行未认证(permissions.php conditions_logic 读 $settings['who_can_see'])

### 8. 短代码 form 参数陷阱
- `[frontend_admin form="<数字ID>"]`:get_form_args(数字) 直接返回,**不触发 load_data**(post_id/user_id 不解析,删除按钮等依赖对象 ID 的字段不渲染)
- `form="form_xxx"`(带 form_ 前缀):走 meta 查询 + validate_form → load_data 正常,但 get_form_args 对非数字字符串直接报错("post_type on string")
- 渲染删除按钮需对象 ID 数字:表单配置 post_to_edit=select_post + select_post=<ID>(或 url_query)

### 9. 常用调试手法
- 所有 setup/debug 脚本放 WWW 下,curl 访问(web 环境插件完整加载);不要用 PHP CLI(git-bash 路径转换坑 + 无 wp 环境)
- 验证洞:匿名 nonce 从公开页面 `"nonce":"(\w+)"` 提取;删除按钮 nonce 从 `data-nonce="([a-f0-9]{10})"` 提取(匿名全站一致)
- 令牌解密验证:写 dec.php 调 fea_decrypt 看铸造的 _acf_objects 内容(能发现 user_id 被渲染时 conditions_logic 置 'none')
