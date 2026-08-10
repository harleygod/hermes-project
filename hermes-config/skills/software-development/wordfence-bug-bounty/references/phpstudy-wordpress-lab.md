# phpStudy/Win 本地 WordPress 靶场搭建与复现细节

> 2026-08 实测:WordPress 6.6.2 + PHP 8.0.30 + MySQL 5.7.26 + Apache 2.4.39(phpStudy Pro),复现 ACF Frontend 3.29.10 漏洞链。

## 环境要点(全是坑)

- **MySQL 端口不是 3306**:phpStudy 自定义 `my.ini` 里 `port=6778`。WP 的 `DB_HOST` 必须写 `127.0.0.1:6778`。
- **PHP 版本**:最新 WP(7.x)要求 PHP ≥7.4,且很多插件捆绑的 ACF/依赖用 PHP 8 语法——本机 PHP 7.3 直接 Parse error。**下载 PHP 8.0.30**(`windows.php.net/downloads/releases/archives/php-8.0.30-nts-Win32-vs16-x64.zip`,走 socks5h 代理)解压到 `Extensions/php/php8.0.30nts/`,改 `Extensions/Apache2.4.39/conf/vhosts/0localhost_80.conf` 的 `FcgidInitialEnv PHPRC` + `FcgidWrapper` 指向新目录。改完**必须彻底杀 Apache**(见下)。
- **git-bash 杀进程**:`taskkill //F //IM httpd.exe` 无效;用 `MSYS_NO_PATHCONV=1 taskkill /F /IM httpd.exe /T`。不杀干净旧 httpd 还占 80 端口,新配置不生效。
- **git-bash 跑 Windows 程序**:PHP CLI 等必须用反斜杠原生路径(`"D:\...\php.exe"`);`curl -o /tmp/x.html` 在 git-bash 下文件会丢(Windows curl 不认识 /tmp),用相对路径或 Windows 路径。
- **.maintenance 文件**:WP 升级残留会导致全站 503"维护",删掉 `WWW/.maintenance`。
- **active_plugins 序列化长度**:SQL 直改 `wp_options.active_plugins` 时字符串长度必须精确(`s:42` 不是 `s:41`),否则 maybe_unserialize 失败 → 插件"已激活但不加载"(`wp_get_active_and_valid_plugins()` 返回 0)。

## WordPress 安装

```bash
# 下载(国内走 socks5h 代理)
curl -sL --socks5-hostname 127.0.0.1:7890 "https://downloads.wordpress.org/release/zh_CN/wordpress-6.6.2.zip" -o wp66.zip
# 解压到 WWW,改 wp-config.php(DB_NAME/DB_USER=root/DB_PASSWORD=root/DB_HOST=127.0.0.1:6778)
# 安装(两步:GET 初始化 → POST 完成)
curl "http://localhost/wp-admin/install.php" -c /tmp/c.txt
curl -X POST "http://localhost/wp-admin/install.php?step=2" \
  -d "weblog_title=LAB&user_name=admin&admin_password=X&admin_password2=X&admin_email=a@b.c&blog_public=0"
```

## 插件加载时机(诊断 fea_encrypt MISSING)

- 插件 `Front_End_Admin::init` 挂 `after_setup_theme`(priority 11),`Plugin::plugin_includes` 挂 priority 12——**wp-load 不触发 after_setup_theme**。
- setup/debug 脚本里要 `do_action('after_setup_theme')` **两次**(一次触发 init→构造注册 12,再一次触发 plugin_includes→helpers.php 加载)。
- 判定顺序:`class_exists('Frontend_Admin\Plugin')` 存在 ≠ helpers 函数存在。

## ACF 字段数据库结构(acf-field post)

- **post_name = field key**(如 `field_pub_title`),**post_excerpt = field name**(如 `post_title`)——搞反字段不渲染
- post_content = maybe_serialize(字段设置数组:key/label/name/type/...)
- post_parent = 所属表单(admin_form post)的 ID
- 表单 admin_form post:post_content = maybe_serialize(表单配置数组),meta `form_key` = key

## FEA 表单加载路径(复现链关键)

- `get_form(数字ID)` → get_form_args **直接 return,不经 load_data**(对象 ID 不解析!)
- `get_form('form_xxx')`(带 form_ 前缀)→ 走 meta 查询 → validate_form → load_data ✓
- **短代码 `[frontend_admin form="非数字key"]` 有 bug**:直接 `get_form_args($key)` 对字符串报错;短代码传数字 ID 才正常(渲染时 render_form→validate_form→load_data 会执行)
- load_data 决定 post_id/user_id:select_post/select_user/url_query/current_post 等

## 复现 PoC 要点

- **匿名 nonce 全站共享**(uid 0 + 空 token):任何页面提取的 acf_nonce / fea_delete_{key} nonce 对所有未认证请求有效;可硬编码(wp_create_nonce 在匿名上下文生成的值)
- 提取页面 nonce 正则:`"nonce":"(\w+)"` 或 `name="_acf_nonce" value="..."`;删除按钮:`data-nonce="([a-f0-9]{10})"`
- 令牌(change_form 铸造的 _acf_objects)可解密验证:`fea_decrypt()` 看内容(实测曾出现 `{"user":"none"}` = 被 conditions_logic 拦截)
- 复现脚本放 WWW 下用 Python 跑(urllib 即可),证据保存响应 HTML

## 本次 FEA 3.29.10 复现结果(供参考)

- **P0-3 提交数据泄露**:`GET /?page_id=<表单页>&submission=<ID>` 枚举 1..N → 未认证读取全部提交字段值(姓名/电话/邮箱/地址)。入口:display.php handle_get_params(1273-1304)→ submissions get_form(解密 fea_encrypt)→ get_all_fields_values 输出。前提:保存提交开启 + 表单 who_can_see=all
- **P0-1 删除**:delete_object(nopriv)短路 → 只能删 **post_author=0** 的文章(conditions_logic 的 `is_author = post_author == $user->ID(0)` 误判);删除用户/非零作者文章被 3.29.10 拦截
- add_form → submissions 渲染路径被 related-items 无条件 die() 拦截,不可用(静态分析会漏)
