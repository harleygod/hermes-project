# WordPress 上传 mime 校验实证判定

审计插件上传端点（`wp_ajax_nopriv_*add_attachment` 等）时，要判定"某扩展名能否通过校验"。
**不要凭记忆推断 WP core 函数语义** —— get_allowed_mime_types/wp_check_filetype 的行为随 WP 版本变过，
且审计前提常把 if/else 控制流读错。用 `scripts/wp-mime-sim.php` 跑真实逻辑（实证）。

## WP core 关键事实（WP 5.9 与 6.5 源码逐行比对确认）

1. `get_allowed_mime_types()` 返回**完整键值映射**（扩展名正则 => mime 类型），不是 array_keys。
   `in_array($mime_type, $map)` 匹配的是**值** —— 按此写判定时校验是有效的。
   （旧记忆"返回 array_keys 导致全拒"是错的；但若审计的代码把 type 与 keys 比，那才是逻辑 bug。）
2. **匿名用户（无 unfiltered_html）会被剔除 'htm|html'、'js'、'swf'、'exe'**（WP≥4.7.4 安全修复）
   → "未认证上传 html → 存储型 XSS"链在现代 WP 默认**不成立**（html 对匿名 type=false）。
   管理员（unfiltered_html）仍可传 html，那是认证场景，不算未认证链。
3. **版本差异**：WP≥6.5 的 `wp_check_filetype($name, null)` 默认 `$mimes = get_allowed_mime_types()`
   （匿名过滤后的表）；旧版默认 `wp_get_mime_types()`（全表）。审计按目标 WP 版本选源码比对。
   两条路径下 php 系都被拦，但 html 的判定结果依赖版本 → 必须实证。
4. **php/phtml/php5/pht/phar/php7 全部不在 wp_get_mime_types() 映射** → wp_check_filetype 返回
   type=false → 任何 "type ∈ allowed" 判定都拒绝。大小写变体（.pHp）一样被拦（无对应正则键）。
5. **双扩展名** shell.php.jpg：正则 `!\.(jpg)$!i` 匹配末段 → 校验**通过**；但插件落盘名普遍用
   `strrpos` 取**最后一个**扩展名（保存为 `shell.php-<uniqid>.jpg`）→ 直接请求不执行。
   仅 Nginx `location ~ \.php`（无 $ 锚）+ `cgi.fix_pathinfo=1` 配置下该 .jpg 可被 php-fpm 当 PHP
   执行（标 UNCERTAIN，服务器配置依赖，Apache 默认不执行）。
6. `sanitize_file_name`：去尾点（`|\.+$|`）、去 %/&/引号等、空格转 '-'、**前导点保留**
   （'.php' 经 pathinfo 扩展名='php'，仍被 type=false 拦）。

## 方法

1. 下载 WP core 源码（版本匹配目标站点；对比历史行为再拉一版旧源码）：
   ```
   curl -o wp-functions.php https://raw.githubusercontent.com/WordPress/wordpress-develop/6.5/src/wp-includes/functions.php
   curl -o wp-functions-59.php https://raw.githubusercontent.com/WordPress/wordpress-develop/5.9/src/wp-includes/functions.php
   ```
2. `php scripts/wp-mime-sim.php <wp-functions.php> [额外文件名...]`
3. **逐分支核对插件自己的 if/else**：常见反模式是 else 分支兜底在 `mime_types` 为空**或非空时都执行**
   （ACF Frontend class-upload-file.php:478-496）→ "字段 mime_types 含 php 即可绕过"类假设是错的，
   兜底里的 get_allowed_mime_types 判定仍会拦 php。任务/公告给的利用链前提必须回到代码逐行验证。

## 提取数组字面量的坑（脚本已内置处理）

- preg_match 提取函数体需要 `/s` 修饰符（`.` 不匹配换行）
- 函数体内 docblock 可能含 'array(' → 从 `'apply_filters('` 之后锚定 strpos
- 非贪婪 `.*?` 会在第一个 `'return apply_filters('` 处截断 body → 用完整 `$src` 从函数位置找，
  别用截断后的 `$body` 再 strpos
- execute_code 沙箱与 bash terminal 的 /tmp 不是同一个 → PHP 测试脚本用 write_file 写到真实路径
  （如 %LOCALAPPDATA%\Temp），再 terminal 执行

## 本会话验证结论（ACF Frontend / acf-frontend-form-element 3.29.10）

- `ajax_add_attachment`（nopriv）链：mime_types 为空或含 'php' 都走 else 兜底 → php 系全拦（实证 NO）
- html/js 匿名被剔除 → 存储型 XSS 链对未认证不成立；仅 admin 可传 html
- `maybe_mkdir` 写 index.php（防列目录）但 **unlink .htaccess** → fea-submissions 目录零保护，
  但落盘文件类型仍受限（安全类型直链）
- 字段 UI 的 mime_types 默认值 'php' 不构成漏洞：兜底检查与字段配置无关地拦 php
- 真正可报告的剩余面：双扩展名条件 RCE（Nginx fix_pathinfo，UNCERTAIN）、
  change_form 令牌铸造 → delete_object 任意删除、公开 add_user 表单 + 明文密码（服务端
  fea_encrypt/fea_decrypt 往返，role 仅拦 administrator）→ 未认证建号直接登录
