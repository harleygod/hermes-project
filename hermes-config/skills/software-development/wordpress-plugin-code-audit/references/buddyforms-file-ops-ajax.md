# BuddyForms 2.9.0 — 未认证 AJAX 文件操作面审计

来源：对 buddyforms_src/buddyforms 2.9.0 的 7 个 nopriv 端点 + file_put_contents 写点深挖。只读审计，无写入。

## 端点注册总览（nopriv 全量）

```
includes/functions.php:1325  wp_ajax_nopriv_handle_dropped_media        → buddyforms_upload_handle_dropped_media
includes/functions.php:1375  wp_ajax_nopriv_handle_deleted_media        → buddyforms_upload_handle_delete_media
includes/functions.php:1401  wp_ajax_nopriv_upload_image_from_url       → buddyforms_upload_image_from_url
includes/gdpr.php:143        wp_ajax_nopriv_buddyforms_gdpr_data_request → buddyforms_gdpr_data_request
includes/form/form-ajax.php:24   wp_ajax_nopriv_bf_load_taxonomy            → buddyforms_ajax_load_taxonomy
includes/form/form-ajax.php:94   wp_ajax_nopriv_buddyforms_ajax_process_edit_post → buddyforms_ajax_process_edit_post
includes/form/form-ajax.php:221  ajax_delete_post 的 nopriv 已被注释 → 仅登录可用，无未认证面
```

枚举命令：`grep -rn "nopriv" --include="*.php" .`（中文路径下用 terminal grep，search_files 会 IO error）。

## 端点逐条结论

### 1. upload_image_from_url（金矿候选：无 nonce + 无权限检查）
functions.php:1401-1414：函数开头只有 phar:// php:// 过滤，**无 check_ajax_referer、无 current_user_can**，未认证直接可调。
```php
$valid_url = strtolower( $url );
if ( strpos( $valid_url, 'phar://' ) !== false || pathinfo( $valid_url, PATHINFO_EXTENSION ) === 'phar' || strpos( $valid_url, 'php://' ) !== false ) {
    return false;
}
```
functions.php:1422-1436：远程下载 → getimagesize 校验 → wp_upload_bits 落盘。
```php
$image_data = wp_remote_retrieve_body( $url_response );
$image_data_information = getimagesize( $image_url );
$image_mime_information = $image_data_information['mime'];
if ( !in_array( $image_mime_information, $accepted_files ) ) { ... die; }
if ( $image_data && $image_data_information ) {
    $file_name = $file_id . '.png';          // ← 扩展名强制 .png
    $upload_file = wp_upload_bits( $file_name, null, $image_data );
```
关键判定链：
- **sanitize_text_field 不删除 `../` 和 `/`**（functions.php:1409 `$file_id = sanitize_text_field(...)`）→ $file_id 可含路径穿越，`wp_upload_bits` 内部 `$upload['path'] . '/' . $filename` 直接拼接、wp_unique_filename 不清理 `../` → 可写 uploads（含年月子目录）之外。
- **扩展名被强制 `.png` 后缀**（`$file_id . '.png'`）→ 无法直接写 .php → 直接 RCE 被挡。攻击者可写"GIF89a 头 + PHP payload"（getimagesize 只验 mime，accepted_files 参数攻击者可控）到任意可写路径的 .png 文件。
- SSRF 超范围；归类为"未认证任意文件写（受限 .png 扩展名）"+ SSRF。

### 2. process_edit_post（未认证任意文章内容篡改，需 public_submit 表单）
form-ajax.php:93-107：nopriv 注册，无端点级 nonce；`parse_str($_POST['data'])` 后 `$_POST = $form_data`（字段全可控，含 post_id/form_action）。
```php
add_action( 'wp_ajax_nopriv_buddyforms_ajax_process_edit_post', 'buddyforms_ajax_process_edit_post' );
function buddyforms_ajax_process_edit_post() {
	...
	if ( isset( $_POST['data'] ) ) {
		parse_str( filter_var( wp_unslash( $_POST['data'] ), FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES ), $form_data );
		$_POST = $form_data;
	}
	$args = buddyforms_process_submission( $form_data );
```
链：form-control.php:114-116 验 `buddyforms_form_nonce`（nonce 经 form-render.php:254 `wp_nonce_field` 公开输出，任意表单页可提取）→ form-control.php:372-374 public_submit 表单 `$user_can_edit = true` → **line 273 `if ( is_user_logged_in() )` 使未认证跳过 post_type 匹配检查** → post_id 攻击者可控（form-control.php:35-48 extract）→ form-control.php:626 `wp_update_post($bf_post)` 覆盖任意 post_id 的标题/内容/状态。→ 未认证文章篡改/存储 XSS（前提：站点存在 public_submit 表单，BuddyForms 常见配置）。

### 3. handle_dropped_media（未认证上传，WP MIME 白名单兜底）
functions.php:1328 `check_ajax_referer( 'fac_drop', 'nonce' )` — nonce 经 form-assets.php:192 `'ajaxnonce' => wp_create_nonce( 'fac_drop' )` 前端公开输出 → 防护形同虚设。
functions.php:1332-1353：`public_submit` 表单 → 未认证可进；`media_handle_upload($file_id, 0)` 有 wp_check_filetype_and_ext MIME 白名单 → **直接传 .php 被拒**。未认证 + 批量上传任意 WP 允许类型（SVG 若站点放行则存储 XSS）。无上传字段与表单配置一致性校验、无数量限制。

### 4. gdpr_data_request（human 验证可绕过，低危邮件滥用）
gdpr.php:94-102：human 验证 key = `N000M`（两个 rand(1,9) 拼接）**藏在页面隐藏字段**（gdpr.php:46），攻击者读页面即自算答案；nonce 同样公开（gdpr.php:47）。
gdpr.php:126-134：`wp_create_user_request($email, $type)` + `wp_send_user_request()` → 未认证向任意邮箱发起 GDPR 请求/确认邮件（滥用）。导出数据需邮箱确认，不直接泄露 PII。

### 5. handle_deleted_media（有归属校验，不可任意删）
functions.php:1378-1387：nonce 公开但 **`$post->post_author == $current_user->ID` 归属校验**；未认证 ID=0 仅能删 author=0 的附件（通常不存在）。`$post` 为 null 时 PHP8 `null==0` 为 true 但 wp_delete_attachment(null) 不删任何东西 → 无效。

### 6. bf_load_taxonomy（低危：私有 taxonomy 术语枚举）
form-ajax.php:30 验 `bf_tax_loading` nonce（form-elements.php:1140 前端公开）→ `$args['taxonomy']` 仅 sanitize_text_field（form-ajax.php:53-55），可传任意已注册 taxonomy（含私有）→ WP_Term_Query 枚举术语名。

### 7. file_put_contents ×5（不构成任意写 — 负向结论要实证）
- form.php:106、form-render.php:113、pfbc/Form.php:528、templates/buddyforms/the-loop.php:22、the-table.php:16 — 文件名 `bf-*-<form_slug>.*`。
- **$form_slug 必须匹配已注册表单**：form.php:65 `if ( empty( $buddyforms[ $form_slug ] ) ) return '';`、form-render.php:96 `isset( $buddyforms[ $form_slug ] )` —— 即使 form.php:119 `$form_slug = $wp_query->query_vars['bf_form_slug']` 无 sanitize（rewrite 规则 rewrite-roles.php:28-32 映射 URL 路径段），**配置键查找 = 穿越约束**，未认证无法注入路径。
- 内容均来自静态样式/JSON 化参数，非攻击者可控。→ 低危，报告写明"负向：被配置键约束挡住"。

## 可复用方法论（本会话提炼）

1. **nopriv 枚举先行**，但**注释掉的 nopriv 注册无攻击面**（ajax_delete_post 案例）。
2. **nonce 公开输出 = 无防护**：查 `wp_localize_script` 的 ajaxnonce 字段、`wp_nonce_field` 是否渲染在公开页面；非绑定用户 ID/session 的 nonce 全站共享。
3. **sanitize_text_field 保留 `../` 与 `/`** → 文件名/路径拼接前先查是否经 sanitize_text_field；`wp_upload_bits`/`wp_unique_filename` 不清理穿越。
4. **强制扩展名后缀是 RCE 的常见死穴**：`$file_id . '.png'` 固定后缀 → 写任意内容但不可执行；报告别报成"任意文件上传可 RCE"，按"受限扩展名任意写 + SSRF"定级。
5. **getimagesize 只验图片头 mime**，accepted_files 参数攻击者可控 → 内容可带 payload（polyglot），决定权在扩展名。
6. **file_put_contents 写点先找配置键约束**：`isset($global_config[$var])` 类查找挡住穿越时是负向结论，明确写出排除理由。
7. **`parse_str($_POST['data'])` + `$_POST = $form_data`** 是表单插件 AJAX 提交的常见形态 → post_id/form_action/status 全可控；配 public_submit 表单 + `is_user_logged_in()` 分支跳过 post_type 检查 → 任意 post_id 更新。
8. **GDPR/human 验证的 key 若渲染进 HTML 隐藏字段，验证可绕过**（N000M 加法题案例）。
9. **删除端点看归属校验**：`post_author == current_user->ID` 对未认证（ID=0）只剩 author=0 对象可删 → 通常不可利用，标负向。

## 输出形态
FILE:LINE + 代码原文证据 + 每条"触发前提 + 定级"，负向结论（被拦/被约束/归属校验）也列出，证明验证完整性。
