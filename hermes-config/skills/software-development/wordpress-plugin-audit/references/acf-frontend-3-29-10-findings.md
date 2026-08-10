# ACF Frontend (acf-frontend-form-element) 3.29.10 自由版 — 6 假设验证明细

项目根：`D:\Documents\sources\Wordpress插件\acf-frontend-form-element`（含 main/frontend、main/admin、main/custom-fields、main/freemius）。

## 根因（影响全部 nopriv 端点）

`main/helpers.php:795` `feadmin_verify_ajax($nonce='', $action='')`：默认 nonce action = `acf_nonce`。匿名用户（uid 0 + 空 token）的 nonce 全站共享且确定，渲染插件脚本的公开页面 HTML 均可提取 → 所有 `wp_ajax_nopriv_*` + feadmin_verify_ajax 端点实际未认证。

## 逐条结论

| # | FILE:LINE | 类型 | 级别 | 利用方式 |
|---|---|---|---|---|
| 1 | class-upload-files.php:49 | INFO_LEAK | P1 | nopriv `acf/fields/gallery/get_attachment`：共享 acf_nonce + 任意现存 field_key，传任意 attachment id → render_attachment 经 wp_prepare_attachment_for_js 返回 URL/文件名/尺寸/作者 display_name/alt 完整元数据，无属主/权限/隐藏校验，可枚举含 `_hide_from_library` 及他人提交的附件 |
| 2 | class-upload-files.php:53 | INFO_LEAK | P1 | nopriv `acf/fields/gallery/get_sort_order`：ids 任意数组 post__in + post_status 'any' → 附件存在性/ID 枚举 oracle，辅助 #1 盲扫 |
| 3 | class-upload-file.php:567-569,641-645 | INFO_LEAK | P1 | 匿名上传至 `wp-content/uploads/fea-submissions/`；maybe_mkdir 无条件 unlink .htaccess、仅加 index.php（防列目录不防直链）；文件名 `<原名>-<uniqid>.<ext>`（uniqid 13 位 hex 时间戳可预测）；直链 URL 无鉴权可下载；$attachment 未设 post_author → 匿名上传 post_author=0 |
| 4 | class-upload-file.php:596-623 | IDOR | P1 | nopriv update_meta：attach_id 任意无属主校验 → 对任意附件触发 wp_generate_attachment_metadata（图片缩略图重建=资源耗尽/DoS）并 wp_update_attachment_metadata 覆写 `_wp_attachment_metadata`（可清空他人附件元数据） |
| 5 | display.php:1704-1747 + submissions/crud.php:459-468 | IDOR | **P0** | nopriv `frontend_admin/forms/add_form`（共享 acf_nonce）→ POST data_type=submission、form_action=数字提交ID → render_form 无任何权限/approval-nonce 校验 → get_form 解密 fea_encrypt(fields) 并渲染完整表单（全部 PII 字段值）→ 未认证遍历提交 ID 读取所有用户表单提交数据 |
| 6 | plans/crud.php:360-376 | INFO_LEAK | P1 | 同一 nopriv add_form 端点，data_type=plan 时同样无鉴权读取任意 plan 记录 |
| 7 | class-user-to-edit.php:42,150 | INFO_LEAK | P1 | nopriv `acf/fields/user_to_edit/query`：per-field 匿名 nonce（公开表单 HTML 可提取），search_columns 含 user_login/user_nicename/user_email → 邮箱/登录名前缀枚举；空搜索分页（20/页）枚举全部用户 ID+display_name（回退 login） |
| 8 | class-post-author.php:42,54-80 | INFO_LEAK | P1 | nopriv `fea/fields/post_author/query` 同上模式，经 ACF_Ajax_Query_Users 按 login/nicename/email 搜索返回用户 |
| 9 | elementor/widgets/general/acf-form.php:693 + content-tab.php:932 | CRED_LEAK | UNCERTAIN | reCAPTCHA **secret** 作为 Elementor 控件默认值/字段设置明文存入页面 `_elementor_data` 并注入字段参数；前端 render_field 仅输出 site key（server-side 校验），secret 未直接进 HTML，但明文落于页面数据，编辑器/低权 REST 场景或可暴露 → 未实证直出前端 |

## 正面排除项（验证过安全）

- `submissions/crud.php:132` get_submissions 有 `current_user_can('edit_posts')`；`display.php:1954` `frontend_admin/forms/get_submissions` 仅 wp_ajax 无 nopriv → 列表/编辑路径有权限防护，漏洞仅在 #5 的 add_form→render_form 旁路
- `apis.php` 及 main/ 全目录（排除 freemius）：无硬编码 password/secret/api_key/token；Google Maps/reCAPTCHA 密钥存 option 服务器端，仅管理页明文显示；recaptcha 前端只输出公开 site key
- 提交数据 `fields` 以 fea_encrypt（AES-256-CBC，key=wp_hash('fea_encrypt')）存储，但 #5 服务端解密后渲染，加密不构成防护
- 插件内无 .htaccess/rewrite 规则保护 fea-submissions 目录（find 确认）

## 方法论备注

- 附件枚举链：get_sort_order（存在性 oracle）→ get_attachment（完整元数据+URL）→ 直链下载（uniqid 文件名时间窗猜测）
- ACF 字段类端点的 field_key 约束不是有效防护：站点上任意现存字段 key 即可（公开表单 HTML data 属性可提取）
- 用户枚举端点 nonce action 格式 `acf_field_<field_type>_<field_key>`，`wp_create_nonce` 位置：render_field 内（class-user-to-edit.php:331、class-post-author.php:279）
