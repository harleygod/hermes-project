# ACF Frontend 3.29.10 — 未认证提交数据泄露链（P0-3）细节

会话:2026-08-06 第二期审计。Frontend Admin (acf-frontend-form-element) 3.29.10 自由版。

## 漏洞链（源码逐行确认，未靶场实跑）

端点: `frontend_admin/forms/add_form`（nopriv, display.php:1958）
参数: `nonce=<匿名acf_nonce>`, `form_action=<提交记录ID>`, `data_type=submission`

1. `ajax_add_form`（display.php:1704-1749）仅 `feadmin_verify_ajax()`（匿名共享 acf_nonce），
   随后 `do_action('frontend_admin/ajax_add_form', $args)`（:1747）
2. `Submissions_Crud::render_form`（submissions/crud.php:459-468, 订阅 :475）对 data_type=submission
   调用 `$this->get_form($args['form_action'])`（:462）——form_action 即提交 ID（数字可枚举）
3. `get_form`（crud.php:325-361）：is_numeric → `get_submission($id)`（:80-97,
   `$wpdb->get_row("SELECT * FROM fea_submissions WHERE id=%d")` 无权限/属主检查）→
   `json_decode(fea_decrypt($submission->fields))` 服务端解密全部字段值（:353-360）
4. **二次放行**：`Form_Display::render_form`（display.php:1328-1339）当 `$form['submission']` 非空时
   整段跳过 `show_form` 权限门控——而 `$approval_form['submission'] = $submission->id` 在 get_form
   内必置（crud.php:374）→ who_can_see 形同虚设
5. `_acf_approval_nonce` 无效仅 `$approval=false`（crud.php:482-487），不阻断渲染

前提: 插件"保存表单提交"（frontend_admin_save_submissions）开启——核心功能，启用率极高。
影响: 未认证遍历提交 ID 读全站表单提交 PII。CVSS 7.5（C:H;含高敏字段可 9.1）。
与 `_acf_objects` 令牌无关（不需要 change_form），纯 2 请求。

## 同端点其他 data_type

- `data_type=plan` + form_action=<plan ID> → plans/crud.php:360-368 render_form 同样无鉴权读 plan
- `form_action=admin_form` + `form[form]=<表单ID>`（数组参数）→ display.php:1726-1745 直接
  render_form（不经 show_form）→ 未认证渲染任意表单，提取删除按钮 `data-nonce`（fea_delete_{key}）
  与字段 key —— 这是 delete_object 链的 nonce 捷径（无需公开页面恰好含删除按钮）

## 关联洞（同插件第二期）

- P0-1 delete_object 短路删除（class-delete-object.php:13-14,62-64,115,130,156,161）：
  `$allowed_by_settings=true` 短路 `!current_user_can && !$allowed_by_settings`；
  wp_delete_user 无管理员豁免可删管理员；**term 分支（:146）不引用该变量 → 不成立**；
  change_form（display.php:1659-1661 absint item_id）铸造令牌
- P1 订阅者删 plan（plans/crud.php:147-162 仅 nonce 无 capability）
- P1 附件枚举（class-upload-files.php:202-237 render_attachment→wp_prepare_attachment_for_js 全元数据；
  :247-268 get_sort_order ID oracle）
- P1 未认证上传安全类型（class-upload-file.php:519-594）+ fea-submissions 目录 unlink .htaccess（:641-645）直链
- P1 用户枚举（class-user-to-edit.php:42,150 / class-post-author.php:42,54-80, search_columns 含 email/login）
- 已排除: 上传 .php RCE（双层校验 else 兜底实证）、SQLi（全参数化）、CSV（list_users 守卫）、
  post.php 编辑（3.29.10 已加 is_author 闸门）、check_inline_field（已加 edit 门控）

## 提交材料

两份 Wordfence 材料已按 SECTION 1-5 格式产出（见项目目录）:
- WORDFENCE_SUBMISSION_DeleteChain_中文版.md（P0-1, CVSS 9.1）
- WORDFENCE_SUBMISSION_SubmissionLeak_中文版.md（P0-3, CVSS 7.5）
PoC 均为浏览器控制台 + URLSearchParams，标注"静态审计未实跑"。
