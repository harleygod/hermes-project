# ACF Frontend — delete_object 短路绕过链（本会话实测）

来源：对 `acf-frontend-form-element`（Frontend Admin / ACF Frontend）源码的假设验证审计。路径 `D:\Documents\sources\Wordpress插件\acf-frontend-form-element`（注意：路径含中文，rg 直接搜会 IO error，见 SKILL.md 工具陷阱）。

## 结论摘要

| 假设 | 判定 | 严重度 |
|------|------|--------|
| delete_object nopriv 删任意用户/文章 | 成立（短路绕过） | P0 |
| _acf_objects 令牌攻击者可控 | 成立（change_form 铸造） | P0 |
| term 删除可绕过 | 不成立（该分支不引用 $allowed_by_settings） | - |
| options.php options 分支无能力检查 | 成立 | P1 |
| admin-pages 各 crud.php 有 AJAX CRUD | 仅 plans/crud.php 有，且缺能力检查 | P1 |
| ajax_add_form nopriv 渲染任意表单 | 成立 | P1 |

## 1. delete_object 短路链（P0，未认证删任意用户含管理员）

文件：`main/frontend/fields/general/class-delete-object.php`

- `:13-14` `wp_ajax_frontend_admin/delete_object` + `wp_ajax_nopriv_...` 同注册 → 未认证可达
- `:22-24` `$key = sanitize_key($_POST['field'])`，nonce 校验 `feadmin_verify_ajax($_POST['nonce'], 'fea_delete_' . $key)` —— nonce 动作串拼接攻击者可控 key
- `:194` 渲染时 `wp_create_nonce('fea_delete_' . $field['key'])`，`:202` 输出到 `data-nonce` 属性 → guest（uid0+空token）共享 nonce，从公开页面或 nopriv 渲染端点提取
- `:44-64` 关键逻辑：`$field = apply_filters('frontend_admin/forms/get_delete_button', null, $key)` 为空且 `form_id != key` 时加载表单 → `apply_filters('frontend_admin/show_form', $form)` 非空 → **`:63 $allowed_by_settings = true`**
- `:115/:130/:156` `if ( ! current_user_can(...) && ! $allowed_by_settings )` → 短路，能力检查被跳过（post/product/user）
- `:161` `wp_delete_user($user_id, $field['reassign_posts'])` 无自我保护/管理员豁免 → 任意用户（含 admin）删除
- **`:146` term 分支不引用 $allowed_by_settings**（用 `$field['special_permissions']`）→ term 不构成绕过，报告需明确区分

show_form 放行面（`main/frontend/forms/classes/permissions.php`）：
- `:37-40` Gutenberg 构建器表单在 AJAX 上下文（无 $fea_block_visibility）`display=true` 无条件放行
- `:53-56` Bricks 同理；`:151` `who_can_see='all'` 放行

## 2. 令牌铸造端点（change_form，P0 前提）

文件：`main/frontend/forms/classes/display.php`

- `:1955-1956` `wp_ajax_frontend_admin/forms/change_form` + nopriv 同注册
- `:1628` 仅 `feadmin_verify_ajax()`（默认 acf_nonce，uid0 共享）
- `:1652-1661` `if ($request['item_id']) { if (is_numeric(...)) { $form[$type.'_id'] = absint($request['item_id']); $form['save_to_'.$type] = 'edit_'.$type; } }` → 任意 type + 任意数字 ID 铸造编辑令牌
- `:395-405` form_render_data 输出 `_acf_objects = fea_encrypt(json_encode({type:id}))` hidden input → 从 AJAX 响应 HTML 直接提取
- `:1957-1958` `ajax_add_form` 同样 nopriv（`:1704-1749`，仅 nonce 校验，`:1742` 直接 render_form 不经 show_form 门控）→ guest 可渲染任意表单并提取 fea_delete_* nonce 与字段 key

攻击链：公开页取 acf_nonce → change_form(type=user, item_id=管理员ID) 取 _acf_objects 令牌 → 取 fea_delete_{key} nonce（页面或 ajax_add_form）→ POST nopriv delete_object(field=key, _acf_form=放行表单, nonce, _acf_objects) → wp_delete_user(管理员)。

## 3. options.php 分支能力对照（P1）

文件：`main/frontend/forms/actions/options.php`

- `:60` admin_options 分支有 `current_user_can('manage_options')` 门控
- `:89-103` **options 分支无任何能力检查**：`acf_update_value($option['_input'], 'options', $field)` 改写站点级 ACF options 字段
- 对照法：同文件相邻分支能力检查差异 = 缺失即漏洞

## 4. plans CRUD 缺能力检查（P1）

文件：`main/admin/admin-pages/plans/crud.php`

- `:375` `wp_ajax_frontend_admin/plans/delete`（无 nopriv，登录可达）
- `:147-162` ajax_delete_plan 仅 `feadmin_verify_ajax()`，**全文件零 current_user_can** → 任何登录用户按 ID 删任意 plan
- `:331-358` save_plan 挂 `frontend_admin/form/on_submit`，无能力检查；`:360-368` render_form 经 nopriv ajax_add_form 可达 → guest 可创建/覆盖任意 plan（plan_id 任意，`:347-352` 直接 $wpdb 写）
- emails/payments/subscriptions/submissions 的 crud.php **无 wp_ajax 处理器**（假设不成立）；submissions/crud.php:133 get_submissions 有 edit_posts 门控

## 5. 排除/门控项

- `display.php:1882-1886` ajax_render_field_settings 有 `acf_current_user_can_admin()` → 受保护
- `submit.php:11-92` check_inline_field nopriv 但 `:38` current_user_can_edit_object 按对象类型逐项门控（post_/user_/term_ 前缀）→ 已修
- ajax_get_submissions（display.php:1605-1625）无 nonce/cap，但下游 submissions/crud.php:133 edit_posts 门控 → 仅计数泄漏
