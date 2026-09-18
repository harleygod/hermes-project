# BuddyForms 注册/用户创建链证据图（v2.9.0，2026-08 审计）

审计范围：includes/wp-insert-user.php、includes/form/form-control.php、includes/form/form-render.php、
includes/form/form-ajax.php、includes/form/form-validation.php、includes/admin/user-meta.php、includes/change-password.php、
includes/admin/form-builder/meta-boxes/metabox-registration.php、includes/functions.php

## 结论速查（含 FILE:LINE 证据）
- **角色不可 POST 控制**：wp-insert-user.php:236 `$user_role = isset( $buddyforms[$form_slug]['registration']['new_user_role'] ) ? ... : 'subscriber'`；L240-253 wp_insert_user('role'=>$user_role)。管理端 UI 仅挡无 promote_users 的管理员（metabox-registration.php:179-183）。→ 未认证铸管理员仅"管理员把注册表单角色配成 administrator"的配置依赖
- **注册无自动登录，激活链才有**：wp-insert-user.php:699-701 `wp_set_current_user($user_id); wp_set_auth_cookie($user_id);`（template_redirect 钩子 L663）。key = user meta `has_to_be_activated` 的 md5，仅发邮箱（L333-360）→ 跨用户激活需猜 key，不成立
- **自定义 nonce 按 user_id 锚定**：functions.php:1255-1269 `buddyforms_create_nonce($action,$user_id)`（uid≠0 时 token 留空）；验证端配 `nonce_user_logged_out` 过滤器（wp-insert-user.php:526-535）把 uid 设为 GET user → 攻击者无法为他人 uid 铸造
- **未认证可提交注册表单**：form-control.php:162-186 registration 分支位于 bf_user_can 权限检查（L352）之前；门槛 = get_site_option('users_can_register')（L167-181）+ 共享 nonce 'buddyforms_form_nonce'（L114-126，输出点 form-render.php:254，全站表单同一 action）+ honeypot bf_hweb（L104-111，留空绕过）+ Form::isValid（L142）。提交通道：非 AJAX `wp` 钩子（form.php:461-476）+ nopriv AJAX `wp_ajax_nopriv_buddyforms_ajax_process_edit_post`（form-ajax.php:93-107，`parse_str($_POST['data'])` 字段全可控）
- **user meta 写入链**：form-control.php:224-243 注册后遍历 form_fields → user-meta.php:169-174 `update_user_meta($user_id, $slug, buddyforms_sanitize($field_type, $value))`，键=字段 slug（仅 user_first/user_last/user_pass/website/display_name/user_bio 六个映射核心列，L184-207），值=POST。**写入侧无受保护键黑名单**；avoid 列表（user-meta.php:247-262）只用于前端读取展示。sanitize_text_field（form-validation.php:128-130）不破坏 `a:1:{s:13:"administrator";b:1;}` 序列化串 → 配置含 wp_capabilities slug 字段时可覆盖（配置依赖）
- **改密仅自服务**：change-password.php:55-79 需登录 + nonce（模板 templates/buddyforms/bf-change-password.php:26 输出），目标=global $user_ID（当前用户）；L84-91 跳转用非 safe `wp_redirect` + 注册时 POST 可控 meta bf_pw_redirect_url（wp-insert-user.php:270-273）→ 开放重定向（Wordfence 排除）
- **admin_action 缺 capability 但 nonce 不可得**：wp-insert-user.php:492-515 `buddyforms_activate_action`（无 current_user_can('edit_user')）、L541-580 resend——nonce 仅渲染在 admin 用户列表（L484-485）→ 订阅者无法取得，实际不可利用
- **登录者提交 registration 表单 = 更新自己账户**：wp-insert-user.php:21-135，角色变更被 current_user_can('administrator') 门禁（L92-95）

## 可推广的审计手法（同族插件适用）
1. 注册链先答三问：角色来自哪（POST/配置/固定）？meta 键来自哪？目标 user_id 是否可控？答"配置"即归配置依赖，不强行 P0
2. 找 registration/创建分支相对权限检查（bf_user_can/who_can_see）的位置——通常在其之前，渲染端权限不覆盖提交端
3. 激活/确认链接 = 自动登录候选点；判定 = key 是否可猜 + nonce 是否可为他 uid 铸造（查自定义 nonce 函数 + nonce_user_logged_out 过滤器）
4. meta 写入链的黑名单查证：写入侧常无防护，avoid/blocklist 常只用于读取——别把读取端列表误判为写入防护
