# ACF Frontend (acf-frontend-form-element) ≤3.29.10 — no_kses 块注入建管理员链（D6 实例）

未认证 → 管理员完整链，2026-08 真实靶场端到端验证（WordPress 7.0.2 + PHP 8.0.2）。对应 Wordfence 提交材料 `WORDFENCE_SUBMISSION_ChainQ_中文版.md`（D:\Documents\sources\Wordpress插件\acf-frontend-form-element\）。

## 核验记录（2026-08-14 接手复核）
- 报告引用 11 处代码位置全部属实；唯一出入：submit.php 实际在 `main/frontend/forms/classes/submit.php`（报告写 actions/submit.php）。
- 报告笔误教训：他人提交材料先核验 FILE:LINE 再讲解。

## 5 环节攻击链（精确行号）

| 环节 | 机制 | 位置 |
|------|------|------|
| ① 令牌铸造 | `change_form` nopriv 任意 item_id → fea_encrypt 铸造 `_acf_objects` | main/frontend/forms/classes/display.php:1627-1695（is_numeric 门控 :1660；nopriv 注册 :1956） |
| ② 块注入 | no_kses=1 跳过 `feadmin_sanitize_input` → Gutenberg 块注释 JSON 完整存储 | classes/submit.php:303-306（`if($form['kses'])` 才清洗）；main/helpers.php:278-285（wp_kses_post） |
| ③ 伪造字段解析 | `get_field_block` 从文章内容解析块 attrs（name=wp_capabilities, type=number） | main/gutenberg/blocks/form.php:426-464 |
| ④ 创建用户无闸门 | add_user 路径无 current_user_can（:439-444 只拦 edit_user） | main/frontend/forms/actions/user.php:509-538 |
| ⑤ meta 直写 | `acf_update_value → acf_update_metadata($post_id, $field['name'], $value)` → name 即成 user meta 键 | main/custom-fields/includes/acf-value-functions.php:224；user.php:589-594 |
| ⑥ 自动登录 | login_user 配置 → wp_set_current_user + wp_set_auth_cookie | user.php:597-603 |

## 前置条件（Wordfence 材料里逐项标必需/可选）
- 公开投稿表单：保存到=New Post【必需】、Who Can See=All Users【必需】、Allow Unfiltered HTML【必需-本 PoC 通道】、Content 字段【必需】
- 新文章状态可选（默认 no_change 自动 publish；draft 亦不影响——get_the_block 不查状态）
- **no_kses 不是根因**：捆绑 ACF acf_form / 低权限账号+REST API 等通道亦可注入；根因 = add_user 无闸门 + meta 直写 + login_user

## 三个 AJAX 请求 PoC（手动复现版）
1. POST admin-ajax.php `action=frontend_admin/form_submit` + `acff[post][<Content字段key>]=` 伪造双块（form 块：save_to_user=new_user, login_user=1；number-field 块：name=wp_capabilities）→ data.post = 新文章 ID
2. POST `action=frontend_admin/forms/change_form` + `form_data={文章ID}_gutenberg_pwn` + type=user + item_id=1 → 响应 HTML 提取 `_acf_nonce`
3. POST form_submit `_acf_form={文章ID}_gutenberg_pwn` + `acff[user][{文章ID}_gutenberg_cap][administrator]=1` → Set-Cookie 管理员会话
验证：wp_usermeta.wp_capabilities = `a:1:{s:13:"administrator";s:1:"1";}`

## 给 Java/Spring 背景用户讲解 WP 的翻译表（本用户偏好）
- `wp_ajax_` / `wp_ajax_nopriv_` = 默认需登录态 vs @PermitAll 公开接口
- nonce（_acf_nonce）= CSRF token（公开页面可提取），**不是权限凭证**
- `current_user_can()` = @PreAuthorize / hasAuthority 检查
- wp_usermeta.wp_capabilities = User 实体的 roles 字段（谁能写谁当管理员）
- 数据驱动表单 = 接口行为由请求可控 config 决定（类比：register 接口内部调 execute(config)）
- 字段 name 直写 meta 键 ≈ 列名注入（用户可控字符串拼进 SET 子句）

## 本链给审计的通用提示
- 修复对比：作者只给 edit_user 加内联闸门，add_user 特例放行——"修复一个分支忘兄弟分支"是 WP 插件补丁常态，出新版本必复测
- CVSS 9.8 合理性：前置条件是官方正常配置（富文本投稿站），非攻击者强加
