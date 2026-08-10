# 审计进度 — wp-user-manager 2.9.18

> 状态: 已放弃(防护到位) | 日期: 2026-08-09 | 源码: D:\Documents\sources\Wordpress插件\wp-user-manager\
> 安装量 10000 | changelog 修过: csrf, injection | NVD 无已披露 CVE(干净)

## 结论
防护非常到位,无预认证/权限绕过洞。所有后端 AJAX = nonce + capability + is_admin 三重校验;前端表单固定 current_user;上传白名单严格。**不建议继续投入。**

## 结构
- includes/forms/ — 注册/登录/密码找回/密码/资料/隐私 6 表单
- includes/fields/ — 字段系统(file 字段=上传)
- includes/roles/ — 角色编辑器(后台)
- includes/directories/ — 用户目录
- includes/integrations/stripe/ — 付费注册 + webhook

## 已查面(结论 + 关键行号)
| 面 | 结论 | 位置 |
|---|---|---|
| nopriv AJAX | 仅 2 个:wpum_stripe_register / wpum_shortcode(无副作用) | includes/integrations/stripe/Registration.php:77, includes/shortcodes/class-wpum-shortcode-button.php:41 |
| 注册角色 | 白名单校验 ✓ | class-wpum-form-registration.php:216-243(validate_role), :575-577(set_role 走白名单/默认) |
| 密码找回 | 标准 WP 流程(get_password_reset_key+邮件+check_password_reset_key)✓ | class-wpum-form-password-recovery.php:210-272(submit_handler), :310-368(reset) |
| 文件上传 | wp_check_filetype_and_ext + MIME 白名单(图/pdf/doc,无 php/svg)✓ | includes/functions.php:550-595(wpum_upload_file), :616-631(wpum_get_allowed_mime_types) |
| profile/密码表单 | 固定 wp_get_current_user,无 user_id 可控 ✓ | class-wpum-form-profile.php:72, trait-wpum-account.php:23-53 |
| 登录 | wp_signon 标准 ✓ | class-wpum-form-login.php:138-212 |
| 角色/表单/字段编辑器 AJAX | 全部 check_ajax_referer + current_user_can + is_admin ✓ | class-wpum-roles-editor.php:172-214, class-wpum-registration-forms-editor.php:195-463, class-wpum-fields-editor.php:247-410 |
| stripe 付费注册 | 先建账号后 Stripe Checkout(激活靠 webhook,设计如此);handle_register 未认证可批量注册(注册轰炸,低危不交) | Registration.php:214-260 |
| send_test_email | nonce + manage_options + is_admin ✓ | class-wpum-emails-list.php:126-132 |

## 未深查(价值低)
- 字段渲染 XSS(types/) — 大概率转义
- 用户目录/资料页自定义字段输出 — 正常功能

## 待办
- 无(放弃)
