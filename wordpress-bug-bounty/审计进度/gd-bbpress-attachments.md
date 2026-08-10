# gd-bbpress-attachments 补丁分析 (2026-08-10)

## 基本信息
- 6000装, 4.9.4 (2026-04-12), bbPress 论坛附件上传/管理插件
- 4.7.3 (2024.11) 修 "reflected XSS with the attachment actions"; 4.9 加 "additional validation and sanitization"

## 4.7.3 XSS 修复 diff (front.php)
- delete/detach 链接 esc_url; item_class/class_a/class_span/class_li 加 sanitize_html_class
- 根源 = 附件扩展名($ext)拼进 CSS class; class.php 无改动

## ★ 候选洞: 订阅者任意附件删除 IDOR (4.9.4 存活)
- 位置: code/class.php:105 delete_attachments (init 钩子, 任意请求触发)
- 逻辑: $_GET['d4pbbaction']=delete + att_id + bbp_id + _wpnonce('d4p-bbpress-attachments' 固定action)
  - nonce: 固定 action, 登录用户自己的 nonce 即有效; 作者删除权限开启时按钮渲染→nonce 可达
  - 权限: $allow 判定 = admin(administrator角色)/moderator(bbp_moderator角色)/$post(bbp_id)->post_author == $user_ID
  - **att_id 与 bbp_id 无归属关联校验** → 权限只看 bbp_id 帖子作者, 附件 ID 任意
- 攻击链: 订阅者注册发帖(自己帖子作 bbp_id) → 帖子附件按钮渲染提取自己 nonce → 构造 ?d4pbbaction=delete&att_id=<任意附件>&bbp_id=<自己帖子>&_wpnonce=<nonce> → wp_delete_attachment(任意附件) 物理删除
- 前置: 配置 delete_visible_to_author = 'delete'/'both' (默认 'no', code/defaults.php:39)
- 判定: Arbitrary File Deletion In-Scope + 订阅者级 + 6000装✓, 但**配置依赖**(作者删除权限默认关)
- 4.7.2→4.9.4 该逻辑无变化(只加 absint/sanitize) → 多版本存活
- 角色判定严格(administrator/bbp_moderator 硬编码 in_array) 无绕过

## 其他面
- 上传: wp_handle_upload + sanitize_file_name + wp_check_filetype (WP 标准, 订阅者无 unfiltered_upload 传不了 php)
- detach action 同 IDOR 但影响低(post_parent=0)

## 状态
- 已向用户汇报, 待决策: 靶场复现验证(需配置 delete_visible_to_author 开启) 或放弃
