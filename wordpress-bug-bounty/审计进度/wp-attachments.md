# wp-attachments 补丁分析 (2026-08-10)

## 基本信息
- 3000装, 5.3.4 (2026-03-14), 修复版本 5.3 "Better permission handling" (2026-02-02)
- 5.0 (2025-05) 也有 "Enhanced security + Improved admin capabilities and permission handling"

## diff 5.2.1→5.3.4 (wp-attachments.php / attach_unattach_reattach.php / meta-box.php / settings.php)
1. **wpa_unattach_do_it (attach_unattach_reattach.php:88-113)**:
   - current_user_can('edit_post', $id) 检查(修复前后都有)
   - **5.3.4 引入 noheader 绕过**: `if (!isset($_GET['noheader'])) { wp_die(...) }` —— 带 noheader 参数可绕过 wpa_unattach_{id} nonce 验证("Fallback for requests from metabox")
   - 绕过后果: `$wpdb->update(posts, post_parent=0, ID=id, post_type=attachment)` = unattach 附件(不删除)
   - 入口: add_submenu_page('tools.php', capability='upload_files') → 作者+ 才能访问; CSRF 场景 = 诱导作者/管理员点击 noheader 链接 → unattach 自己可 edit 的附件(管理员=任意附件)
   - **影响低(仅解除父子关联,附件不删) → 低危不交**
2. meta-box.php: 渲染权限 edit_posts→upload_files 收紧; 删除链接加 forcedelete 参数(走 WP 核心 get_delete_post_link,核心 nonce 保护)
3. settings.php: settings_fields 换 wp_nonce_field('wpatt_general_settings') + check_admin_referer + manage_options + 固定 option 名 sanitize → 防护完整
4. 主文件: deleted_post 钩子 = 删除附件后跳转(forcedelete 参数), 无文件操作

## 结论
- 无订阅者/未认证可利用洞; noheader nonce 绕过 = CSRF 低危(unattach 影响小), 不交 → **放弃**
- 教训: "修复引入的 nonce 绕过"要评估绕过后的实际影响——unattach 只是 post_parent=0, 不是删除

## 下一步: gd-bbpress-attachments (bbPress 附件上传,前端用户可达)
