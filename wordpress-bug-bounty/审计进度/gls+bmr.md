# gallery-lightbox-slider + bulk-media-register 补丁分析 (2026-08-10)

## gallery-lightbox-slider (10000装, 2026-01-24 更新)
- changelog: 1.0.0.41 + 1.0.0.43 两次 "Fixed XSS issue, thanks to patchstack.com" → 曾期待漏修
- **SVN tags 只到 1.0.0.41**，1.0.0.43 是 trunk（带版本 zip 404，下 gallery-lightbox-slider.zip 得最新版）
- 第一次修复 (1.0.0.39→1.0.0.41): 前端 JS 加 escapeHtml() 对 Gutenberg 画廊 img alt 属性转义（前端修补，非后端 sanitize）
- 第二次修复 (1.0.0.41→latest): **重构式完整加固**——glg-functions.php 全量 esc_html/esc_url；glg-admin-ajax.php:17 的 glg_ajax_save_settings 加 `|| ! current_user_can('manage_options')`（修复前只有 check_ajax_referer 无权限检查，update_option($val['name'], esc_html($val['value'])) 任意 option 写）；gfg-metabox.php esc_html_e + 权限 elseif 重排
- 判定: **放弃**。第二次是重构式完整修复（非单点），前端输出主路径全转义。残留: glg-admin-ajax.php:162-171 free_plugins 输出远程 feed 内容未转义（ghozylab.com 供应链依赖类，不交）
- 附: glg_ajax_save_settings 修复前"无权限 update_option"——nonce 'glg_form_settings' 只在 manage_options 菜单页 (glg-global-settings.php:8 add_menu_page capability=manage_options) 输出 → 订阅者不可达 → 不可利用（nonce 不可达模式又一例）

## bulk-media-register (8000装, 2026-03-29 更新)
- changelog: 1.40 修 "Added nonce when sorting" + "Changed file operations to WP_Filesystem"; 1.32 修过 Path traversal
- 1.39→1.40 diff: list-table 覆盖 print_column_headers + 排序回调加 bmrt_sort_nonce；rename→WP_Filesystem::move、unlink→wp_delete_file
- 防护面: 全部页面处理器 current_user_can('upload_files') + check_admin_referer；AJAX (wp_ajax_bulkmediaregister-ajax-action / bulkmediaregister_message，无 nopriv) check_ajax_referer + upload_files + strpos($file, ABSPATH) + is_file；register_settings(admin_init) 只写当前用户 option 无害；robots_txt filter 只 append Disallow
- 判定: **放弃**。upload_files(作者级) 超 Wordfence 范围 + nonce 全覆盖，订阅者/未认证不可达。作者 nonce 习惯差（排序都漏）但权限门在

## 结论
2 个插件均防护完整，无订阅者/未认证可利用洞。下一步: wp-attachments (3000装/149天/"better permission handling"权限重写)
