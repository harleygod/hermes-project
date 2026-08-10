# media-library-helper 补丁分析 (2026-08-10)

## 基本信息
- 10000装, 1.3.2 (2025-12-03), 媒体库增强插件(批量编辑附件标题/alt/描述/说明, 搜索空 alt)
- 1.3.0 修 "Addressing the Cross-Site Request Forgery (CSRF) vulnerability"
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\mlh-1.2.0\ (修复前) mlh-1.3.2\ (最新)
- 结构: 主文件 63 行引导; 核心 lib/Admin/Admin_Ajax.php(174行) Media.php(324行) Extended_Media_List_Table.php(364行) templates/extended-upload.php(430行)

## 入口点 (wp_entry_map.py 产出)
- wp_ajax × 3 (全登录, 无 nopriv): cdxn_mlh_attachment_save_bulk / image_metadata / rate_the_plugin
- 无 REST/短代码/前端面

## ★ 修复引入的削弱 (1.2.0→1.3.2 diff, Admin_Ajax.php)
- image_metadata 的 nonce: 1.2.0 硬检查 `!wp_verify_nonce(...)` → 1.3.2 改成 `!manage_options && !wp_verify_nonce(...)` (**OR 逻辑, admin 免 nonce**)
- 作者为修 admin 功能 bug 牺牲 nonce → admin CSRF 面: 诱导 admin 提交 → 任意附件 title/alt/caption/description 修改 (wp_update_post/update_post_meta)
- 影响: 附件元数据篡改, 非文件操作 → **低危不交** (Wordfence CSRF 需 considerable impact)
- attachment_save_bulk_edit: nonce 保持硬检查 + 每 id edit_post 校验 → 完整 (未受削弱影响)

## 其他面 (全部防护完整)
- SQL: search_join_table/search_where_table (posts_join/posts_where) 全 $wpdb->prepare 参数化, JOIN 用固定表名 → 无 SQLi
- 批量处理 (extended-upload.php): upload_files 入口 + check_admin_referer('bulk-media') + 全 delete_post/edit_post 校验 → 复制 WP 核心逻辑, 完整
- 导出功能: get_bulk_actions 加 export 但未找到服务端处理 (前端 JS 生成, 低价值)
- nonce 'ajax-nonce' 输出在后台媒体库页 (Admin.php:132) → 订阅者不可达

## 结论
- 无订阅者/未认证可利用洞; admin CSRF 元数据篡改低危不交 → **放弃**
- 教训: "CSRF 修复" diff 里 nonce 从硬检查变 OR 逻辑 = 修复引入削弱 (同 wp-attachments noheader 模式); 但削弱后果若只是元数据篡改/低影响 → 不交
