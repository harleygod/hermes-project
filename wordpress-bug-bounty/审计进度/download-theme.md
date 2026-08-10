# download-theme 补丁分析 (2026-08-10)

## 基本信息
- 4000装, 1.1.2 (2025-04-23 更新 = 474天没更新, 老维护), 14-16 个文件小插件
- 功能: 把站点"已安装主题"打包成 zip 下载(备份用途), 非 wp.org 下载
- 修复史: 1.0.3 (2016) "Improved security of download"; 1.1.0 (2025) "Security updates"

## 1.0.9→1.1.2 diff (download-theme.php)
- **1.1.0 核心修复: dtwap_download 加 nonce 检查** (之前无 nonce)
- 新增 wp_ajax_dt_send_inquiry_email: 登录用户无 nonce 可发邮件给 support@metagauss.com (sanitize_email/url/textarea 有) → 邮件轰炸低危不交
- 新增 dtwap_dismissible_notice (admin notice 关闭), download_theme_admin_notice (esc_html_e 转义)

## dtwap_download (82-133行) 防护分析
- nonce 'dtwap-themes' ✓ (1.1.0 加)
- current_user_can('switch_themes') ✓ (管理员级)
- $themes = wp_get_themes() + array_key_exists 白名单 ✓ (只允许已安装主题)
- $folder_path = get_theme_root().'/'slug + realpath ✓ 无路径穿越
- ZipArchive 打包主题目录 → readfile → unlink (zip 残留边缘情况=主题源码本来公开, 不算洞)
- 结论: **防护完整, 无洞, 放弃**

## 今日累计 (2026-08-10 补丁分析)
| 插件 | 结论 |
|------|------|
| gallery-lightbox-slider | 重构式完整修复, 放弃 |
| bulk-media-register | upload_files+nonce 全覆盖, 放弃 |
| wp-attachments | noheader nonce 绕过=CSRF 低危, 放弃 |
| gd-bbpress-attachments | ★ IDOR 任意附件删除(配置依赖, 用户拍板放弃; NVD 查重干净) |
| download-theme | 四层防护完整, 放弃 |
