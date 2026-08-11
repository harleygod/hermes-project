# csv-import-and-exporter 审计 (2026-08-11)

## 基本信息
- 1000装, 1.0.1 (2023 首发, 2025-06 更新=411天), NVD 干净, changelog 无安全修复
- 功能: 文章 CSV 导入/导出 (自定义字段/分类支持)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\csv-1.0.1\ (50文件, PHP 11个)

## 入口点
- ★ wp_ajax_nopriv_download (csv-import-and-exporter.php:42) → ajax_download → require admin/download.php —— **代码异味, 实际不可利用**
- wp_ajax_download (登录版)
- 导入页: admin_menu 'level_7' capability (csv-import-and-exporter.php:60-61)

## download 面 (admin/download.php)
- 整个导出在 if( isset type && is_user_logged_in && wp_verify_nonce('csv_exporter') && (admin||editor) ) 内 (:3-9); else 只加错误 (:296)
- SQL: prepare 全参数化 + sanitize_key 列名 (:46-105) → 无 SQLi
- 文件路径固定: CSVIAE_PLUGIN_DIR.'/download/'.'export-{type}-{时间}.csv' (:270-271) → 无任意文件操作
- **未认证/订阅者 → 不进 if → 无导出** ✓

## import 面 (import/rs-csv-importer.php)
- dispatch step=1: check_admin_referer('import-upload') (:435)
- 菜单 capability='level_7' (editor+) → **editor+ 入口超 Wordfence 范围**
- 导入=上传CSV→解析→wp_insert_post 创建文章 (内容注入, 但 editor+ 本来高权限)

## 判定
- **放弃**: 无订阅者/未认证可达面; nopriv_download 注册是异味但被 is_user_logged_in 硬挡
- 教训: 看到 nopriv 端点先别兴奋——读完整 if 条件, 登录检查挡在前面 = 不可利用; 菜单 capability 用老式 level_N 的要看映射(level_7=editor+ 超范围)
