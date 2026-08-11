# wordpress-reset 审计 (2026-08-11)

## 基本信息
- 5000装, 1.5.0 (2025-01 重写; API last_updated 2025-10), NVD 查重干净
- 功能: 一键重置 WP 站点(清空数据库表/重建/保留管理员密码)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\wr-1.5.0\ (11文件, 核心 class-wpre-reset.php 454行)
- 结构: wordpress-reset.php 引导 + includes/class-wpre-reset.php

## changelog 信号
- 1.5.0 (2025) 是 2016→2025 十年后重写: "Modernized code to meet WP Coding Standards + Improved input sanitization and output escaping" → 作者重写时做安全功课
- 1.4 (2016) 之前是 2012-2013 老代码

## 防护链分析 (admin_init:59-233)
- 三重触发条件: wordpress_reset=true (hidden) + wordpress_reset_confirm='reset' (人工输入) + wp_verify_nonce('wordpress_reset') (:64)
- current_user_can('activate_plugins') 硬检查 (:68, wp_die 403)
- MySQL: SHOW TABLES LIKE + DROP TABLE %i + wp_install + UPDATE %i 全参数化 (:169-202)
- SQLite: 删数据库文件路径来自常量 FQDB/DB_DIR/DB_FILE (管理员配置, 不可控)
- 表单 nonce 只在 activate_plugins 菜单页输出 (:338-345, :443) → 订阅者/未认证不可达
- admin_bar_link 前端也显示但只对 activate_plugins 用户且只是跳转
- hijack_mail: 正则替换邮件文本, 无风险
- JS: 确认弹窗, 无风险

## 判定
- **防护完整, 放弃**。1.5.0 重写版 = 高质量代码(nonce+confirm+capability+参数化+escaping 全齐)
- 教训: 筛选器按"维护差"选目标, 但 1.5.0 恰好是最近重写 → 重写版大概率防护好, 优先挑"多年未动的老代码"而非"刚重写"

## 下一步: wp-migration-duplicator (5000装/133天, 迁移类=打包解包RCE高发)
