# 审计进度 — backup-bolt 1.5.0 / buddypress-message-attachment 3.0.1

> 日期: 2026-08-10 | High Threat 方向(新规则:25装即可交)

## backup-bolt 1.5.0(800装, 309天)
**放弃**:备份下载有 manage_options(admin/pages.php:112),AJAX 全 nonce+manage_options(admin/ajax_handlers.php:32/62/85/105/149),备份文件名含 key(不可枚举)。

## buddypress-message-attachment 3.0.1(200装, 473天)
**放弃**:上传走 media_handle_upload(WP 标准 MIME 检查,订阅者仅基础类型,php 不可传)。
- includes/class-bp-msgat-action.php:76 wp_ajax_bp_msgat_upload(非 nopriv,登录用户可调)
- :157 check_ajax_referer('bp_msgat_upload')(nonce 前端输出)
- :172 media_handle_upload('file', 0) 标准上传
- :200 add_attachments:bp_msgat_attachment_ids 可指定任意附件 ID 关联到消息(影响低,附件本身 public)
- file-types option 只在前端 JS 校验,后端靠 WP 标准 MIME

## 规律(High Threat 方向 5 连看)
well-known-file-manager/tweak-option/fields-and-file-upload/backup-bolt/bp-msgat 全部防护好:
- 上传类:media_handle_upload/wp_handle_upload 标准 MIME + nonce
- 管理类:锁 manage_options
- **真正要找的**:自写上传逻辑(检查顺序/MIME 误判/双扩展名)或下载无权限/路径可控的插件

## 待看候选
- kp-zip-downloader(3000, 247天, ZIP 下载)
- lana-downloads-manager(3000, 238天, 下载管理器)
- csv-import-and-exporter(1000, 410天)
- attachment-download-on-gravity-form-submission(300, 424天)
