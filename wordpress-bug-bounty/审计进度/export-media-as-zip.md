# export-media-as-zip 审计 (2026-08-11)

## 基本信息
- 2000装, 1.8 (2026-04 更新=125天), NVD 干净, changelog 无安全记录
- 功能: 媒体库图片筛选打包 ZIP 下载 (年/尺寸筛选, 进度条, cron 清理过期 ZIP)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\emz-1.8\ (7文件, 单 PHP 587行)

## 入口点
- 5 × wp_ajax (全登录, 无 nopriv): emaz_export_media_zip / get_export_progress / get_media_stats / get_filter_options / preview_export
- init → emaz_schedule_zip_cleanup (只注册 cron)
- 全部 check_ajax_referer + current_user_can('manage_options') → 管理员级超范围

## ★ 半洞: 固定 ZIP 路径未认证可下载
- $this->zip_filename = 'media-images.zip' 固定 (export-media-as-zip.php:29)
- ZIP 生成到 uploads 根目录 (:357), 下载 URL = uploads baseurl + '/media-images.zip' (:473)
- **web 可访问 + 文件名固定** → 管理员导出后 5 分钟内, 未认证直接 GET 下载全站媒体库图片打包
- 触发条件: 管理员必须先触发导出 (manage_options AJAX) — 攻击者无法自己触发
- 5 分钟过期 + cron 清理 (emaz_cleanup_expired_zips 固定路径 unlink, 无任意删除)
- 影响: 图片本来就通过 wp_get_attachment_url 公开 (除非私有附件场景) → 价值低
- Wordfence: 信息泄露类需 50k 装 (2000 超范围) + 需管理员配合 → 不交

## 其他面
- SQL: get_filter_options 静态 SQL 无用户输入拼接; preview 用 get_posts + intval/sanitize_key
- 文件操作: 全固定路径 (uploads/media-images.zip), 无用户输入进路径

## 判定
- **放弃**。唯一半洞 (固定 ZIP 路径) 价值太低 (管理员触发+公开图片+超范围)
- 教训: 插件把生成文件放 web 可访问目录+固定文件名 = 半洞模式; 评估要点 = 触发条件(谁触发) + 内容敏感性 + 窗口
