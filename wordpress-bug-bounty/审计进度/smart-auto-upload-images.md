# 审计进度 — smart-auto-upload-images 1.2.3

> 状态: 已放弃(认证受限SSRF,价值低) | 日期: 2026-08-09
> 源码: D:\Documents\sources\Wordpress插件\smart-auto-upload-images\
> 安装量 5000 | 2026-05 更新 | NVD 干净

## 结论
SSRF 面真实存在但受限:作者+ 权限触发(REST 字段/文章保存)、URL 必须外部、内容必须真图片(双校验)→ 只能探测内网端口+下载内网图片。中低危,不理想。放弃。

## 结构
- src/classes/Services/ImageDownloader.php — 下载核心(wp_remote_get :142)
- src/classes/Services/ImageValidator.php — URL/内容校验
- src/classes/Plugin.php — 触发点

## 关键代码
- 触发点 1:Plugin.php:39 add_filter('wp_insert_post_data') → process_post_images(作者+ 保存文章)
- 触发点 2:Plugin.php:110 register_rest_field('smart_aui_featured_image_url', update_callback=update_featured_image_url_field) → download_image(作者+ 更新文章)
- download_image:validate_image_url(外部+域名黑名单+wp_http_validate_url)→ fetch_image(wp_remote_get)→ validate_image_content(wp_check_filetype_and_ext+getimagesize)→ save
- SSRF 盲区:is_external_url 只排同站(:141-146),is_domain_excluded 默认空(:154-177)
- REST /settings 等:manage_options(:181-183)

## 待办
- 无(放弃)
