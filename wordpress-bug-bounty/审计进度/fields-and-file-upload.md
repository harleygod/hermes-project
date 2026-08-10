# 审计进度 — fields-and-file-upload 1.2.3

> 状态: 已放弃(上传白名单限制) | 日期: 2026-08-10
> 100装 | 321天未更新 | WooCommerce 结账文件上传插件

## 结论
nopriv 上传端点 cffu_file_upload 存在,但:
- nonce('cffu-file-upload')校验 ✓
- 字段白名单:cffu_fields option(管理员配置),php 不在默认配置
- override_wp_check_filetype_and_ext(:110-125)允许 cffu-custom 类型绕过 MIME 检查,但只对管理员配置的扩展名生效
- 随机文件名(bin2hex 15 bytes)+ 自定义上传目录
**放弃**(php 不可传,除非管理员自杀式配置)

## 关键代码
- src/includes/class-upload-api.php:22-23 wp_ajax/nopriv_cffu_file_upload → process
- :138 nonce 校验;:146-166 字段查找;:176 get_permitted_mimes;:204 wp_handle_upload
- :110-125 override_wp_check_filetype_and_ext(cffu-custom 绕过)
