# 审计进度 — image-upload-for-bbpress 1.1.23

> 状态: 已放弃(设计安全) | 日期: 2026-08-09
> 源码: D:\Documents\sources\Wordpress插件\image-upload-for-bbpress\
> 安装量 3000 | 10 个月前更新(2025-08)| NVD 干净

## 结论
420 行小插件,作者安全意识到位:**上传文件被 GD 重编码(不可能传 shell)+ 32 位随机文件名 + 路径穿越检查 + 权限检查**。唯一可能 = 未认证磁盘填充 DoS(需 bbPress 开匿名,低危)。放弃。

## 结构(2 个 PHP 文件)
- bbp-image-upload.php — 全部功能
- plugin-credit.php — 版权

## 关键代码
- hm_bbpui_handle_upload(init 钩子,GET hm_bbpui_do_upload 触发):权限检查(publish_topics/replies 或 _bbp_allow_anonymous)→ is_uploaded_file → switch($_FILES['type']) → GD 重编码 → 随机 32 字符名 + .jpg/.png/.gif → hm_bbpui_temp/
- hm_bbpui_insert_post(wp_insert_post):内容引用 hm_bbpui_temp 文件 → 移动到 hm_bbpui/<post_id>/,穿越检查 strpos($match,'/')
- hm_bbpui_delete_post / hm_bbpui_cleanup / hm_bbpui_clean_temp_dir:清理逻辑

## 待办
- 无(放弃)
