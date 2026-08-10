# 审计进度 — well-known-file-manager 1.4.10 / tweak-option 1.8

> 日期: 2026-08-10 | 均为 High Threat 类型候选(新范围下 25 装即可交)

## well-known-file-manager 1.4.10(200装, 237天)
**放弃**:全部 AJAX = nonce('wkfm_nonce') + manage_options + 文件类型白名单(convert_filename_to_class_name + class_exists)。
- classes/class-admin.php:573-603(toggle:nonce+manage_options+白名单)
- classes/class-well-known-file.php:338 file_put_contents / :395 unlink(但只操作白名单 .well-known 文件)

## tweak-option 1.8(100装, 242天)
**放弃**:AJAX(twop_ajax_callback)能 delete_option/update_option 任意 option 且无 capability 检查,但:
- tweak-option.php:282 check_admin_referer('twop', 'tweak_option')
- nonce 只在 :146 管理页(tools.php?page=tweak_option,manage_options)输出 → 订阅者不可达
- 表单路径(:77 同样 nonce + 管理页)锁 admin
- **又是 nonce 不可达模式** → 排除

## 经验
"管理工具类"插件(改 option/文件管理)全锁 admin 面 + nonce。High Threat 真正机会在**前端可触发**的文件操作(上传/下载/删除走 nopriv 或前端表单,nonce 前端输出)。
