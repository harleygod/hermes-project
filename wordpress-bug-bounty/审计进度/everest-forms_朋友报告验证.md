# Everest Forms 3.5.3 朋友报告验证 (2026-08-11)

## 结论: 代码引用真实(行号/函数名全对), 核心漏洞不成立, 不可交

## VULN-01 非认证表单提交 — 代码真, 非漏洞
- 确认真实: class-evf-ajax.php:145 nopriv 注册 get_form_update_nonce; :2338-2361 referer 检查(wp_get_referer→$_REQUEST['_wp_http_referer'] 可伪造)+返回 wp_create_nonce('everest-forms_process_submit'); :682 ajax_form_submission 的 check_ajax_referer 被注释; form-task.php:171 do_task 用同 action nonce
- 不可交原因:
  1. 公开表单 nonce 本来就公开(页面 HTML, uid=0 共享) — 端点只是便捷通道
  2. 未认证提交公开表单 = 设计功能, 垃圾靠 CAPTCHA 防
  3. CAPTCHA 在 do_task 完整执行(form-task.php:337-414: token 缺失拒绝 + 调 Google/hCaptcha/Turnstile API)
  4. 无认证绕过(do_task 无"仅登录可提交"逻辑)
  → Wordfence 不收 spam 类

## VULN-04 任意文件删除 — 误报(报告没追到 value 生成约束)
- 确认真实: class-evf-form-fields-upload.php:1655-1700 remove_csv_file_after_email_send, :1674-1676 ABSPATH+preg_replace+unlink 无 realpath; :1664-1666 signature 分支直接 unlink(meta_value)
- 但 value 双重约束(报告漏了):
  1. 新文件: format()→generate_file_info(:1465-1496) value=服务端生成 file_url = uploads/everest_forms_uploads/{hash}/{wp_unique_filename} — 攻击者不可控
  2. 旧文件: format()(:1381-1404) old_files 每个过 resolve_uploads_file_from_url(:1785-1820) = baseurl 前缀 + realpath + uploads 目录内 + is_file, 不过则丢弃
  3. deleted_files 也有防护(:617-644 同款校验)
  → unlink 只能删 uploads 内文件(正常临时文件清理), 无法删 wp-config.php
- signature 分支: meta_key 需含 signature_(管理员配置字段), value=签名图片服务端路径 → 不可控

## VULN-05 CSRF 上传/删除 — 影响低不收
- upload_file/remove_file nopriv 无 nonce 真实(:115)
- 影响: tmp 目录垃圾文件/删自己上传的临时文件, 需表单配置 file-upload 字段
- Wordfence 不收 CSRF 低危

## 其他
- VULN-02 evf_bypass_form_nonce_validation filter 存在(form-task.php:168) 默认 false, 配置依赖
- VULN-06/07/08/09 配置依赖/低危/超范围
- SQL 注入排查结论(全参数化) 与验证一致

## 给朋友的建议
- 静态审计要追"值进 DB 前的最后一道处理"(format/generate_file_info/resolve_uploads_file_from_url)
- 报告的"已验证安全"栏(realpath 校验)是真实亮点
- 后续方向: shortcode 渲染 XSS / 第三方集成回调 / Elementor 集成(报告盲区清单)
