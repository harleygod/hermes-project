# Everest Forms 3.5.3 他人报告验证案例（2026-08-11）

## 背景
朋友（Claude Code wp-plugin-audit v3.2 审计）交出 465 行审计报告，声称 90k 装 Everest Forms 3.5.3 有未认证表单提交（HIGH）+ 任意文件删除（CRITICAL）。用户要求验证真实性。

## 验证方法（可复用）
1. SVN 按文件拉关键文件（10MB 大插件 zip 下载慢）：`plugins.svn.wordpress.org/{slug}/tags/{ver}/{path}`，核心文件先拉：ajax handler / form-task / 字段上传抽象类
2. 逐条对照报告 FILE:LINE → 确认代码真实存在（行号/函数名/注释全对 = 真审计）
3. 关键：**追"值进 DB 前最后一道处理"**——报告只看删除点（remove_csv_file_after_email_send 的 unlink），没追 value 怎么生成

## VULN-01 非认证表单提交 — 代码真，不可交
确认真实：
- class-evf-ajax.php:145 nopriv 注册 get_form_update_nonce
- :2338-2361 referer 检查（wp_get_referer → $_REQUEST['_wp_http_referer'] 可伪造）+ wp_create_nonce('everest-forms_process_submit')
- :682 ajax_form_submission 的 check_ajax_referer 被注释
- form-task.php:171 do_task 用同 action nonce 验证

不可交原因：
1. 公开表单 nonce 本来就公开（表单页 HTML 内，uid=0 共享）——get_form_update_nonce 只是"远程拿 nonce 的便捷通道"，等价页面抄源码
2. 未认证提交公开表单 = 设计功能（表单就是给人提交的）
3. CAPTCHA 在 do_task 完整执行（form-task.php:337-414：token 缺失拒绝 + 调 Google/hCaptcha/Turnstile API 服务端验证）
4. do_task 无"仅登录可提交"逻辑 → 无认证绕过

## VULN-04 任意文件删除 — 误报（报告漏了 value 生成约束）
确认真实：
- class-evf-form-fields-upload.php:1655-1700 remove_csv_file_after_email_send
- :1674-1676 `ABSPATH . preg_replace('/.*wp-content/','wp-content', wp_parse_url($file_url, PHP_URL_PATH))` → unlink 无 realpath
- :1664-1666 signature_ 前缀 meta 直接 unlink($meta_value)

但 value 双重约束（报告没追到 format()）：
1. 新文件：format() → generate_file_info(:1465-1496) value = 服务端生成 file_url = uploads/everest_forms_uploads/{hash}/{wp_unique_filename} — 攻击者不可控
2. 旧文件：format()(:1381-1404) old_files 每个过 resolve_uploads_file_from_url(:1785-1820) = uploads baseurl 前缀 + realpath + uploads 目录内 + is_file，不过则丢弃
3. deleted_files 同款校验(:617-644)

→ unlink 只能删 uploads 目录内文件（正常临时文件清理），无法删 wp-config.php

## 判定
- 报告代码引用 100% 真实（真审计），但核心漏洞不可利用/不可交
- 报告"已验证安全"栏（delete_entry_files realpath 校验等）反而是真实亮点
- 报告盲区清单（shortcode XSS/PDF addon/集成回调/Elementor）= 继续挖的地图

## 盲区深挖结论（2026-08-11 会话后半段，按报告盲区清单继续挖）
1. **shortcode 渲染 XSS → 干净**：text 字段 POST 回填值（$defaults = $_POST['everest_forms']['form_fields'][$field_id]，shortcode-form.php:849）→ properties['inputs']['primary']['attr']['value'](:905) → 输出走 evf_html_attributes（evf-core.php:1012，datas/atts 值全 esc_attr :1039/:1056）；textarea 字段 = evf_sanitize_textarea_field + esc_html(:250/:295)；label/description/messages 全 esc_html/esc_attr/kses → 3.5.3 渲染层转义完整
2. **成功页 entry_id → 安全（HMAC）**：shortcode-form.php:1108-1121 `everest_forms_return`（base64）→ is_valid_hash 门（:1110）→ validate_return_hash（form-task.php:1164-1172）`wp_hash(form_id.','.entry_id) !== $output['hash']` 即拒 → **wp_hash = WP secret keys HMAC，攻击者不可伪造** → 无法用任意 entry_id 触发成功页/PDF 下载 = 无 IDOR
3. **集成回调动态 action → 低危**：class-evf-ajax.php:962 `do_action('everest_forms_integration_account_connect_'.sanitize_text_field($_POST['source']), $_POST)`——但 integration_connect(:939-945) 有 check_ajax_referer('process-ajax-nonce') + current_user_can('everest_forms_edit_forms') 双防护 → 需后台编辑权限，非未认证面

## 表单类插件可复用检查点（本案例沉淀）
- **提交后确认页 IDOR 判定**：`?entry_id=N` / base64 参数回显条目 → 看 hash 校验——`wp_hash` HMAC 签名 = 不可伪造（安全）；仅 base64 无签名 = 任意条目读取 IDOR
- **字段 POST 回填 XSS 判定**：提交失败后值回填 = 追 `$defaults（$_POST 直取）→ properties attr → 最终输出函数`——输出走统一属性渲染函数（evf_html_attributes 类）且全 esc_attr = 干净；裸 sprintf 拼接 = 反射 XSS
- **防护质量高插件的整体判断**：全面 escaping + HMAC 确认页 + realpath 文件校验三件齐 = 现代高质量插件，盲区大概率也干净，挖 2-3 面即止

## 给报告作者的反馈模板

"静态审计要追'值进 DB 前的最后一道处理'（format/generate_file_info/resolve_uploads_file_from_url）——运行时约束是静态分析最容易漏的层；CRITICAL 标签先验证值可控性再定性。"
