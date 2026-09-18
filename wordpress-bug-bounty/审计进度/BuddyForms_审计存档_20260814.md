# BuddyForms 2.9.0 审计发现存档（2026-08-14）

> 结论：2 个真实漏洞，但 900 装 < 50k，Wordfence 新范围下不可交。
> 价值：能力证明 + 同类竞品（wp-user-frontend 2万装等）照方抓药的模板。

## 目标画像（为什么选它）
- 前端表单构建器（前端投稿/编辑/注册 = 配置驱动表单引擎）
- 900 装 / 436 天未更新 / 最后一次安全修复 2025-02（Max Boll 审的短代码洞）
- 命中"被审过但没审干净"规律：修复后无人再审 = 新漏网温床

## 漏洞 1：未认证任意文章篡改（Missing Authorization）

### 位置
- `includes/form/form-ajax.php:93-107` — `wp_ajax_nopriv_buddyforms_ajax_process_edit_post`
- `includes/form/form-control.php:260-261` — bf_post_type = $_POST（仅 sanitize_text_field，无白名单）
- `includes/form/form-control.php:130` — post_status_action = $_POST['status']（POST 可控）
- `includes/form/form-control.php:607` — wp_insert_post($bf_post) 直接使用
- `includes/form/form-control.php:275` — 仅"编辑已有"时校验 post_type，新建（post_id=0）不校验
- `includes/form/form-control.php:430` — 未登录时 $user_id=0 → post_author=0

### 利用链
```
1. 站点有 public_submit 表单（前端投稿，BuddyForms 核心功能）
2. 打开表单页，提取 nonce（form-render.php:254 wp_nonce_field 公开输出）
3. AJAX POST admin-ajax.php?action=buddyforms_ajax_process_edit_post
   data[form_slug]=<公开表单slug> & data[post_id]=<任意文章ID>
   & data[bf_post_type]=任意值 & data[status]=publish & _wpnonce=<nonce>
4. wp_update_post 覆盖任意文章标题/内容/状态
```

### 影响
- 未认证篡改任意文章（内容→存储XSS受限因wp_kses_post清洗 / 状态→绕过审核流直接发布 / post_type→任意对象）
- Wordfence 归类: Missing Authorization（其他类，需 50k 装）→ 900 装超范围

## 漏洞 2：未认证受限扩展名任意文件写（upload_image_from_url）

### 位置
- `includes/functions.php:1401-1414` — `wp_ajax_nopriv_upload_image_from_url`
- 无 nonce / 无权限检查
- `functions.php:1422-1436` — 远程 URL 下载 → wp_upload_bits 写文件
- `$_REQUEST['id']` sanitize_text_field 不删 `../` → 路径穿越（wp_upload_bits 不清理）
- 扩展名强制 .png（直接 RCE 被挡）
- getimagesize 校验可绕过（GIF89a 头 + payload）

### 影响
- 未认证写任意文件到 uploads 任意位置（.png 受限）
- Wordfence 归类: 非"任意 PHP 上传"（High Threat 定义）→ 降级 → 900 装超范围
- 用户判定: 只能写 .png 没啥用（除非 Nginx 把 .png 当 PHP 的罕见配置）

## 已排除面（防重复劳动）
```
✗ 注册提权: 角色只来自表单配置(管理员设), 默认 subscriber, POST 不可控
✗ file_put_contents ×5: form_slug 被已注册表单键约束, 不可穿越
✗ delete_post: nopriv 被注释, 仅登录+作者归属校验
✗ handle_deleted_media: 作者归属校验, 未认证删不了
✗ gdpr_data_request: human 验证可绕过但仅邮件滥用(超范围)
✗ bf_load_taxonomy: 私有 taxonomy 枚举(低危)
✗ 激活链接: nonce 绑定目标用户, 无法跨用户伪造
```

## 对同类竞品的启示（下次照方抓药）
```
1. 找"前端表单/CRUD 类 + 有安全修复历史 + 150天+未更新"插件
2. 重点查: process_edit_post 式 nopriv 提交端点里
   - $_POST['post_id'] 是否直接进 wp_update_post
   - post_type/status 是否 POST 可控无白名单
   - public_submit 表单配置是否跳过权限检查
3. 大装量竞品: wp-user-frontend(2万装)/user-registration(5万装)
   → 但都活跃维护(2026-08更新), 需等/或找同款老版本
```
