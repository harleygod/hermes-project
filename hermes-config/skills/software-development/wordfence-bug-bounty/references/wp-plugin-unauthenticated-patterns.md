# WP 插件未认证攻击模式清单

来源：Frontend Admin (ACF Frontend) 3.29.10 两期审计实战沉淀（2026-08）。模式可复用到其他 WP 插件。

## 模式 1：匿名 nonce 共享 → nopriv 端点等同未认证

- WP 未登录用户（uid 0 + 空 session token）的 `wp_create_nonce` 输出**全站一致**
- 任何渲染插件脚本的公开页面 HTML 都能提取 nonce（`"nonce":"..."` / `_acf_nonce` 隐藏域 / `data-nonce` 属性）
- 结论：`wp_ajax_nopriv_*` + 仅 nonce 校验的端点 = 实际未认证访问
- 检查：`feadmin_verify_ajax()` 类函数默认 action 是否固定（如 'acf_nonce'）

## 模式 2：服务端加密令牌可由 nopriv 端点铸造 = 令牌可控

- 插件常用 fea_encrypt（AES-CBC，key = wp_hash('secret')）铸造客户端令牌（对象 ID 等）
- 攻击者不能自行伪造（不知 wp_hash 密钥），但若存在 nopriv 端点接受任意参数并让服务端铸造令牌（如 change_form 的 item_id → absint → 令牌）→ 令牌内容完全可控
- 检查：所有接受 item_id/object_id/type 参数的 nopriv 端点

## 模式 3：权限检查短路（$allowed_by_settings 型）

- 代码模式：`if ( !current_user_can(...) && !$allowed_by_settings ) { deny }`
- 若 `$allowed_by_settings` 由"表单/配置对攻击者可见"即可置 true（不经能力检查）→ 短路绕过
- 常见位置：删除按钮/提交按钮/导入导出的"设置放行"逻辑

## 模式 4：渲染门控的"非空跳过"旁路

- `if ( empty($form['submission']) ) { apply_filters(show_form) ... }` 型：某字段（submission/record/preview）已设置时跳过整个权限门控
- 若该字段在渲染流程早期被赋值（如 $form['submission'] = $submission->id），门控形同虚设
- 检查：权限 filter 外层是否有 `empty()` 提前 return 分支

## 模式 5：字段 name 直写任意 meta（无保护键名单）

- `acf_update_metadata($post_id, $field['name'], $value)` → `update_metadata('user', ID, name, value)`
- 若字段 name 攻击者可控（表单伪造/块注释注入定义字段）→ 可写 `wp_capabilities`（角色覆盖）、`session_tokens`（会话注入）、任意 user/post meta
- 检查：meta 写入函数是否过滤敏感键名

## 模式 6：动作路径权限不对称

- 同一 run() 内：edit 路径有 current_user_can 闸门，add/create 路径无闸门（add_user vs edit_user）
- 检查：所有 action 的 add_/create_/new_ 分支是否漏了与 edit 分支相同的检查

## 模式 7：双层 mime 校验（防误判，别当 RCE 报）

- `if ( mime_types 非空 && 扩展名不在列表 ) deny; else { wp_check_filetype + get_allowed_mime_types() 兜底 }`
- **else 分支无条件执行**：即使字段 mime_types 含 'php'，兜底仍拦截（php 不在 WP mime 映射）
- WP ≥ 4.7.4 对匿名用户额外剔除 htm|html|js|swf|exe
- 双扩展名 `shell.php.jpg`：校验通过但落盘保留末点扩展名（.jpg）→ 默认不可执行
- 结论：默认配置下此类上传端点只能传安全类型；RCE 需 Nginx `location ~ \.php` 无 $ 锚 + cgi.fix_pathinfo=1（罕见）

## 模式 8：目录零保护 + 直链

- 上传目录创建时**主动删除 .htaccess**（为兼容某些服务器）→ 目录无保护，文件直链可访问
- 文件 URL 随 AJAX 响应返回 → 攻击者直接拿到 URL
- 上传者 post_author=0（未认证）→ 无法按属主追溯

## 模式 9：提交/记录数据加密存储但服务端解密渲染 = 防护无效

- 存储用 fea_encrypt（服务端密钥），但读取端点（nopriv）服务端解密后直接渲染 → 攻击者读渲染结果，加密毫无意义
- 检查：所有"加密存储"的数据的读取端点是否有权限

## 常用检查命令

```bash
# 枚举 nopriv AJAX 端点（核心攻击面）
grep -rn "wp_ajax_nopriv" main/ --include="*.php"
# 权限检查分布
grep -rn "current_user_can" main/ --include="*.php" | wc -l
# 无权限的 AJAX 处理器
grep -rn "add_action( *'wp_ajax" main/ --include="*.php" | grep -v nopriv
```
