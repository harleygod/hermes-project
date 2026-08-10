---
name: wordpress-plugin-code-audit
description: "审计 WordPress 插件代码：nopriv 端点、匿名 nonce、上传双层校验、删除短路。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, wordpress, code-audit, php, exploit, penetration]
---

# WordPress 插件代码审计

WordPress 插件/主题的渗透视角代码审计专项。通用流程（架构推理 → 多 Agent 并行 → 去重汇总）见 `penetration-code-audit` skill；本 skill 是 WP 特有的攻击面清单与实证方法，基于 Frontend Admin (ACF Frontend) 3.29.10 审计实践提炼。

## 攻击面清单（按价值排序）

### 1. AJAX 端点全量清单（未认证攻击面核心）
```bash
grep -rn "wp_ajax_nopriv_" main/ --include="*.php"        # 未认证可触发
grep -rn "add_action( *'wp_ajax" main/ --include="*.php" | grep -v nopriv   # 登录即可触发
```
- nopriv = 未认证；wp_ajax(无 nopriv) = 登录即可，仍要看有无 capability 检查——很多只验 nonce 无 current_user_can → **订阅者越权**
- 注意注释掉的注册（`/* add_action(...) */` 或 `//`）——未注册端点无攻击面

### 2. nonce 体系（WP 特有）
- **匿名用户(uid 0 + 空 token)的 nonce 全站共享** → 任何渲染插件脚本的公开页面提取的 nonce，所有未认证请求通用
- 插件常见 `verify_ajax($nonce, $action)` 封装，默认 action 固定（如 acf_nonce）→ nopriv + 该封装的端点实际等同未认证无防护
- 按字段/动作命名的 nonce（如 `fea_delete_{key}`，key 攻击者可控）从页面 `data-nonce` 属性提取

### 3. 加密令牌铸造（关键组合件）
- 插件常用对称加密令牌保护对象 ID（如 fea_encrypt/fea_decrypt，key=wp_hash('xxx')）→ 攻击者不能自造
- 但常存在**令牌铸造端点**（如 change_form 类：任意 item_id → absint → 服务端铸造 `edit_{type}` 令牌并渲染表单）→ 令牌内容攻击者可控
- 铸造端点 = 任意对象编辑表单 + nonce 的来源，常是多个漏洞的公共前置

### 4. 文件上传（必须实证，别只读代码推断）
- nopriv 上传端点常仅验匿名 nonce + field_key 攻击者可控 → 未认证上传
- **双层校验陷阱**：扩展名白名单（字段 mime_types 配置）通过后，else 分支仍执行 `wp_check_filetype` + `get_allowed_mime_types()` 兜底
- `get_allowed_mime_types()`：WP≥4.7.4 对未登录用户剔除 htm|html|js|swf|exe；未知扩展名 wp_check_filetype 返回 type=false → 拒绝
- php/phtml/php5/pht/phar 全不在默认映射 → **默认配置不可 RCE**
- 双扩展名 shell.php.jpg：校验可通过，但落盘名取最后一个扩展名(.jpg) → 不可执行
- 结论：默认只传 jpg/png/pdf/zip 等安全类型；除非站点扩展了 upload_mimes（如允许 svg → SVG 存储型 XSS）
- **实证法**：`php -r` 直接跑 wp_check_filetype / get_allowed_mime_types 测行为，比读代码推断可靠
- 上传目录检查：插件可能主动 `unlink` 目录 .htaccess → 文件静态 URL 无鉴权直接访问

### 5. 删除端点短路模式（高价值）
```php
if ( ! current_user_can('edit_post', $id) && ! $allowed_by_settings ) { die; }
```
- 当表单配置/过滤器放行（show_form 返回非空）时 `$allowed_by_settings=true` → 短路权限检查
- 目标对象 ID 来自可铸造令牌 → 任意对象；wp_delete_user 无管理员豁免 → **可删管理员账户**
- 前提：站点存在渲染删除按钮的表单（who_can_see 对攻击者可见），nonce 从页面提取

### 6. admin CRUD AJAX
- plans/emails/payments/subscriptions/submissions 等 wp_ajax 处理器常只有 nonce 无 capability → 订阅者越权增删改业务数据

### 7. 表单提交记录读取
- 提交数据表（如 fea_submissions）含 PII；读取端点若无 nonce/权限检查 + 表单 who_can_see=all → 登录用户读全量提交

### 8. 前端 secret 泄漏（Elementor）
- Elementor 控件 `'default' => get_option('..._secret')` + widget 渲染时把 secret 塞进字段数组 → 若默认值随 widget 保存，前端 data-settings JSON 含 secret（需 Elementor 环境实测，标 UNCERTAIN）

### 9. SQL 注入
- admin-pages 常见 $wpdb->prepare / sanitize_sql_orderby 白名单；确认原生拼接：`grep -rn 'SELECT.*\.\s*\$_\|WHERE.*\.\s*\$_\' main/`
- duplicate/复制类 SQL 用 addslashes 属边缘（宽字节注入需 GBK 编码 + 库内可控数据，一般不成立）

### 10. Gutenberg 块解析
- `parse_blocks(post_content)` 递归匹配块 attrs → 若 post_content 可控（no_kses 通道）可定义任意字段（name/type）
- 配合 meta 直写：`acf_update_metadata($post_id, $field['name'], $value)` 字段 name 直接当 meta 键、无保护键名单 → `wp_capabilities` 等敏感 user meta 可覆盖 → 提权

## 捆绑代码
- 插件常捆绑完整 ACF 副本（custom-fields/）和 SDK（freemius/）→ 审计时排除 vendor 类目录，聚焦自有代码
- 但捆绑 ACF 的 acf_update_value / acf_update_metadata 是漏洞链执行点，必须跟踪

## 权限模型（表单类插件）
- who_can_see(all/logged_out/logged_in) + special_permissions（管理员配置的放宽）
- 渲染时和提交时都要过 show_form 过滤器；删除/编辑端点常只校验配置表单的权限、不校验目标对象 → 令牌 ID 即越权点

## 红线与工具坑
- **禁止 execute_code（用户红线）**：一律用 terminal；子 Agent 无记忆，delegation context 必须显式注明
- **search_files/ripgrep 中文路径 IO error**（报"系统找不到指定的路径"）：目录含中文（如 D:\Documents\sources\Wordpress插件\）时改用 terminal grep
- 子 Agent 找不到文件 → 先 find 定位；不确定的漏洞标 UNCERTAIN 不编造

## 输出
同 penetration-code-audit：FILE:LINE | TYPE | P0/P1/P2 | 利用方式（≤200字符）；P0=未认证、P1=登录越权、P2=组合链；不写修复建议；上传/删除类"可能成立"的洞标 UNCERTAIN 并给实证判定。
