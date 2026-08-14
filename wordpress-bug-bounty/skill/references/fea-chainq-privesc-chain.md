# FEA (acf-frontend-form-element) 3.29.10 ChainQ 未认证提权链 — 已验证源码级笔记

> 来源：2026-08-14 会话。朋友审计的 Wordfence 提交材料（`WORDFENCE_SUBMISSION_ChainQ_中文版.md`），我方逐条核实 11 处代码位置全部属实。**朋友的成果不提交**，仅作教学/同插件后续审计的参考。此链是 skill 中"前端表单插件删除链（FEA P0-1）"的姊妹链：同插件、同信任模型、不同根因。
>
> **2026-08-14 同会话已在本机靶场（WP 7.0.3 + FEA 3.29.10）端到端跑通**：伪造文章(ID=40) → change_form 拿伪造表单 nonce → 提权提交 → `wp_usermeta.wp_capabilities = a:1:{s:13:"administrator";s:1:"1";}` + `Set-Cookie: wordpress_logged_in_*` → 带 Cookie 访问 `/wp-admin/` 200 管理员仪表盘、`/wp-admin/plugin-install.php` 200。可复现 PoC 脚本留在 `D:\phpstudy_pro\WWW\_chainq_poc.py`（三请求全自动，未认证）。重放坑（`_acf_objects` 必须带 / change_form 用页面 JSON nonce / form_key 要 form_ 前缀 / 改代码改运行实例那份）见 `references/wp-lab-setup.md` 的"FEA 表单提交重放四大坑"。

## 一句话本质
公开投稿表单的处理逻辑是**配置驱动**的：字段叫什么、保存到哪里（post/user）、建用户还是改用户、是否自动登录，全由表单配置决定。攻击者伪造一份自己的表单配置（块注释注入）→ 让插件渲染它 → 提交时 add_user 路径无权限检查 + 字段 name 直写 user meta → 覆盖 `wp_capabilities` → 自动登录 = 管理员。

## 五步链 + 代码位置（已核对）
1. **注入通道**：表单勾选官方设置"Allow Unfiltered HTML"→ `submit.php:303-306` 的 `if($form['kses'])` 分支整体跳过 → `feadmin_sanitize_input`（helpers.php:278-285，即 `wp_kses_post`）不执行 → 攻击者在 Post Content 字段提交 Gutenberg 块注释 `<!-- wp:frontend-admin/form {"form_key":"pwn","form_settings":{"save_to_user":"new_user","login_user":1}} /-->` 完整落库（经 wp_update_post 的 wp_unslash 还原）
2. **配置加载**：`change_form`（display.php:1627-1695，nopriv 注册于 :1956）接受 `form_data={文章ID}_gutenberg_{key}` → gutenberg/blocks/form.php 的 `get_form_block`/`get_field_block`（:426-464）解析攻击者文章的块 attrs 为表单+字段定义 → 渲染并吐出 `_acf_nonce`
3. **创建用户无闸门**：user.php:439-444 只拦 edit_user 路径（`'add_user' !== $user_id` 特例放行）；:509-538 `wp_insert_user` 无任何 current_user_can
4. **meta 直写**：user.php:589-594 `acf_update_value(...)` → acf-value-functions.php:224 `acf_update_metadata($post_id, $field['name'], $value)` → `update_metadata('user', ID, $field['name'], ...)`。伪造字段 `name="wp_capabilities"` = 角色字段被任意写，无保护键名单
5. **自动登录**：user.php:597-603 `$form['login_user']` → `wp_set_current_user` + `wp_set_auth_cookie` → 响应 Set-Cookie 即管理员会话

## 关键代码事实（FEA 3.29.10，后续审计复用）
- **kses 默认逻辑**：display.php:289 `'kses' => isset($form['no_kses']) ? !$form['no_kses'] : true` —— 表单配置序列化数组里**没有 no_kses 键 = 默认清洗开启**；要复现块注释注入必须让表单配置含 `no_kses=1`
- 表单 = `admin_form` post，`post_content = maybe_serialize(配置数组)`（例：`a:5:{s:12:"save_to_post";s:8:"new_post";s:11:"who_can_see";s:3:"all";...}`）
- 字段 = `acf-field` post（post_parent=表单 ID）：post_name=字段 key、post_excerpt=字段 name、post_content=serialize(设置数组)
- **块注释唯一写入载体 = Post Content 类型字段**（type=post_content）；text/textarea 写 post meta，`get_the_block` 不读取 → 表单没有 Content 字段则链断在第一步
- 3.29.10 的既有修复（edit_user 内联闸门 :439-444、change_form is_numeric 门控 :1659-1661）**未覆盖创建路径与 meta 注入**

## 前置条件矩阵（复现前逐项核对靶场表单）
| 设置项 | 必需性 | 原因 |
|---|---|---|
| 保存到 = 新建文章 (save_to_post=new_post) | 必需 | 链第一步必须建文章（含块注释）；编辑模式未认证被作者校验拦截 |
| 谁可以看 = All Users (who_can_see=all) | 必需 | 未认证要能提交 |
| Allow Unfiltered HTML (no_kses=1) | 本 PoC 通道必需 | 跳过 kses 清洗块注释才完整落库；核心缺陷不依赖此项（ACF acf_form/REST 等通道亦可） |
| 字段：Post Content (type=post_content) | 必需 | 块注释唯一写入载体 |
| 新文章状态 | 可选 | 默认自动 publish；draft 也不影响（get_the_block 不查状态） |

## 靶场核对表单前置条件的命令（Windows/phpStudy，MySQL 5.7.26）
```bash
MYSQL=/d/phpstudy_pro/Extensions/MySQL5.7.26/bin/mysql.exe
"$MYSQL" -uroot -proot wordpress_test -e "SELECT post_content FROM wp_posts WHERE ID=<表单ID>;"   # 看 save_to_post/who_can_see/no_kses
"$MYSQL" -uroot -proot wordpress_test -e "SELECT ID,post_title FROM wp_posts WHERE post_type='acf-field' AND post_parent=<表单ID>;"  # 看有无 post_content 类型字段
# 页面渲染验证：curl -sL -H "Host: localhost" "http://127.0.0.1/?page_id=10" | grep -o 'data-key="[^"]*"' 
```
- **localhost curl 坑**：`curl http://localhost/?page_id=10` 直连会 301/503（Apache 虚拟主机解析），必须 `-H "Host: localhost"` + `-L` 且用 `127.0.0.1` 才 200
- MySQL 5.7.26 的 bin 目录在 `D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe`，本靶场 DB=wordpress_test root/root（无密码参数警告可忽略）

## 后续审计启示
- **"配置驱动表单" = 信任边界**：凡表单行为（save_to_*/new_*/login_user/角色/字段 name→meta 键）由配置决定，先问"配置谁给的"。攻击者能写配置（块注释/短代码属性/用户可控 post）或能加载任意配置（change_form 式任意 ID）→ 权限模型崩溃
- **add_user/edit_user 双路径插件**：修了编辑路径的闸门 ≠ 创建路径安全——逐路径检查 current_user_can
- **字段 name 直写 meta 键**（ACF 系通病）：`acf_update_metadata($post_id, $field['name'], $value)` 无敏感键白名单 → 能写 `wp_capabilities`/`user_level` 等 = 提权。看到 `update_metadata('user'...` 条件反射：能写 user meta = 能提权
- **CVSS 9.8 的底气**：三个"任意"（任意写配置/任意加载配置/执行无鉴权）串起来 + 前置条件是官方正常设置（富文本），不是配置依赖降级

## WP → Java/Spring MVC 对照表（给 Java 背景审计者教学用）
| WordPress | Java/Spring MVC 对应 | 含义 |
|---|---|---|
| `wp_ajax_nopriv_xxx` | `@PermitAll`（接口无登录要求） | 未认证可达的入口点 = "公开接口清单"，先数它 |
| `wp_ajax_xxx` | 默认需登录态 | 登录用户才能调 |
| nonce (`_acf_nonce`) | 页面内嵌的 CSRF token | 只证明"请求来自本站页面"，**不是权限凭证**；匿名 nonce（uid 0 + 空 token）全站访客共享，页面 HTML 可抠 |
| `current_user_can('edit_user',$id)` | `@PreAuthorize("hasAuthority(...)")` | 真正的权限检查。**没有它 = 洞** |
| `wp_usermeta.wp_capabilities` | User 实体的 roles/authorities 字段 | 角色存这；能写它 = 能当管理员 |
| Gutenberg 块注释 `<!-- wp:x {...json} /-->` | 富文本里嵌结构化 JSON | 文章正文的存储格式，kses 跳过时攻击者可自定义 |
| 表单配置（save_to_*/login_user/字段 name） | 接口的行为由请求体 JSON 里的配置决定（而非代码写死） | 配置驱动 = 攻击者可伪造行为 |
| `change_form` 任意 form_data | 公开接口可传任意 templateId 渲染任意模板 | 配置加载无校验 |
