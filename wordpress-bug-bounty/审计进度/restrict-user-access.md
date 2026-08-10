# 审计进度 — restrict-user-access 2.8

> 状态: 进行中(发现 XML-RPC 绕过,待靶场验证) | 日期: 2026-08-09
> 源码: D:\Documents\sources\Wordpress插件\restrict-user-access\
> 安装量 10000 | 307 天前更新(2025-10)| NVD 干净

## 主发现(待验证): 订阅者 XML-RPC 绕过内容访问控制(CWE-862)
**逻辑链**:
1. 核心保护 authorize_access() 只在 template_redirect 触发(level.php:34-39 add_action)
2. 全项目 grep 无 XML-RPC 拦截逻辑
3. WP 核心 XML-RPC(xmlrpc.php 默认开)wp.getPost 对 publish 文章返回完整 post_content
4. 攻击链:站点配置级别保护(核心功能)→ 注册订阅者(默认允许)→ xmlrpc.php wp.getPost(受限文章ID)→ 绕过前端拦截读全文
5. 影响:任何注册用户读全部会员内容,插件核心功能失效
6. Wordfence 视角:Authenticated (Subscriber+) 权限绕过,插件核心价值失效 → $100-500 档

**靶场验证卡点**:WPCA 条件系统是 SQL 级(post_type 模块 in_context+db_join 查 restriction posts),手动写 _ca_condition-groups meta 不生效(缓存 _ca_condition_type_cache option)。需 UI 配置或清缓存重试。

## 已查面(结论)
| 面 | 结论 | 位置 |
|---|---|---|
| ContentMode(列表模式) | the_content 截断,rest_authentication_errors 覆盖 REST ✓ | src/Module/ContentMode.php:104-108 |
| RestApiContentProtection | 未认证/订阅者拦截 REST(/wp/v2/posts 等);contributor+ 放行 | src/Module/RestApiContentProtection.php:34-90 |
| AdminAccess | auth_redirect 拦截无 admin_access 级别用户(DOING_AJAX 跳过) | src/Module/AdminAccess.php:34-60 |
| authorize_access | template_redirect;default_access/authorized_levels/drip 三层检查,逻辑严密 | level.php:274-405 |
| has_global_access | administrator 角色 | models/user.php:56-60 |
| Automator | admin 配置面;wp_ajax 仅 is_admin 注册 | src/Membership/Automator/AutomatorService.php:84 |
| Restrict 短代码 | level 不存在时放行(参数作者可控,不可利用);大小写误判需作者写错 | src/Shortcode/Restrict.php:30-120 |
| QueryFilters | 评论查询过滤(内部逻辑) | src/Membership/QueryFilters.php:37-75 |

## 待办
- [ ] 靶场验证 XML-RPC 绕过(UI 配置条件 或 清 WPCA 缓存后手动 meta)
- [ ] 可选:验证 REST 的 contributor+ 放行是否有面(contributor 调 REST 读受限文章?——REST 拦截对 contributor 放行,但 contributor 有 edit_posts,本来可看内容?待确认)
