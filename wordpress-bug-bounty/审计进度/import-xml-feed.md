# 审计进度 — import-xml-feed 2.1.6

> 状态: 已放弃(nonce 不可达) | 日期: 2026-08-09
> 源码: D:\Documents\sources\Wordpress插件\import-xml-feed\
> 安装量 2000 | 2026-05 更新 | NVD 干净

## 结论
**XXE 面真实存在(无 LIBXML 选项 + 回显确认)但被 nonce 可达性挡住**:AJAX 需要 nonce('moove_xml_admin_nonce_field'),nonce 只在 manage_options 设置页输出(moove-options.php:90 add_options_page)→ Contributor+(edit_posts)拿不到 nonce → 实际不可利用。排除。

## 关键代码
- moove-actions.php:79-95 moove_read_xml:nonce + current_user_can('edit_posts') → $args['data'] 到 controller
- controllers/moove-controller.php:217-232 moove_read_xml:simplexml_load_string($data) 无 LIBXML 选项(PHP7 默认外部实体可展开 = XXE)
- :159-183 moove_recurse_xml:叶子节点 value 输出(htmlspecialchars+maybe_unserialize)→ 实体内容回显
- :185-187 moove_importer_sanitize_xml:直接返回(无过滤)
- nonce 输出:views/moove/admin/settings/settings_page.php:3
- moove_create_post(:101-114):同 nonce + edit_posts,不可达同样排除
- URL 模式:moove_importer_get_content(内部 curl 抓取,esc_url http/https/feed 限制)

## 待办
- 无(放弃)。若未来需要:POP chain(maybe_unserialize 在 moove_recurse_xml 输出处!)——但前提同样是 nonce 可达
