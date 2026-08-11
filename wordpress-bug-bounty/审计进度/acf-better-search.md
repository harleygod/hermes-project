# acf-better-search 审计 (2026-08-11) — SQLi/XSS 面第二单

## 基本信息
- 40000装, 4.5.0 (71天), ACF 字段搜索增强 (posts_join/posts_search filters)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\abs-4.5.0\ (69文件, 现代OOP)
- semgrep (3规则): 34文件 0 发现 ✓ 与手工一致

## 攻击面分析
1. posts_join (Join.php:43-83): JOIN 表名固定 $wpdb->postmeta/posts; get_fields_types(:117) 用 _real_escape 转义配置值
   → 配置值来自后台设置(管理员), 非用户输入 ✓
2. posts_search (Where.php:43-61): 搜索词 query_vars['s'] (用户可控 /?s=) → get_phrase_regex(:123-131)
   → **_real_escape 转义后拼接** (LIKE '%...%' / REGEXP '\b...\b')
   → 单引号/反斜杠都被转义, 字符串字面量内无法逃出 → 无 SQLi ✓
   (REGEXP 分支同样安全: 模式内容在转义字符串内, 无法闭合引号)
3. posts_distinct (Request.php): 固定 'DISTINCT' ✓
4. 触发: 任何带 s 参数的前端搜索 (pre_get_posts 主查询) — 未认证可达但无洞

## 判定
- **放弃**: 搜索词 _real_escape 转义 = WP 标准实践, 无 SQLi/XSS
- 教训: 大插件(10k-50k装) SQL 拼接普遍用 _real_escape/参数化 — 这是 WP 生态常态;
  semgrep 自定义规则 + 手工双重确认 = 无洞可信
