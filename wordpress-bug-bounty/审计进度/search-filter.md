# search-filter 审计 (2026-08-11) — SQLi/XSS 面第一单

## 基本信息
- 50000装, 1.2.18 (240天未更新), 搜索过滤插件 (分类/标签/自定义分类/日期/文章类型筛选)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\sf-1.2.18\ (16文件, 主文件1337行)
- semgrep (wp_rules_sqli_xss.yaml 3规则): 0 发现 ✓ 与手工一致

## 攻击面分析
1. 日期过滤 (posts_where, :339-362): $post_date → DateTime::createFromFormat('Y-m-d') 严格解析 + format('Y-m-d H:i:s') 重写
   → 注入字符被格式化解毒 (createFromFormat 只取合法日期部分, format 只输出数字/-/空格/:) → 无 SQLi ✓
2. 分类/标签/自定义分类 (:506-617, :624-693): sanitize_text_field + get_category/get_tag/get_term_by slug 白名单化 → 值不可控 ✓
3. 搜索词 (:696-708): sanitize_text_field + rawurlencode → URL 参数 ✓
4. 表单渲染 (get_search_filter_form): 全 esc_attr/esc_url/wp_kses_post → 无 XSS ✓
5. ★ 开放重定向 (:827): `wp_redirect(esc_url($_POST[SF_FPRE.'empty_search_url']))`
   - 触发: 空搜索提交 (urlparams=='/?s=') + empty_search_url 参数
   - nonce 'searchandfilter_form' 在搜索表单渲染时输出 (前端短代码) → 未认证共享 → 可达
   - **但 Wordfence 不收 open redirect → 不交**

## 判定
- **放弃**: 无 SQLi/XSS; 唯一发现是 open redirect (Wordfence out of scope)
- 教训: esc_url 防不住 open redirect (允许外域); 但它本身也是 Wordfence 不收的类型, 看到即跳过
- semgrep 机械层再次证明与手工一致: 工具定位, 人工判定
