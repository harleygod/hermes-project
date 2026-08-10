# pdf-viewer-block 补丁分析 (2026-08-10)

## 基本信息
- 10000装, 1.1 (2025-11-27), Gutenberg block 插件（嵌入 PDF 查看器, 用 pdf.js）
- 1.0.1 修 "Fix XSS security vulnerability. Thanks @wpscan"
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\pvb-1.0\ pvb-1.1\（SVN 单文件拉取, zip 下载因代理失败）

## 结构（block 插件极小, 核心 5 文件）
- pdf-viewer-block.php (33行): 主文件, 1.0→1.1 仅版本号
- admin/admin.php (51行): 后台, 无 diff
- public/public.php (46行): 前端 enqueue block 存在时加载 pdf-viewer-block.js + pdfjs viewer.html; wp_add_inline_script pdfViewerUrl(plugins_url 固定) 安全
- block.json: 无 render 字段 → block HTML 由 JS save 函数生成(存 post_content)
- ★ public/js/pdf-viewer-block.js: XSS 修复点

## XSS 修复 diff (pdf-viewer-block.js, 1.0→1.1)
- 修复前: `var href = $(this).find('.uploaded-pdf > a').attr('href');` → `src="' + pdfViewerUrl + '?file=' + href + '"` 直接拼接 iframe
- 修复后: `var href = encodeURI(...)` 
- 本质: 存储型 DOM XSS——post_content 里 block 的 href 属性注入 iframe src（`"` 闭合属性→onload 注入）
- 修复质量: encodeURI 编码 `"` `<` `>` → 属性注入防住; `'` 不编码但拼接用双引号无效; javascript: 在参数位不执行 → **有效单点修复, 无漏修(全文件仅此一处拼接)**

## 触发面判定（关键）
- block HTML 由 JS save 生成存 post_content; href 可被 REST API 直接写 post_content 控制
- 写权限 = edit_posts = **作者级** → 存储 XSS 但作者级写 → **超 Wordfence 范围(Contributor/Author 级排除)**
- 访客触发但写者需作者+ → 不交

## 结论
- 修复有效 + 触发面作者级超范围 → **放弃**
- 备注: inc/pdfjs/ 为第三方库, 即便有 pdf.js 旧版 CVE(如 CVE-2024-4367) 也属依赖漏洞不交
- 教训: block 插件攻击面 = JS save/render + post_content 可写性, PHP 端往往极小
