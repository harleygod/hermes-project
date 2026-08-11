# 公开情报搜索途径可用性矩阵（curl 实测）

目的：查"某漏洞/接口是否有公开 POC"。用户偏好浏览器搜索或联网搜索 API；
以下为 curl 兜底途径的实测结论（2026-08，经 Clash 代理 127.0.0.1:7890）。

## 可用（curl 直接能出结果）

| 途径 | 用法 | 备注 |
|------|------|------|
| DuckDuckGo HTML 版 | `https://html.duckduckgo.com/html/?q=<urlencode>` + 浏览器 UA | 对 curl 最友好；grep `class="result__a"` 取标题，`class="result__snippet"` 取摘要 |
| GitHub issues search | `https://api.github.com/search/issues?q=<kw>` | 匿名可用（限速 10/min）；漏洞名/接口名常出现在 issue 标题 |
| GitHub commits search | `https://api.github.com/search/commits?q=<kw>` + `Accept: application/vnd.github.cloak-preview+json` | 匿名可用；查 POC 提交 |
| nuclei-templates 文件树 | `https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1` | 匿名可用；grep `"path"` 里的关键词（如 ecology），直接看出官方有哪些该产品漏洞模板 |
| GitHub raw 文件 | `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>` | 拉配置文件/源码查默认密钥等 |
| CSDN 文章 | `curl -sL <article_url> -A "<浏览器UA>"` 后解析 `id="content_views"` div | 无需登录/无验证码（实测 2026-08，156KB 正常返回）；抓标题 + 正文直接看 POC/复现细节。用户给 CSDN 链接时先 curl，不必开浏览器 |
| 用友/泛微等厂商公告 | curl 直连常被 Cloudflare 等拦 | 见 memory 红线：被拦时申请 computer_use 浏览器或请用户截图，绝不用知识库旧数据代替 |

## 不可用/受限（踩过）

| 途径 | 问题 |
|------|------|
| grep.app | Vercel Security Checkpoint 拦截（HTML 验证页） |
| Sourcegraph stream API | 走 Clash 代理 CONNECT 建立但响应为空 |
| GitHub code search API | 需要认证 token；无 token 时用 issues/commits 代替 |
| Gitee api/v5/search | 返回空（可能限流/反爬），gitee.com issue 页面需登录看全文 |
| Bing 国际版 | UA 不带时无结果；带 UA 也未必稳定，优先 DDG |
| Google | curl 基本被验证码挡；但**浏览器里 Google 的 AI 概述**对"该漏洞是否公开"的判断很有效（用户偏好浏览器搜索的原因之一） |

## 搜索关键词模板
- `"<接口路径>"` + 系统名（精确匹配接口是否被人写过）
- `"<参数名>"` + 系统名
- 系统名 + 漏洞类型（表达式注入/OGNL/SpEL/SQLi）
- 区分同名漏洞：命中结果必须核对**接口路径完全一致**才算公开；只匹配到"同系统其他漏洞"不算

## 参考做法（本次案例）
泛微 e-cology verifyFormula 表达式注入：Google AI 概述 + DDG + GitHub issues/commits + nuclei-templates tree 全部无该接口 → 判定未公开 1day → 自研 POC。其中 nuclei tree 列出的 17 个 ecology 官方模板正好用于排除"已公开的相似漏洞"（appThirdLogin RCE、getdata.jsp SQLi 等）。
