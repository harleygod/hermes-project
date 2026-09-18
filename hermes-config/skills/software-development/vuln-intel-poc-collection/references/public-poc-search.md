# 公开情报搜索途径可用性矩阵（curl 实测）

目的：查"某漏洞/接口是否有公开 POC"。用户偏好浏览器搜索或联网搜索 API；
以下为 curl 兜底途径的实测结论（2026-08，经 Clash 代理 127.0.0.1:7890）。

## 可用（curl 直接能出结果）

| 途径 | 用法 | 备注 |
|------|------|------|
| DuckDuckGo HTML 版 | `https://html.duckduckgo.com/html/?q=<urlencode>` + 浏览器 UA | 对 curl 最友好；grep `class="result__a"` 取标题，`class="result__snippet"` 取摘要 |
| GitHub issues search | `https://api.github.com/search/issues?q=<kw>` | 匿名可用（限速 10/min）；漏洞名/接口名常出现在 issue 标题。**匿名 core 限流 60 次/小时，共享代理 IP 极易耗尽（403 rate limit exceeded，TongWeb 案例踩到）→ 改抓 HTML：`https://github.com/<owner>/<repo>/issues/<n>` 不走 API 不限流，`<meta name="description">` 即标题+正文开头。中文关键词 CJK 模糊匹配噪音巨大（搜"数犀"命中"犀牛鸟"/lingxi），中文产品名基本不可用** |
| GitHub commits search | `https://api.github.com/search/commits?q=<kw>` + `Accept: application/vnd.github.cloak-preview+json` | 匿名可用；查 POC 提交 |
| nuclei-templates 文件树 | `https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1` | 匿名可用；grep `"path"` 里的关键词（如 ecology），直接看出官方有哪些该产品漏洞模板 |
| GitHub raw 文件 | `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>` | 拉配置文件/源码查默认密钥等 |
| CSDN 文章 | `curl -sL <article_url> -A "<浏览器UA>"` 后解析 `id="content_views"` div | 无需登录/无验证码（实测 2026-08，156KB 正常返回）；抓标题 + 正文直接看 POC/复现细节。用户给 CSDN 链接时先 curl，不必开浏览器 |
| NVD API keywordSearch | `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<厂商名>&resultsPerPage=40` | 匿名可用（实测 2026-08）；查"某产品名下有无 CVE 归属"（如 inspur 仅 5 条硬件 CVE）——CVE 层面干净是 0day/未公开的佐证之一 |
| 搜狗网页搜索 | `https://www.sogou.com/web?query=<urlencode>` + 浏览器 UA | 国内搜索 curl 兜底，但**时好时坏**（一次 10 条完整结果，后续同参数返回 525B 空页）——带 `-c` cookie jar 重试几次，别一次失败就放弃。产品背景/市场地位调研可试 |\n| 微信搜狗（公众号） | `https://weixin.sogou.com/weixin?type=2&query=<kw>` + UA | 不被反爬但**结果对安全词不敏感**（2026-08 致远案例返回概念股/旧闻垃圾），公众号 nday 情报抓不到——低信号渠道，只有别的全废才试 |\n| 百度网页搜索 | `https://www.baidu.com/s?wd=<kw>` + UA + `Accept-Language: zh-CN,zh;q=0.9` | 实测 2026-08 致远案例**连续多次成功**（799KB 完整页）；解析 `<h3[^>]*>\s*<a[^>]*href="..."` 取标题+链接（结果 URL 是 `baidu.com/link?url=` 跳转，需 `-L` 跟随拿真实地址）。仍可能反爬（~540B 验证页），失败就换别的，别死磕 |
| CSDN 搜索 API | `https://so.csdn.net/api/v3/search?q=<kw>&t=all&p=1` | 匿名 JSON（实测 2026-08）；返回 `result_vos[].title/.nickname`——查产品官方运营号/技术栈/社区版线索，比翻文章页快 |
| 用友/泛微等厂商公告 | curl 直连常被 Cloudflare 等拦 | 见 memory 红线：被拦时申请 computer_use 浏览器或请用户截图，绝不用知识库旧数据代替 |

## 不可用/受限（踩过）

| 途径 | 问题 |
|------|------|
| grep.app | Vercel Security Checkpoint 拦截（HTML 验证页） |
| Sourcegraph stream API | 走 Clash 代理 CONNECT 建立但响应为空 |
| GitHub code search API | 需要认证 token；无 token 时用 issues/commits 代替 |
| Gitee api/v5/search | 返回空（可能限流/反爬），gitee.com issue 页面需登录看全文 |
| Bing 国际版 | UA 不带时无结果；带 UA 也未必稳定，优先 DDG。**中文查询实测被替换成无关结果**（2026-08 致远案例：搜"致远OA wapi"返回日语汉字字典、搜"wapi.getConditionValue"返回抖音链接——查询被吃/区域重定向），中文情报别用 Bing |\n| 爱企查/天眼查/企查查 | JS 壳，curl 只拿到模板（注册资本/成立日期/参保人数全无）；公司规模/融资/工商数据走 computer_use 浏览器 |\n| 官网直接抓 | 数犀案例：shuxitech.com 200 但 curl 空文件、shuxisec.com 403 拦爬虫——官网域名探测（`curl -o /dev/null -w %{http_code}` 猜域名）只能确认"活着"，内容经常抓不到，走浏览器 |
| 先知 xz.aliyun.com 站内搜索 | 搜索页返回的 `/news/<id>` 是**侧边栏固定推荐文章**（换关键词结果一样：17597/17841）——搜索功能 curl 不可用（要登录/JS），别拿它当搜索结果 | 
| Google | curl 基本被验证码挡；但**浏览器里 Google 的 AI 概述**对"该漏洞是否公开"的判断很有效（用户偏好浏览器搜索的原因之一） |

## 搜索关键词模板
- `"<接口路径>"` + 系统名（精确匹配接口是否被人写过）
- `"<参数名>"` + 系统名
- 系统名 + 漏洞类型（表达式注入/OGNL/SpEL/SQLi）
- 区分同名漏洞：命中结果必须核对**接口路径完全一致**才算公开；只匹配到"同系统其他漏洞"不算

## 参考做法（本次案例）
泛微 e-cology verifyFormula 表达式注入：Google AI 概述 + DDG + GitHub issues/commits + nuclei-templates tree 全部无该接口 → 判定未公开 1day → 自研 POC。其中 nuclei tree 列出的 17 个 ecology 官方模板正好用于排除"已公开的相似漏洞"（appThirdLogin RCE、getdata.jsp SQLi 等）。

## 0day 纯度佐证：老洞公开度对照法（泛微 dispatch 案例 2026-08）

判断某新入口是否真未公开时，先搜该产品**同类的已知老洞**（泛微 e-cology：BeanShell 未授权 RCE、getdata.jsp SQLi、XmlRpcServlet 文件读取——Google 一搜一大把、CSDN/GitHub 遍地）：
- 老洞公开资料**极其丰富** + 新入口**全渠道零命中**（Google 精确搜接口名无直接结果、CSDN 0、GitHub issues 0、NVD 无 CVE）= 强"未公开/极罕见"佐证——产品本身是安全圈常客，若入口公开过，搜索引擎大概率早已收录
- 注意区分"泛词噪音"：`dispatch/invoke` 这类词在 GitHub 上有 9.6 万条但全是 dotnet/wasm 无关内容；判定必须逐个核对是否与目标产品/接口路径一致
- 浏览器（Google）是这条线的最终裁决：curl 全通道试完仍无果时用 computer_use 接浏览器搜精确串（引号全匹配 `"dispatch/invoke/java.lang.String"`），用户会主动提醒"你可以接浏览器呀"——别在 curl 死磕

## POC 合集仓库：下架现状与替代（致远 wapi 案例 2026-08）

大而全的 POC 合集仓库（wy876/POC、POC0/wpoc 等）**经常被 DMCA 下架/改名**（git clone 报 Repository not found）——别依赖固定 URL。替代路径：
1. GitHub repo 搜索 API `search/repositories?q=<产品名> poc`（匿名可用、不受 issues 端点限流）找**活着的专项仓库**——致远案例：Summer177/seeyon_exp ★425、li8u99/Seeyon_exp_plus ★58、A0er/seeyonOA_POC 等
2. 浅克隆后 grep 接口名/类名（`--depth 1` 即可）——老仓库往往只覆盖老洞（致远系仓库全停在 htmlofficeservlet/getSessionList/test.jsp SQLi 时代），**新 nday 大概率不在里面**，零命中本身就是"没沉淀到公开 POC 库"的佐证

## 新 nday 全渠道零命中的判读（致远 wapi.getConditionValue 案例 2026-08）

用户报"nday"但全渠道（CSDN/GitHub/搜狗/Bing/百度/微信/先知/官方文档）零直接命中时：
- 三种可能如实摆出：① 极新鲜（几天内）渠道未索引；② 名称来自源码/调用链，公开文章用别的名字；③ 只在群里/私有情报流传
- 官方开发文档可作为背景（致远 wapi = 开放平台 API 体系，open.seeyon.com GitBook：`/book/` + 拼音页名 + 无 search_index.json，正文可抓但可能不含安全词）
- **下一步要用户给来源线索**（公众号链接/群消息/通报截图）定向挖——盲搜到此为止，继续烧时间没意义；有请求样本则直接走 3.5 解读流程

## 产品使用广度判断信号（数犀云身份连接器案例，2026-08）

用户问"这个软件用的人多嘛"时，多源交叉判断，不靠单一搜索：

1. **产品名精确匹配各渠道结果量**：CSDN 搜索 API（30 条但零相关=无痕）、Bing 0、GitHub 0、百度 ~9 条全自家营销 → 全渠道近乎空白 = 长尾产品。装机量大的国产软件（帆软/泛微）CSDN 讨论必然一大把
2. **自家营销 vs 独立第三方讨论比例**：命中内容全是宣传稿（公众号/知乎自答）≈ 无独立测评/踩坑帖 = 生态薄
3. **竞品对比**：搜索自然带出同赛道玩家（数犀案例带出 Authing/宁盾/竹云/腾讯云数字身份）——在结果里出现频率即份额排序
4. **客群画像**：身份连接器这类"桥"产品服务中小企业/传统企业（钉钉/用友对接），客群本身安全采购少；私有化部署 → 公网暴露面小 → "遇到了就打"而非 FOFA 扫
5. **单点价值 vs 存量**：身份/连接器类单点价值高（账号体系/令牌/同步密钥一锅端）但存量窄——结论格式：单点值钱 + 适用范围窄 + 建议策略

**MSYS/curl 坑（git-bash）**：`curl -o` 用绝对中文路径（`/d/Pentest/攻防/武器库/x`）会静默失败（文件不生成）——先 `cd` 到目标目录用相对路径，或管道直出到 python 解析（管道比 -o 稳）。
