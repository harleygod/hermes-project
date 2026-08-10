# 公开漏洞情报检索源 — 命令库（2026-08 实测验证）

所有请求走 Clash 代理: `export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890`
UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36`

**代理实测坑（2026-08）**：
- export 的代理 env 变量跨 terminal 调用不持久（命令超时中断后即丢）→ 每次命令内重 export，或 curl 显式 `-x http://127.0.0.1:7890`，git 用 `-c http.proxy=http://127.0.0.1:7890`（裸 git clone 会直连 GitHub 龟速超时；一劳永逸可 `git config --global http.proxy`）
- 大文件/jar 下载优先阿里云 Maven 镜像直连（`--noproxy "*"`，秒下）：`https://maven.aliyun.com/repository/central/<group路径>/<artifact>/<ver>/<file>`——repo1.maven.org 走代理可能超时

## 1. 搜索引擎
- DuckDuckGo HTML（curl 最友好，无验证码）:
  `curl -s "https://html.duckduckgo.com/html/?q=%22verifyFormula%22+%E6%B3%9B%E5%BE%AE" -A "$UA" | grep -oP 'class="result__a"[^>]*>.*?</a>' | sed 's/<[^>]*>//g'`
- Bing: `curl -s "https://www.bing.com/search?q=..." -A "$UA"`（解析 h2 链接，可能被反爬返回空——空结果本身也是情报）
- Google: 建议浏览器（curl 易被验证码挡）；看 AI 概述——若概述罗列的是"其他漏洞"，反证目标漏洞未公开

## 1.5 主源速查（先跑这两个，5 秒拿定性结论）
- NVD API（描述+参考+CVSS 一次拿全）:
  `curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-40494" | python -c "import json,sys; d=json.load(sys.stdin); v=d['vulnerabilities'][0]['cve']; [print(x['value']) for x in v['descriptions'] if x['lang']=='en']; [print(r['url']) for r in v['references']]"`
- GitHub Advisory API（严重性+影响版本范围；GHSA id 用 DuckDuckGo 搜 CVE 号，第一条即 GitHub Advisory）:
  `curl -s "https://api.github.com/advisories/GHSA-xfw6-m86r-mwwx"`
- 坑：NVD 参考区的博客链接（carrot2.cn / mari0er.club 等）常被反爬返回空或 404——不要硬刚博客，直接 nuclei 模板 + Advisory 拿细节

## 2. GitHub API（无需认证，未认证限速 ~10 req/min）
- issues: `curl -s "https://api.github.com/search/issues?q=verifyFormula+ecology&per_page=10"`
- commits（需 Accept 头）:
  `curl -s -H "Accept: application/vnd.github.cloak-preview+json" "https://api.github.com/search/commits?q=verifyFormula&per_page=10"`
- 提取: `grep -oP '"title":\s*"[^"]+"|"html_url":\s*"[^"]+"'` 或 `"message"` / `"path"`
- code search API 需认证 token —— issues/commits 通常已够判断公开性
- **POC 仓库检索（CVE 号直搜，比 issues 强）**: `curl -s "https://api.github.com/search/repositories?q=CVE-2024-36401&sort=stars&per_page=8" | grep -oP '"full_name":\s*"[^"]+"|"description":\s*"[^"]*"'`（Mr-xn / bmth666 等武器化 POC 仓库按 star 排序即得）
- 坑：issues search 搜裸 CVE 号（如 "CVE-2022-40494"）返回的全是 dependabot/renovate 依赖升级 PR 噪音，勿据此判公开性
- 命中全是无关项目（Salesforce 公式验证、数学脚本等）→ 视为未公开

## 3. nuclei-templates 官方模板库（无认证，判断官方 POC 覆盖）
`curl -s "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1" -A "$UA" | grep -oP '"path":\s*"[^"]*[Ee]cology[^"]*"'`
按产品名 grep（ecology / yonyou / landray / seeyon / tongda 等），看有没有对应漏洞模板。

**POC 提取捷径（2026-08 实测，最快路径）**：树里 grep 命中后，raw 拉取模板正文 = 官方验证过的完整 POC：
- 命中路径两类：`http/vulnerabilities/<产品>/xxx.yaml`（如 nps-auth-bypass.yaml）与 `http/cves/<年份>/CVE-xxxx.yaml`（如 CVE-2024-36401.yaml）
- CVE 编号已知可直接猜路径：`http/cves/2024/CVE-2024-36401.yaml`
- 拉正文：`curl -s "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/<path>" -A "$UA"`
- 模板自带：`verified: true` 元数据、完整 HTTP 请求（含参数构造如 `auth_key={{md5(unix_time())}}&timestamp={{unix_time()}}`）、matchers、shodan/fofa/google 指纹、参考链接
- 多步利用链（如先 MapPreviewPage 正则提取 typeName 再打 GetPropertyValue）模板里 flow/extractors 直接写明

## 4. 国内源
- Gitee repo 搜索: `curl -s "https://gitee.com/api/v5/search/repositories?q=verifyFormula&per_page=20"`（未认证限速 20/min，代码内容搜索需认证）
- CSDN / 博客园 / 微步在线 x.threatbook.com / 墨知 zhi.oscs1024.com / 腾讯云开发者社区：搜索引擎 site: 语法命中后浏览器阅读

## 5. 不可用源（2026-08 实测，勿浪费时间）
- grep.app: Vercel Security Checkpoint 拦截 curl
- Sourcegraph stream API (sourcegraph.com/.api/search/stream): 走 Clash 代理返回空
→ 一律用 DuckDuckGo HTML + GitHub API 兜底

## 6. 判定要点
- Google AI 概述 + 检索结果罗列邻近漏洞 → 目标漏洞未公开的强信号
- 必须区分邻近漏洞（同产品不同漏洞），示例——泛微 e-cology 已公开漏洞对照表：
  | 漏洞 | 状态 | 修复版本 |
  |------|------|----------|
  | /papi/passport/rest/appThirdLogin + H2 JDBC 反序列化 RCE | 公开 (2024.8 hw) | 10.69+ |
  | /js/hrm/getdata.jsp 未授权 SQLi | 公开 | <10.75 |
  | /api/doc/out/more/list + /api/ec/dev/table/counts 前台 SQLi (DES 加密绕 WAF) | 公开 (2025.7) | <10.76 |
  | E-Mobile OGNL 表达式注入 | 公开 (2021) | E-Mobile 产品，非 e-cology |
  | /api/excel/formula/verifyFormula + expressSql 表达式注入(内存马链) | 未公开 1day (2026.8) | — |

## 7. 浏览器检索（computer_use）
- Chrome 未开 remote-debugging 端口时无法 CDP 驱动；background type 对 Chrome 不可用，foreground swap 可能被 Windows 前台锁拒绝（UIAccess 限制）
- 可行路径：list_windows 看已开标签页 → 直接点击目标标签页 → 读 AX 树（Document 节点下的 Text/Hyperlink 元素）——**依赖 AX 树文本，不要依赖截图**
