---
name: wordfence-bug-bounty
description: "Wordfence 赏金挖掘：WP 插件未认证 RCE/提权链、范围规则、目标筛选、提交材料。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [wordfence, wordpress, bug-bounty, rce, pentest, plugin-audit]
---

# Wordfence Bug Bounty 挖掘（WP 插件）

**用户目标（2026-08 确认）**：上交 Wordfence 漏洞平台。双轨策略：
- 长期：RCE / 权限获取级（High-Threat）漏洞为主攻
- 当前（破零优先）：**新上架/少人审的插件** + 小漏洞也交（$5-25 也要），先拿到第一个有效收录获得 **1337 研究员身份**（该身份对之后所有提交有全局 bonus）→ 再冲大洞
- 新手别碰热门插件（elementor/woocommerce/CF7 被职业研究者审烂）；0 安装新插件也在范围内且没人审，最好挖

## 触发条件

- 用户要做 WordPress 插件/主题漏洞挖掘、上交 Wordfence
- 用户贴出 bounty 规则/范围要求审计方向
- 需要选目标插件、按 Wordfence 格式写提交材料

## 范围规则（Wordfence 官方，详见 references/wordfence-rules.md）

- **范围内**：任何存在于 wordpress.org 仓库的免费插件/主题（**0 安装也在范围**）；premium 不在仓库需 ≥1000 安装（或销量 1:1 折算）才 in-scope
- premium：免费版安装量在范围内则 premium 也算范围内，但赏金按 premium 安装量
- **减分因素**：利用前提（软件设置/服务器配置）、需用户交互、跨软件依赖（赏金至少减半）、低敏信息泄露（Basic Info Disclosure 低价值）
- PHP Object Injection：有新的可用 POP gadget 才最高级
- 月度冲刺：同 CWE+认证级别每年最多 5 个计入冲刺 → 提交需多样化类型
- 最低 $5

## 目标筛选（优先顺序）

1. 安装量 1M+、免费版、wordpress.org 可下载
2. 类型：文件管理/备份迁移/导入导出/表单/上传（文件操作多 = RCE 面大）
3. 维护一般（更新频率低/版本老）优先；排除大厂维护好的（updraftplus/jetpack）与被审烂的（elementor/woocommerce/CF7）
4. 历史有 CVE 但修复不彻底的插件（权限模型复杂 → 新绕过概率高）
- 候选清单获取：wordpress.org API（见下）
6. 破零阶段目标：新插件列表 `https://wordpress.org/plugins/browse/new/`（HTML 页稳定，API browse=new 不稳），挑上架 1-6 个月、功能含上传/导入/表单/签名/预订的；用 API plugin_information 单查安装量

## 审计流程（修正版，来自实测教训）

```
Step 0: 下载源码 → 项目识别（语言/框架/规模）
Step 1: 倒推 5 分钟：要拿权限/RCE，最短路是什么（权限来源→触发点→输入通道）
Step 2: 端点正推：枚举 nopriv AJAX 端点 + nonce 校验强度 + 权限检查一致性
Step 3: 信任边界：配置/表单定义/字段名等管理员数据是否攻击者可控（伪造配置能做什么）
Step 4: 对已知/已报告根因做变体穷举（换注入目标、换组合配置）
Step 5: 多 Agent 并行验证 → 汇总去重 → 按 Wordfence 减分因素评估
Step 5.5: **靶场端到端复现(铁律,提交前提)** → 见 references/phpstudy-wordpress-lab.md
         - 用户要求"得复现出来的"才提交;材料必须标注复现状态+实测输出
         - 复现结果经常推翻静态结论(见下"运行时拦截"教训):删除用户被 conditions_logic 拦、
           非零作者文章被拦、add_form 被 related-items 抢先 die()——静态分析高估范围是常态
Step 6: 提交材料（SECTION 1-5 + 浏览器控制台 PoC）→ 材料中"受影响版本/前提条件"按复现结果修正

Step 7: **真实站点验证（配置依赖洞强制）**
  - 靶场复现成功 ≠ 真实世界可利用。配置开关类前提（"保存提交开启""需存在特定数据"）会过滤掉大部分真实站点
  - 实操：FOFA（用户有会员）按插件特征搜真实使用站点（如 `fea-submissions` 目录、`frontend_admin/form_submit` action、插件路径）→ 导出 CSV → 抽查 3-5 个站点公开页面（**只做与访客一致的 GET 观察**：确认表单渲染、收集什么字段）→ 定价值档位
  - 红线：真实站点**禁止发漏洞利用参数**（如 `?submission=1` 探测）——未授权 + Wordfence 规则禁止；用户如明确授权"只看信息不改数据"，也只做读响应不写数据
  - 实测案例（ACF Frontend P0-3）：靶场完美复现未认证读提交 PII；FOFA 35 个真实站点全是招聘/领养/预约场景（场景真实），但抽查第一个站点 `?submission=1` 未命中——"保存提交"开关真实开启率极低 → 价值从"可交"降为"弃"。**开启率无法远程确认的配置依赖洞，默认按低值处理**
  - 提交材料"影响"部分按真实验证结果如实写，不粉饰场景普遍性
```

### 实测教训（必须遵守）

- **旧报告污染**：项目里已有的审计报告当"验证清单"而非"划掉清单"；已报告根因必须变体穷举。读了报告就跳过目标链 → 只能找到边角洞
- **倒推优先**：只正推端点会漏掉最强链（实测：同一插件正推只找到删除/泄露，倒推才能到建管理员 9.8 链）
- **配置依赖减分**：明确写出每条链的配置前提；默认配置可利用的洞优先
- **子 Agent 红线**：派发 context 必须写"只用 terminal/read_file/search_files，禁用 execute_code"
- **运行时拦截(2026-08 FEA 实测,静态分析必查)**:
  - do_action 有多个订阅者时,先注册的无条件 `die()` 会杀死整条链(add_form → related-items render_form 抢先,submissions 渲染永远轮不到)
  - 厂商 3.x 修复常用"渲染时 conditions_logic 重查权限"模式:令牌铸造/对象 ID 在 show_form/special_permissions filter 里被置 'none'(user_id 必拦,post 靠 is_author 边界)
  - **边界误判**:`get_post_field('post_author',$id) == $user->ID` 对未认证($user->ID=0)+ post_author=0 文章 → 通过 → 只能删"无作者/导入/迁移"文章,不是任意文章
  - 结论:每条链的"实际可利用范围"以靶场实测为准,材料里写清边界

## WordPress 访问（国内网络）

- wordpress.org 直连/HTTP 代理均失败；Clash 7890 需 **socks5h**（远程 DNS）：
  `curl --socks5-hostname 127.0.0.1:7890 URL`
- 热门插件清单：
  `https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request%5Bbrowse%5D=popular&request%5Bper_page%5D=100`
- 下载：`https://downloads.wordpress.org/plugin/<slug>.zip`（最新版）或 `.../<slug>.<version>.zip`

## 提交材料结构（WORDFENCE_SUBMISSION_<Name>_中文版.md）

- SECTION 1 软件信息（名称/slug/安装数/受影响版本）
- SECTION 2 漏洞详情（CWE + 标题 + CVSS 3.1 + 技术描述 + 前置条件统一清单 + 受影响文件代码片段）
- SECTION 3 逐步复现（curl 请求序列）
- SECTION 4 PoC（浏览器控制台 JS，URLSearchParams 编码，自动提取 nonce）
- SECTION 5 影响 + 附加信息（与既有漏洞关系/实测环境/是否告知厂商）
- 模板见 references/submission-template.md

## 参考资料

- references/wordfence-rules.md — 官方赏金规则提炼（范围/减分/冲刺）
- references/wp-plugin-unauthenticated-patterns.md — WP 插件未认证攻击模式清单（匿名 nonce 共享、服务端令牌铸造、权限短路等）
- references/submission-template.md — Wordfence 提交材料骨架
- references/phpstudy-wordpress-lab.md — phpStudy/Win 本地靶场搭建与复现细节（MySQL 6778 端口、PHP 版本切换、ACF 字段结构、常见坑）
