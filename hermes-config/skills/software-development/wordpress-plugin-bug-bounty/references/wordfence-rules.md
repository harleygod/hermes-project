# Wordfence Bug Bounty 规则速查（2026-08-10 用户截图核实版）

官方页面（唯一权威）：https://www.wordfence.com/threat-intel/bug-bounty-program#rewards
（该页被 Cloudflare 拦 curl 抓不到 → 用 computer_use 浏览器看或请用户截图）

## 范围（In-Scope）— 2026-08 截图确认
**按漏洞类型分门槛，非按安装量一刀切：**

| 类别 | 门槛 | 类型 |
|------|------|------|
| **High Threat** | **>= 25 安装**（25-999 需在 wp.org 仓库） | Arbitrary PHP File Upload or Read / Arbitrary PHP File Deletion / **Arbitrary Options Update** / Remote Code Execution / Authentication Bypass to Admin / Privilege Escalation to Admin（须未认证或低权限 Subscriber/Customer 可利用） |
| **Common & Dangerous** | **>= 500 安装** | Stored XSS / SQL Injection |
| **其他漏洞** | **>= 50,000 安装（Standard tier）** / 10,000（Resourceful）/ 500（1337） | Missing Authorization、信息泄露、CSRF 等一切未列入上面的类型 |

- Researcher tier（Standard/Resourceful/1337）决定"其他漏洞"的门槛；tier 与已提交/已接受报告挂钩
- premium 插件：按销售额 1:1 计安装量
- **推论（血泪）**：1k-10k 装插件上的 Missing Auth/信息泄露类 = 超范围白挖（sliced-invoices P2、ERE 邮件轰炸、hitpay 取消订单、FEA P0-1、restrict-user-access XML-RPC 全部不能交）→ **主攻 High Threat 类型 × 25-5000 装冷门小插件**

## 赏金决定因素（扣分/加分）
- **利用前提**（软件设置、特定服务器配置如 Nginx fix_pathinfo）→ 降 AC、降赏金
- 用户交互要求（点击链接等）→ 降
- **依赖另一个软件中的漏洞 → 赏金至少减半**（链最好全在同一插件内）
- CIA 影响面（删管理员=完整性+可用性全毁 → 高分）
- 自动化的容易度和可复现性

## 类型价值（同档位内权重）
| 类型 | 相对价值 |
|------|------|
| 未认证 RCE（上传/SQLi/反序列化） | 最高 |
| 未认证/低权限→管理员提权 | 高 |
| 任意 PHP 文件上传/删除/读取、Arbitrary Options Update | 高 |
| SQLi（>=500 装）、Stored XSS（>=500 装） | 中 |
| Missing Auth/信息泄露（需 50k 装） | 中低（且门槛高） |
| Basic Information Disclosure（邮箱/路径/phpinfo） | 低（$5-25） |
| 反射 XSS、CSRF | 低 |
| 重复/已公开 | $0 |

## 赏金金额怎么查
- **Wordfence 不公开单个漏洞的赏金金额**——没有"每个 CVE 多少钱"的表；审稿人内部评估，只在支付时告知数字
- 提交表单的 Vulnerability Type 下拉是固定选项（Remote Code Execution/Cross-Site Request Forgery/Stored XSS/Reflected XSS/SQL Injection/LFI-RFI/Arbitrary File Download-Read/Directory Traversal/PHP Object Injection/Arbitrary File Upload/**Missing Authorization**/Sensitive Information Disclosure/Arbitrary File Deletion/Arbitrary Options Update/Authentication Bypass to Admin/Privilege Escalation to Admin/Basic Information Disclosure/Arbitrary Shortcode Execution/Authentication Bypass to Non-Admin 等）——P2 类洞选 Missing Authorization，认证级别选 Unauthenticated
- **WordPress Core 不在 Wordfence 范围**——Core 漏洞由 WordPress 官方 HackerOne 计划处理（最低 $100，严重 RCE 最高 $12,500），Wordfence 只披露不付赏金
- **已披露 = 占坑**：Patchstack/WPScan/NVD 报过的洞不收重复 → 选目标后先查 NVD（scripts/wp_check_cve.py）；已披露但**不同根因**可在材料里主动声明区分（sliced-invoices P2 vs CVE-2025-31628 案例），降低拒收风险但不保证收录

## 1337 Researcher 身份
- 达到门槛（以官网为准：累计被接受提交数/赏金）后获得；1337 的"其他漏洞"门槛降到 500 装
- 获得后所有后续提交自动享有 bonus → **破零优先策略**：先交 in-scope 的小洞拿身份

## 月度冲刺 Bonus（每月独立）
- 1-10 个有效提交：5 个 $35，10 个 $75
- 11-30：20 个 $200，30 个 $300
- 31+：40 个 $600（需 30 in-scope + 10 High-Threat），50 个 $1000，60 个 $1200
- **每 CWE + 认证级别组合每年最多 5 个计入冲刺** → 提交要多样化类型，别全堆一个 CWE
- Out-of-Scope 不计入冲刺

## 实战策略（2026-08 修正版）
1. **先核实范围页再选目标**（curl 拦 → 浏览器/截图）；目标 = High Threat 类型 × 25-5000 装冷门小插件（文件上传/删除/管理器/备份/Options/角色/重置类）
2. 目标 = 默认配置 + 未认证 + High-Threat 类型（前端可触发的文件操作 > 锁 admin 的管理工具类）
3. 提交材料必须含靶场端到端复现证据（PoC 输出/响应/数据库对比）+ 用户亲手复现记录
4. 真实站点只浏览公开页面佐证场景，不触发漏洞（未授权利用违规）
