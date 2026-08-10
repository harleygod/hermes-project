# Wordfence 提交材料骨架（WORDFENCE_SUBMISSION_<Name>_中文版.md）

> 顶部注明：按 Wordfence 提交表单章节结构编写；PoC 为浏览器控制台脚本可直接执行；静态审计/靶场验证状态

## SECTION 1 — Software Information
| 字段 | 值 |
|---|---|
| 软件类型 | WordPress 插件 |
| 软件名称 / Slug | 官方名 / `slug` |
| 软件地址 | https://wordpress.org/plugins/<slug>/ |
| 当前安装数 | N+（wordpress.org） |
| 最新版本 / 受影响版本 | X.Y.Z / X.Y.Z 及此前版本 |
| 修复版本 | 无（截至提交日） |

## SECTION 2 — Vulnerability Details
- 漏洞类型：CWE-xxx（主）+ CWE-xxx（附加）
- 标题：`<插件名> (by <作者>) <= <版本> - <认证级别><漏洞类型>`
- CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` + 说明（配置依赖需注明 AC 影响）
- 技术描述：攻击链编号步骤（1. 2. 3.），每步带 FILE:LINE 与代码片段
- 所需认证级别：未认证/订阅者/贡献者...
- 前置条件统一清单（表格：# | 前置条件 | 必需性 | 原因）——Wordfence 用这个评估 AC 减分
- 受影响文件与代码片段：每个关键环节一个代码块 + 注释标注缺陷行

## SECTION 3 — 逐步复现步骤
- 测试环境：WP 版本 + PHP + 服务器
- 请求序列：`POST /wp-admin/admin-ajax.php` + 参数 + 预期响应
- 验证：数据库/响应证据

## SECTION 4 — Proof of Concept（浏览器控制台）
```javascript
(async () => {
  const AJAX = '/wp-admin/admin-ajax.php';
  // 1. 提取页面 nonce（正则匹配 "nonce":"..." 或 _acf_nonce）
  // 2. ... 逐步请求
  // 全程 URLSearchParams 编码（+ 号正确编码为 %2B）
})();
```

## SECTION 5 — 影响
- 未认证攻击者可...（具体能力）
- 与既有漏洞关系（独立根因说明）
- 附加信息表：最低 WP 版本 / PHP 版本 / 是否已告知厂商（否，等待 Wordfence 流程）/ AI 辅助披露 ✅

## 要点
- 每条漏洞必须有 FILE:LINE
- 前置条件逐项标注"必需/可选"，评审按此评估 AC
- PoC 必须可复制粘贴运行，自动提取 nonce/ID，不依赖人工步骤
- 写操作类 PoC 若未在靶场执行，注明"源码静态推导，建议靶场实测"
