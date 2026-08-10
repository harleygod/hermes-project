---
name: wordpress-bug-bounty
description: "WordPress 插件漏洞挖掘与 Wordfence 赏金提交:目标选择→审计→靶场复现→提交。"
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [wordpress, bug-bounty, wordfence, pentest, plugin-audit, exploit]
---

# WordPress 插件漏洞挖掘 + Wordfence Bug Bounty

## 触发条件
- 审计 WordPress 插件寻找可提交赏金的漏洞
- 需要理解 Wordfence 收录范围/赏金规则/目标选择
- 搭建 WordPress 本地靶场复现插件漏洞

## 用户核心偏好(铁律)
1. **提交前必须靶场复现**——静态分析结论不算数,Wordfence 要求可复现。只有端到端跑通(含真实响应/DB 证据)才写提交材料。
2. **目标 = 能拿赏金的洞**:High-Threat 类型(RCE/任意文件上传·删除·读取、SQLi、提权、认证绕过、高敏泄露、PHP 对象注入)+ 大安装量 + 零配置依赖 + 未认证。
3. 低值类型(XSS/CSRF/Basic Info Disclosure)可用来破零,但不当主攻。
4. 破零优先:拿到 1337 Wordfence Vulnerability Researcher 身份后,所有后续提交有 bonus;同时月度冲刺奖金按提交量阶梯发放。

## 目标选择策略
- 热门大插件(1M+)被职业研究者盯死,新手别碰
- **甜区:安装量 1k-10k、上架几个月、没人关注的插件**——in-scope + 真实影响面 + 赏金 $100-500
- 新插件(0 安装)也 in-scope(只要在 wordpress.org 仓库),赏金最低档 $5-25,适合破零练手
- 高攻击面类型:文件管理器/备份迁移/导入导出/表单/上传类插件(文件操作 = RCE 高发)
- 用 `curl --socks5-hostname <proxy> https://wordpress.org/plugins/browse/new/` 拉新插件列表;API query_plugins browse=new 常超时,HTML 页更稳

## WordPress 插件审计特有模式
1. **匿名 nonce 全站共享**:uid 0 + 空 session token 的 `wp_create_nonce` 输出全站一致 → 任何 `wp_ajax_nopriv_` + nonce 校验的端点对未认证攻击者实际开放。从渲染插件脚本的公开页面 HTML 提取(`"nonce":"..."` 或 `_acf_nonce` 隐藏域)。
2. **攻击面清单**:`grep -rn "wp_ajax_nopriv_"`(未认证端点)、`wp_ajax_`(登录但可能缺能力检查)、表单动作类、文件上传处理、提交记录渲染、GET 参数直通渲染、REST 端点、短代码。
3. **修复模式识别**:厂商常加"渲染阶段权限检查把对象 ID 置 'none'"来拦越权(如 conditions_logic)。找作者/属主校验的误判:`$user->ID(未认证=0) == post_author(0)` 通过校验 → post_author=0 的文章(导入/迁移/CLI 创建)可被未认证操作。
4. **令牌铸造端点(如 change_form)是公共攻击面**:服务端为攻击者指定的任意对象 ID 铸造加密令牌;令牌内容受渲染时权限检查影响(被拦则令牌里 ID 变 'none')。
5. **do_action 订阅者拦截(静态分析最大盲区)**:同 priority 订阅者按注册顺序执行,先注册的无条件 `die()` 会拦截后注册者 → 静态确认的端点路径可能实际不可达。**必须动态验证**。
6. **GET 参数直通渲染**:`handle_get_params` 类函数常把 `?xxx=<ID>` 直接映射到数据渲染(无 nonce 纯 GET 泄露)——审计时重点看 render 入口的 $_GET 处理。

## 流程
```
Step 1: 目标选择 → wordpress.org 拉列表,选 1k-10k 安装冷门插件
Step 2: 审计 → 架构推理(攻击面清单) + 子 Agent 并行(注意:子 Agent 输出必须动态复核)
Step 3: 靶场复现 → 见 references/phpstudy-windows-target.md
Step 4: 提交材料 → Software Info / Vulnerability Details(CWE+CVSS+代码位置) / 复现步骤 / PoC / 影响
        材料标注"已在靶场端到端复现" + 真实响应输出
```

## 陷阱
- **静态分析确认的"可利用"可能被 do_action 订阅者拦截**——必须跑通验证(实测:add_form 端点被 related-items 的 render_form 无条件 die() 抢先,submissions 渲染路径不可达;真实利用入口是 GET ?submission=<ID>)
- 子 Agent 的漏洞判定(尤其"可复现")只能当线索,主 Agent 必须靶场复核
- 厂商"修复"常不完整:检查同一模式的变体(post 修了 user 没修、或 author 校验误判)
- 提交前核对漏洞是否已被别人披露(Wordfence 查重严格,重复 = $0)

## 支持文件
- references/wordfence-bounty-rules.md — 收录范围/赏金档位/扣钱因素/1337 身份/月度冲刺
- references/phpstudy-windows-target.md — phpStudy Windows 靶场搭建全套坑(端口/PHP 版本/进程杀/插件激活/表单结构)
