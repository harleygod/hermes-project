---
name: penetration-code-audit
description: "渗透审计：架构推理→SAST辅助→多Agent并行→去重汇总。只出能拿权限/信息的漏洞，无修复建议。"
version: 3.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, penetration, code-audit, exploit, multi-agent, architecture-first]
---

# 渗透视角代码审计 v3

**核心原则：**
- 只出漏洞，不写修复建议
- 只关注能拿权限/信息的漏洞
- SAST 只是辅助工具，零命中≠系统安全
- 架构推理 → 假设驱动 → 多 Agent 并行验证

## 整体流程

```
Step 0: 项目识别 → 语言/框架/规模
Step 1: SAST 预扫 → 获取线索（可选，质量差不依赖）
Step 2: 架构推理 → 分析系统功能 → 假设漏洞面
Step 3: 主 Agent 分发 → 3 个子 Agent 并行，各有独立攻击面
Step 4: 汇总去重排序 → P0(无需认证) > P1(认证后) > P2(利用链)
Step 5: 输出报告 → 仅有漏洞描述 + 利用方式
```

---

## Step 0 — 项目识别

```bash
# 确认语言、框架、文件规模和目录结构
find . -type f \( -name "*.cs" -o -name "*.py" -o -name "*.java" -o -name "*.go" -o -name "*.js" -o -name "*.ts" -o -name "*.php" -o -name "*.rb" \) | head -50
```

**识别项目类型：**
- ASP.NET MVC → 检查 FilterConfig / [Authorize] / RouteConfig
- Spring Boot → 检查 SecurityConfig / @PreAuthorize / application.properties
- Django → 检查 settings.py / @login_required / MIDDLEWARE
- Express → 检查 middleware / passport / helmet
- 以此类推...

---

## Step 1 — SAST 预扫（辅助，非权威）

### ⚠️ SAST 定位声明

**SAST 只是一个便利工具，目的是避免盲目全量读文件。它不等于安全审计。**

- Semgrep 零命中 ≠ 系统安全（实测：对 C# ASP.NET MVC 项目 0 命中，但人工发现 10+ 严重漏洞）
- SAST 命中 ≠ 确认漏洞（可能是误报）
- SAST 的价值：帮你快速定位"可能有问题"的文件，减少初始阅读量
- SAST 的局限：看不懂架构、不懂业务逻辑、不懂漏洞组合

### 运行 Semgrep（如果可用）

```bash
pip install semgrep 2>&1 | tail -1
cd <target_dir>
# 优先用 auto + 语言专用规则
semgrep --config=auto --config=p/secrets --no-git-ignore --json -o /tmp/sast.json . 2>/tmp/sast_err.log
```

### 解析 SAST 结果

只提取 security 相关命中，丢弃 style/best-practice 类。
如果 SAST 零命中或无安装 → **跳过，直接进入 Step 2 架构推理**。

---

## Step 2 — 架构推理（核心步骤）

**这是最关键的一步。SAST 不告诉你系统哪里不安全，你的架构理解才告诉。**

### 2.1 回答这些问题

1. **鉴权模型是什么？**
   - 有没有全局鉴权过滤器（FilterConfig / middleware / guard）？
   - 哪些路由是公开的（Login/Register/API）？
   - 鉴权检查是一致的还是分散在各 Action 里的？

2. **权限模型是什么？**
   - 有哪些角色？每个角色能做什么？
   - 角色检查是集中式还是散落在各处？
   - 有没有资源所有权概念（用户只能操作自己的数据）？

3. **数据流是什么？**
   - 用户输入从哪里来（Form/URL/API/Header）？
   - 输入经过哪些处理（验证/编码/过滤）？
   - 数据最终到哪里（数据库/文件系统/网络/响应）？

4. **攻击面有哪些？**
   - 文件上传？→ 有没有校验？
   - 密码重置？→ 有没有验证码/Token/限速？
   - 用户注册？→ 有没有邮箱验证/默认角色？
   - API 接口？→ 有没有认证/限速？
   - 后台管理？→ 有没有独立鉴权？

### 2.2 关键文件定位

读这些文件来验证假设（每个文件只读关键部分，不要全读）：

| 项目类型 | 必读文件 |
|----------|----------|
| ASP.NET MVC | FilterConfig.cs, RouteConfig.cs, 所有 Controller |
| Spring Boot | SecurityConfig.java, application.properties, 所有 Controller |
| Django | settings.py, urls.py, views.py, middleware.py |
| Express | app.js, routes/, middleware/ |
| 通用 | 认证模块、密码处理、文件上传、数据库操作 |

### 2.3 形成假设

基于架构理解，列出 **"我想验证的漏洞假设"**：

```
假设1: FilterConfig 没有全局 [Authorize] → 全站无需登录
假设2: ForgotPassword 没有验证码 → 可爆破重置
假设3: 文件上传没有扩展名校验 → 可传 .aspx
假设4: ProjectController 的 id 参数没有所有权检查 → IDOR
...
```

---

## Step 3 — 多 Agent 并行验证

基于 Step 2 的假设，主 Agent 调用 `delegate_task` batch 模式，派出 3 个子 Agent。

**重要：每个子 Agent 的工作目录必须正确设置。**
主 Agent 先用 `find` 确认 `.cs` / `.py` / `.java` 文件的实际路径，然后把完整路径传给子 Agent。
避免子 Agent 因嵌套目录找不到文件。

### 上下文精简规则（所有子 Agent 必须遵守）

**传给子 Agent 的 context 只包含：**
- ✅ 项目语言 + 框架
- ✅ Step 2 中与该 Agent 领域相关的假设
- ✅ 需要验证的关键文件路径列表（绝对路径）
- ✅ SAST 中与该领域相关的命中（如果有）
- ❌ 不传：无关文件、SAST style 命中、项目背景、其他 Agent 的输出

**子 Agent 输出约束：**
- 统一格式：`FILE:LINE | TYPE | SEVERITY | 描述`
- 每条不超过 200 字符
- 最多输出 15 条
- 不确定的改成 `UNCERTAIN: 原因`
- 不在输出中写代码块、表格、长篇分析
- **如果找不到文件 → 先在项目根目录用 `find` 定位，不要反复尝试错误路径**

### Agent A — 鉴权绕过

```
目标：验证假设中关于鉴权缺失的部分

检查项：
1. 全局鉴权配置 → 读 FilterConfig / SecurityConfig / middleware
2. 每个 Controller/Route 的鉴权属性 → search [Authorize]/@PreAuthorize/@login_required
3. 公开可访问的敏感操作 → 读不依赖 Session/Token 的 Action 入口
4. Session/Token 检查的一致性 → 有哪些 Action 漏了检查

输出格式：
FILE:LINE | AUTH_BYPASS | P0/P1 | 访问路径 | 无需认证即可执行的操作
最多 15 条
```

### Agent B — 凭据 & 权限

```
目标：验证硬编码凭据 + IDOR + 密码缺陷的假设

检查项：
1. 硬编码凭据 → search password|secret|key|token|NetworkCredential|connectionString
2. IDOR → 找 int id 参数直接查库且无所有权验证的 Action
3. 默认密码 → 新建用户时是否设置固定密码
4. 密码存储 → 是否哈希？是否明文比对？
5. 密码重置 → Random 来源？Token 可预测？有限速？

输出格式：
FILE:LINE | CRED_LEAK/IDOR/PRIVESC | P0/P1 | 所需权限 | 描述
最多 15 条
```

### Agent C — 代码执行 & 利用链

```
目标：验证文件上传RCE + SQL注入 + 组合利用的假设

检查项：
1. 文件上传RCE → HttpPostedFileBase/file.SaveAs/Server.MapPath → 有无扩展名校验？
2. SQL注入 → 原生SqlCommand/ExecuteNonQuery + 字符串拼接？
3. 命令注入 → Process.Start/exec/os.system？
4. 反序列化 → BinaryFormatter/LosFormatter？
5. 利用链 → 结合 Agent A/B 的输出分析组合攻击路径

输出格式：
FILE:LINE | UPLOAD/SQLI/CMD/RCE | P1 | 前提条件 | 描述
利用链: 步骤1 → 步骤2 → 最终影响
最多 15 条
```

---

## Step 4 — 汇总去重排序

主 Agent 收到 3 份报告后：

1. **去重**：同一 FILE:LINE 的漏洞合并
2. **分级**：
   - P0 = 无需认证即可利用（最高优先级）
   - P1 = 需要认证但可越权/提权/执行代码
   - P2 = 多个 P0/P1 组合成攻击链
3. **去误报**：对子 Agent 的 `UNCERTAIN` 标记项手动验证
4. **补充利用链**：检查 P0 + P1 能否串成攻击路径

---

## Step 5 — 输出报告

```
渗透审计报告 — <项目名>

项目: <语言> <框架> | <文件数>文件 | <代码行数>行
SAST: <命中数>条 | 架构推理: <假设数>条假设

=== P0 无需认证 ===
FILE:LINE | 类型 | 利用方式简述

=== P1 认证后利用 ===
FILE:LINE | 类型 | 所需权限 | 利用方式简述

=== P2 利用链 ===
链1: 步骤1 → 步骤2 → 最终影响
```

**输出铁律：**
- 不写"修复建议"、"应该"、"推荐"、"最佳实践"
- 不写代码质量、性能、风格
- 每条漏洞必须有 FILE:LINE
- 每条约 1 行，最多 2 行
- 不确定的不写入报告（宁可漏报不误报）

---

## 审计视角范围

### 只关心（能拿权限/信息的）

| 优先级 | 类别 | 判定标准 |
|--------|------|----------|
| P0 | 无需认证 | 不登录就能访问敏感操作/数据/凭据 |
| P1 | IDOR | 登录后改 id 参数访问他人数据 |
| P1 | 权限提升 | 低权限做高权限操作 |
| P1 | 明文密码 | 泄露=全量账号沦陷 |
| P1 | 弱密码重置 | <100万种可能且可爆破 |
| P1 | 默认密码 | 固定字符串分配给新账户 |
| P1 | 文件上传RCE | 可上传可执行文件至 Web 路径 |
| P1 | SQL注入 | 原生 SQL 拼接用户输入 |
| P2 | 利用链 | ≥2 个 P0/P1 组合成攻击 |

### 不关心（跳过）

- XSS（除非能窃取 Session Token）
- CSRF（除非能组合成有意义的攻击链）
- 代码风格/命名/注释/性能
- 异常处理（除非泄露凭据/路径）
- 依赖版本（除非有公开 RCE CVE 且实际可达）
- 任何与"拿权限/拿信息"无关的问题
- 任何修复建议

---

## 子 Agent 上下文控制铁律

**context 字段最多 1500 字符，必须结构化：**

```
项目: <语言>/<框架> @ <绝对路径>
假设: <该 Agent 需要验证的假设列表>
文件: <绝对路径列表>
SAST: <相关命中，格式 file:line:type> (无则写 NONE)
输出: <输出格式说明>
```

**子 Agent 行为约束：**
- 找不到文件时用 `find` 定位，不要猜路径
- 读文件用 `read_file(offset, limit)`，不读全文件
- 不在输出中写代码块、表格
- 每条输出不超过 200 字符
- 最多 15 条，超出的只保留高严重度
- 不确定的写 `UNCERTAIN:` 不编造

---

## 对比 requesting-code-review 的决策表

| 场景 | 用 requesting-code-review | 用 penetration-code-audit(我们) |
|------|---------------------------|-------------------------------|
| 提交前审查改动 | ✅ 极优（diff 小，快） | ❌ 太重 |
| 全量审计反编译代码 | ❌ 需要 git | ✅ 天然支持 |
| 找架构级漏洞 | ❌ 只看改动行 | ✅ 架构推理 |
| 需要自动修复 | ✅ 有 Fix Agent | ❌ 刻意不做 |
| 纯渗透视角 | ❌ 含代码质量 | ✅ 只要权限/信息 |
| 关注上下文消耗 | ✅ diff 极小 | 🟡 中等（已优化） |
| 有 fail-closed 保护 | ✅ JSON schema | ❌ 待加入 |

---

## 陷阱

- **SAST 零命中别慌** → 进入架构推理，人工分析攻击面
- **子 Agent 找不到文件** → 主 Agent 先 `find` 确认路径再分发
- **context 超 1500 字符** → 裁剪假设列表，只保留高优先级
- **子 Agent 输出超 15 条** → 要求只保留高严重度
- **不确定的漏洞** → 标 UNCERTAIN，主 Agent 最后手动验证
- **反编译代码** → web.config / .cshtml 可能缺失，标注"未检查"
