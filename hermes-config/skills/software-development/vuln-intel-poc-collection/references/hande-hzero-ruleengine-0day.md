# 汉得 HZERO rule-engine Groovy RCE 0day 评估案例（2026-08，进行中）

## 漏洞形态
- 入口: `POST /hpfm/v1/rule-engine/run-script`，body: `{"script":"<Groovy>","params":{}}`
- 载荷模式: Groovy 直接执行(无沙箱) → 反射 `sun.misc.Unsafe` → Base64 解码类字节 → `unsafe.defineClass(null,b,0,len,null,null)` → `newInstance()` → 内存马
- 核心洞 = 规则引擎**任意 Groovy 执行**；Unsafe 只是无文件内存马加载的运输方式（匿名类，绕开类加载器）
- 对比: `ClassLoader.defineClass`(反射) vs `Unsafe.defineClass` —— 后者绕开类加载器命名空间，JDK9+ 仍可用

## 开源版对照（决定性证据）
- 汉得 HZERO 开源: github.com/open-hand（org: open-hand；hzero-platform 是平台服务，路由前缀 hpfm）
- 开源版**没有** `/rule-engine/run-script`；等价接口: `POST /v1/{organizationId}/rule-scripts/test`
  - DTO `RuleScriptTestDTO`: tenantId + scriptCode + params（**无裸 script 字段**）——按 scriptCode 查库里的已存脚本（hpfm_rule_script 表）再执行
  - 控制器注解 `@Permission(level = ResourceLevel.ORGANIZATION)` = **需登录**
  - 结论: 裸 script 的 run-script 是**商业版/私有部署独有接口**（开源版是阉割版）
- git 历史被压成 2 提交（[AUTO] commit project），无法考古旧版

## 0day 判定要点
- 公开渠道零记录（CSDN/GitHub issues/Google），但"商业版独有接口"≠"0day"——纯度和是否已被人打过无法从公开渠道判断
- **决定性未知项: 认证** —— 未授权=前台 RCE（顶级）；需登录=后台 RCE（价值大减，开源版同类功能本就要登录）
- 平台级: hpfm 是 HZERO 平台服务，汉得系产品（SSO/SRM/协同等）都基于它 → 一个洞打整个生态（前提接口公网暴露）
- 测绘: FOFA `body="/hpfm/"`（汉得客户多为中大型制造/集团企业）

## HZERO 构件获取（坑）
- 不在 Maven Central；私有 nexus: `nexus.saas.hand-china.com/repository/maven-public/`（browse UI 是 HTML、REST search 未认证返回 0、直接路径 404——仓库可达但抓构件难）
- 开源源码: `git clone -c http.proxy=<proxy> --depth 1 https://github.com/open-hand/hzero-platform.git`（git 协议不受 GitHub API 限流）

## 认证实测（2026-08 定级: 后台 RCE）
- 实测目标 eam1.yimidida.com: 无 token 发无害脚本 `{"script":"'probe'","params":{}}` →
  `HTTP 401` + `<oauth><status>PERMISSION_ACCESS_TOKEN_EXPIRED</status><code>error.permission.accessTokenExpired</code>`
  = HZERO 权限过滤器拦截（该 `<oauth>` 401 包本身就是最强指纹: 无 token 探 run-script, 401+oauth 包=接口活+需登录）
- 401 而非 404 → 路由存在, 有合法 Bearer token 即可打; 价值=后台 RCE, 提级路径=汉得系默认口令/其他入口拿账号
- 无害脚本探测方法: `{"script":"'probe'","params":{}}` — Groovy 字符串字面量 eval 零副作用, 可安全用于全资产认证状态筛查
- 武器化完成: `武器库\汉得HZERO-rule-engine-GroovyRCE\`（0day.md + scan.py 只读三态判定 + exploit.py --check/--send 门控 + payload/ 外置内存马类占位, 已 mock 验证）

## 待办（等用户反馈）
- 真实内存马类 base64 → payload/hzero_memshell.b64（发前必须本地反编译确认类行为）
- 汉得系默认口令核查（提级到前台路径）
- 影响范围测绘（FOFA body="/hpfm/" 捞资产跑 scan.py）
