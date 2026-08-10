# 判定案例：积木报表表达式注入 (2026-07) —— 0day/nday 判定全过程

用户情报：`POST /prod-api/jmreport/save?previousPage=1&jmlink=sdada`，body 的 text 字段写
`concat("str")` 表达式注入内存马。问 0day 还是 nday。

## 判定结论：nday（根因已公开 + 官方已修复未发版），POC 是公开漏洞的变体利用

## 证据链（判定过程实录）
1. NVD/Advisory 无 CVE（未分配编号）→ 走 GitHub issues 检索
2. GitHub issues 命中官方 repo 安全 issue：
   - jeecgboot/jimureport#4733（2026-07-11 公开，2026-07-24 closed）
     标题"JimuReport使用的FreeMarker的沙箱可被绕过造成远程代码执行"
     根因：FreeMarkerUtils 暴露 FreemarkerMethod.compute() → 用户可控表达式直接
     AviatorEvaluator.execute() → Aviator 任意表达式 → ReflectUtils.defineClass() 加载字节码 = RCE
     受影响端点：/jmreport/queryFieldBySql、/jmreport/loadTableData 等（"等"含 save 类）
     作者 zhangdaiscott 评论："已修复，下个版本发布"
   - jeecgboot/jimureport#4736（2026-06-30）：show 接口 customTableTitleSorts[].field ORDER BY SQL 注入（需登录，另一个洞）
3. releases API 双确认：最新 release 仍是 2026-06-26 的 v2.5.0 → 修复在 main 分支但未发版
   → 存量 2.5.0 及以下全部仍受影响，窗口期仍在
4. POC 特征拆解：
   - /prod-api/ = JeecgBoot 前端网关前缀（确认集成版）
   - jmlink=sdada、previousPage=1 = 非官方参数，POC 作者占位/混淆值
   - concat("str") = Aviator 表达式字符串拼接函数，用于拼 "java.lang.Runtime" 类关键字绕过过滤
   - 内存马 = defineClass 链落地，与 issue 描述一致

## 可复用要点
- 官方 repo 的 issue tracker 是"未分配 CVE 的已公开漏洞"第一现场；issues search 不需要认证
- 维护者回复时间 = 官方知晓时间；issue closed = 修复动作完成（但要看 releases 确认发版）
- 同根因不同触发点（queryFieldBySql → save）是"变体"，不是"新漏洞"
- 判定后话术：能用但别捂，一旦进 nuclei/afrog 就烂大街；别当 0day 卖/吹
