# 通达OA appbuilder hrmedals/setlaunch SQL注入 1day 案例（2026-08-14）

收录目录：`D:\Pentest\攻防\武器库\通达OA-appbuilder-hrmedals-setlaunch-SQL注入\`
（0day.md + td_oa_setlaunch_sqli.py 探测 POC + targets.txt + requirements.txt）

## 漏洞形态

```
GET /general/appbuilder/web/hr/hrmedals/setlaunch?id=0;【SQL】&is_launch=1&appanonymousclient=1
```

- id = 勋章 ID（注入点）；is_launch = 1启用/0停用；appanonymousclient = 疑似 app 端免登录开关（更新版本参数）
- 功能：勋章管理 - 启用/停用勋章
- 前端实锤（泄漏源码 `general/hr/medals/manage/list.chunk.js`）：
  `$.ajax({type:"get", url:"/general/appbuilder/web/hr/hrmedals/setlaunch", data:{id:e, is_launch:1}})`

## 公开性判定依据（三关键词全零命中）

- GitHub issues/repos/commits 搜 setlaunch / hrmedals / appanonymousclient → 零命中
- nuclei-templates 官方库 → 无 tongda 模板
- DDG/搜狗/必应/CSDN 搜接口名+系统名 → 零命中
- 2020-08 农夫安全《全网首发|通达OA多枚0day漏洞分享》公开清单（第一波）：
  1. POST `/general/appbuilder/web/calendar/calendarlist/getcallist`（begin_date 注入，需登录）
  2. GET `/general/email/sentbox/get_index_data.php?orderby=`（需登录）
  3. GET `/general/email/inbox/get_index_data.php?orderby=`（需登录）
  4. GET `/general/appbuilder/web/report/repdetail/edit?id=`（需登录）
  5. 未授权访问会议信息
- 结论：**hrmedals/setlaunch 不在任何公开清单** = appbuilder 注入家族中未公开的具体接口点 → 收录。
  注意 2020 那批都标"需登录"，若 appanonymousclient=1 免登录成立则本点价值更高（未授权注入）。

## 泄漏源码验证（本案例实证路径）

- 仓库：`sever686/-OAv11`（通达OA v11 完整源码，155MB，`git clone -c http.proxy=... --depth 1`）
- 模块：`general/appbuilder/modules/hr/controllers/HrmedalsController.php`（**被 zend 加密破坏**，
  解密残留 `class not found` 是坏文件）+ `models/HrMedal.php`（SQL 直拼实锤：`LIKE '%$keyword%'`、
  `USER_PRIV IN ($priv_id)`、`UID IN ($uids)`、`medal_id in ($medalstr)`）
- 风格结论：该模块参数不过滤直拼 SQL，setlaunch 的 id 大概率同样处理

## ⚠️ 关键适配坑：appbuilder 入口 base64 参数编码

v11 `general/appbuilder/web/index.php` 会把所有 GET/POST 参数值
`$_GET[$k] = base64_encode($v)` 后再进 Yii 框架！

- 若目标版本保留该逻辑 → 注入 payload 需 base64 编码适配（POC 默认明文形态，无响应时试 base64）
- 这也解释了为什么 2020 公开的注入点标注"需登录"（入口 base64 可能挡了部分裸注入）

## POC 设计要点（td_oa_setlaunch_sqli.py）

- 时间型盲注（SLEEP），默认零副作用；`--sleep-test` 显式开启
- 支持 `--cookie`（登录态）与 `--anonymous`（追加 appanonymousclient=1）双模式
- `--payload` 自定义注入形态（`{sleep}` 占位）；`--exploit` 仅打印利用链提示
- mock 验证 8/8 通过（漏洞判定/原样回显不误报/401短路/死连短路/匿名模式/自定义payload）

## 复用价值

- 通达OA 2万+ 正式用户，appbuilder 通用模块 → 目标存量巨大
- 同类打法可迁移：通达 appbuilder 其他模块（calendar/report 等）若新版未整体加固，同为注入面
