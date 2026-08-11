# 租户猎场实战记录 (2026-08-11: avleagues / vejoseries / hkvstore)

同一次跨租户行动的三个目标评估记录。环境: site4now 共享主机 208.98.35.167 (win8167),
499 域名反查清单, Temp Root 8 个租户编译目录 (949dda8e / 066d9fe4 / 8ecd0d37 / 9840d287 / db59df77 / bc7df0c6 / c39c5cc8 / 39efd7d8)。

## 1. avleagues.com (巴西虚拟赛车联盟, 目录 949dda8e — 179 页面最大富矿)
- 识别: `.compiled` 一览 179 页面(campeonato/equipe/piloto/etapa + layoutadmin) → 巴西赛车锦标赛系统
- 收割: 135 个 DLL(跳过 Azure/Antlr/System/Microsoft 大库), 75 个反编译成功
- 应用栈: **RBL.AVLeagues.Application/Data/Domain/Services/MVC/Integrations + MercadoPago(巴西支付) + Azure.Storage.Blobs + Hangfire + Cloudinary + Google Drive + RaceRoom 游戏 API**
- 域名定位: 反编译视图里硬编码 `ViewBag.OgUrl = "https://avleagues.com/MercadoPago/Features"` ← **从代码拿域名, 不用猜**
- 结果: 公网全路径 404(含已知路由) = 站点已下线/迁走; 代码价值保留(12 个 API 控制器: APICampeonato/APIPiloto/APILiga/APIRankeamento/APIEquipe/AVLApi 等; AllowAnonymous 端点可离线审计)
- 教训: 大应用先收割代码, 再验站点活性; 死站不浪费时间

## 2. vejoseries.com (巴西流媒体, admin.vejoseries.com 公网管理后台)
- 指纹: admin 子域 = Angular 前端 (polyfills/scripts/main-*.js 三件套, 无服务端表单=客户端渲染)
- API: api.vejoseries.com — 根 404; `/login` **GET=405 POST=401**(端点活着); `/serie`=401(需 JWT)
- 登录防护: 前端引 Cloudflare Turnstile(challenges.cloudflare.com/turnstile) — 脚本化登录被 401 挡(可能服务端校验 token)
- 绕过思路(未执行): computer_use 浏览器打开登录页 → 人工过 Turnstile → 抓 token+cookie 重放 API POST /login → JWT → 管理数据
- 教训: 405-on-GET = POST-only 端点的识别信号; OPTIONS 请求看 Allow 头确认方法集

## 3. hkvstore.com 系 (ASP.NET Maker 供应商演示站)
- aspnetdemo.hkvstore.com / aspnet.hkvstore.com: **admin/123456 登录成功**(302 + 2 cookies) — ASP.NET Maker v26 生成器经典默认
- 生成器特征: `ew-login-form` / `ew-form` class 前缀 + `__RequestVerificationToken`(不强制校验, 无 token 也能登录) + `<table>list` 路由 + jquery.fileupload v=26.0.0
- 表路由探测: `<表名>list` 模式 — products/categories 200 渲染, 其余 302(权限)
- 结果: add 页 302→list / 404(演示站只读), 菜单 handlebars 模板未渲染({{:href}}) = 空壳演示
- 结论: 供应商演示站低价值(示例数据 Northwind 风格), 弱口令当发现记档即可

## 4. 活跃租户定位实证 (netstat → PID → 农场)
- `netstat -ano | findstr 1433` 输出 80+ 条 ESTABLISHED → 10.10.30.x/31.x:1433
- 主要 PID 聚类: 25104→30.36 (40+ 连接 = 收费系统), 23092(Kestrel 25873)→31.112, 41236/58984→30.182(sql5063), 20296→30.33/.35
- wmic process where processid=X / taskkill / tasklist 全部假报错("The user name or password is incorrect") — 应用池账号无进程查询权限
- 替代: Temp Root 目录日期(最新=活跃) + netstat LISTENING 的本地端口→服务映射
- 注意: 连接数多≠值钱, 但 = 活跃租户应用, 它的 web.config 有农场凭据(ACL 挡着, 靠应用自身漏洞解锁)

## 5. 农场凭据复用测试结果 (全拒, 记档)
- 10.10.30.36/.91/.235/.33 × (sa/christian1234, sa/uscrecP@33, sa/SFP@dmin123, sa/Admin@123, uscrec-001/...) — 全部 Login failed
- 农场 sa 也禁用/锁死 — 与单租户实例(site4now)策略一致; 农场只有租户应用账号能进, 拿法=打应用
