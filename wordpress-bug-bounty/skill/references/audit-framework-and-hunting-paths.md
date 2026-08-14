# WP 插件审计框架：10 类成因 × 8 条动作 × WP 载体 + 六路打法（2026-08-14）

> 使用前提：一切围绕 Wordfence 可交成果（装量门槛→类型价值→成因打法→终审），本文件只是第三层"怎么挖"的工具库。

## 一、缺陷成因 10 类（漏洞为什么存在）

1. **输入验证/数据流注入**：SQLi / XSS / 命令注入 / 文件包含 / XXE / SSTI / 反序列化
2. **认证缺陷**：登录绕过 / 弱凭证 / 密码重置逻辑 / 会话固定劫持 / 令牌可预测可重放
3. **授权缺陷**：Missing Auth / IDOR / 角色错配 / nonce 语义错用 / 检查对象≠操作对象
4. **加密与随机性**：弱随机(rand/mt_rand) / 硬编码密钥 / IV 重用 / 可逆加密存密码 / padding oracle
5. **逻辑与状态机**：条件反向 / 边界漏分支 / 多步流程中间态可跳 / 状态非法迁移 / 重复提交
6. **竞态与生命周期**：TOCTOU / 并发双执行 / 临时文件暴露窗口 / cron 时序 / 资源未释放
7. **信任边界与配置**：配置来源可控 / 危险配置键无闸门 / 默认配置不安全 ← ChainQ 归此类
8. **暴露与信息泄露**：详细错误 / debug / 备份文件 / .git / 日志含敏感 / 版本指纹
9. **集成与协议**：回调不验签 / SSRF / OAuth 状态错乱 / 编码解析不一致(双重解码/宽字节)
10. **供应链**：捆绑库 CVE / 依赖过旧 / SDK 后门

## 二、发现动作 8 条（怎么找到，与成因对应）

1. 正向数据流追踪(taint) → 类1
2. 危险终点倒推(写/删/执行/SQL) → 类1/3
3. 入口×权限对照表(端点 vs current_user_can/nonce) → 类3
4. 配置/状态来源推演("配置谁给的") → 类5/7 ← ChainQ 核心动作
5. 开发者意图对抗("这步本该验证什么") → 类2/5
6. 补丁/版本差分(修复前vs后找漏修/绕过) → 全类
7. 时间与并发推演(检查与使用之间窗口) → 类6
8. 平台机制枚举(WP 特有面) → 类2/3/7/8/9

## 三、WP 平台载体（漏洞长在哪）

- 认证面: wp-login / 密码重置 / wp_authenticate / cookie / remember me
- 授权面: current_user_can / capability / nonce(防CSRF不防授权) / 角色
- 写入面: acf_update_metadata / update_user_meta / update_option(无白名单)
- 数据面: post type 公开性 / meta 直写 / REST 权限回调 / XML-RPC / feed
- 执行面: shortcode / wp_ajax_nopriv / admin_init / cron / hooks
- 集成面: webhook 回调 / 出站请求 / 第三方 SDK / 模板渲染
- 暴露面: debug.log / 备份 / 错误详情 / 源码注释 / 版本指纹

## 四、赏金中心四层（使用顺序）

装量档位 → 类型价值(金/银/铜) → 成因×动作 → out-of-scope 终审
（完整定义见 SKILL.md "赏金中心框架" 一节）

## 五、六路并行打法（2026-08-14，按优先级）

- **A. ChainQ 复制（金矿，已验证可产出 9.8 级）**：表单引擎筛选器
  (25-50k装 × 表单/CRUD/前端提交关键词 × 150天+未更)
  → 配置来源追踪五步：change_form 类端点 → 配置谁给的 → 危险配置键枚举
    (save_to_*/new_user_role/login_user/字段name) → 逐分支查闸门 → 串链
  → 产出: 提权到Admin / 认证绕过到Admin
- **B. 远古文件操作（金矿，RCE 高发）**：1k-5k装 × 文件操作 × 3-5年未更
  → 自写文件逻辑(非 WP 标准函数: move_uploaded_file/rename/file_put_contents/readfile)
    + TOCTOU + 路径来源 + 文件名可枚举性
  → 产出: 任意文件上传→RCE / 任意文件读取删除
- **C. 补丁分析清候选（已清完，2026-08-14 池退役）**：候选池剩 dk-pdf + attachments 均已粗扫放弃
  （dk-pdf: 单篇权限分级完整/archive硬编码publish/模板名硬编码/短代码全sanitize → 三面全硬；
   attachments: 纯后台meta box 无nopriv+save三件套齐全 → 攻击面≈0）
  → 补丁分析池（changelog安全词筛"修过洞"插件）10+连审0可交，正式退役；
     剩余精力转 A(表单引擎) + B(远古文件操作) 两个金矿池
- **D. SQLi/XSS 面（银矿，量大）**：10k-50k 装大插件
  → semgrep 3 规则(scripts/wp_rules_sqli_xss.yaml) + 数据流追踪
  → 规律: 10k+ 池机械层基本干净，逻辑层才是高发区
- **E. 认证面（金矿）**：密码重置/登录/会员/权限管理类插件
  → 重置码随机性+令牌空间+尝试限制+角色白名单+绕过面(REST/XML-RPC/cron)
- **F. 0day 竞速（破零练手）**：wordpress.org 新上架插件(1-2周)
  → 快速粗扫（新插件幼稚漏洞多、无人抢），$5-25 档

## 六、候选池可交性审计三关（投入前必做）

装量档位 × 类型映射金矿面 × 维护年龄 —— 三关不过直接划掉。
- 补丁分析池 = 银矿/铜矿池，金矿在"配置驱动表单引擎 + 远古文件操作"两个类别
- 2026-08-14 实战：候选池剩余 5 个仅 dk-pdf、attachments 通过；pdf-forms-for-CF7(130天活跃)、
  upload-larger-plugins(admin功能攻击面极小)、canonical-attachments(300装<500银矿门槛) 划掉
