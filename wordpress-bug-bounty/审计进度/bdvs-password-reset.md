# bdvs-password-reset 审计 (2026-08-11)

## 基本信息
- 900装, 0.0.17 (2025-06 更新=432天), NVD 干净
- 功能: 前端密码重置 (REST API: reset-password / validate-code / set-password)
- 源码: D:\Documents\sources\Wordpress插件\_tmp_dl\bdvs-0.0.17\ (修复前 0.0.15 同目录)

## changelog 安全信号 (0.0.16/0.0.17 = 安全修复)
- 0.0.17: "switched to a cryptographically secure function to generate reset codes"
- 0.0.16: admin 角色默认不可重置 + 码长 4→8 + 字符集扩大
→ 修复前 = 4位弱随机码 = 任意用户密码重置(含admin), 补丁分析目标

## 0.0.17 防护链 (完整)
- 3 个 REST 路由全部 permission_callback=true (未认证), 但内部防护:
- 码生成 (functions.php:11-40): 默认 8 位 + random_int() + 大字符集(80字符) → 暴力不可行 ✓
- validate_code (class.user.php:106-176): 默认 3 次尝试限制 (bdpwr_max_attempts filter), 错误码计数+超限删码; validate-code 与 set-password 共享计数器 ✓
- set_new_password: validate_code 通过才 wp_set_password ✓
- 角色白名单 (send_reset_code:41-57): bdpwr_get_allowed_roles, admin 默认排除 ✓
- 目标用户: set-password/validate-code 用 email 参数指定, 需正确 code (发受害者邮箱) ✓

## 发现但不可利用
- ★ 过期检查逻辑写反 (class.user.php:166): `if ($now > $code_expiry) $expired = false` → 过期码永久有效
  → 但需要正确 code (攻击者无), 单点缺陷无攻击面 → 不构成洞
- 用户枚举: email_exists 区分响应 (低危超范围)

## 判定
- **主链安全, 放弃**。0.0.16/0.0.17 修复完整(生成/验证/尝试限制/角色白名单四层都补)
- 教训: "changelog 无 security 词" ≠ 没修过——bdvs 的安全修复没写 security 词(写的是 cryptographic/administrator); 筛选器产出要结合 changelog 语义判断
- 过期检查写反这类逻辑 bug 要记录 (可能其他版本/其他插件同款)
