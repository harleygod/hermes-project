# JeeSite 4.x / 5.x 默认密钥与账号速查（源码确认，2026-08）

来源：clone thinkgem/jeesite4 源码核对，非记忆。

## 1. 初始登录账号（README 明确）
```
管理员: system / admin
```
（注意不是 admin/admin，社区常见误记）

## 2. AES 默认密钥（AesUtils.java 硬编码）
```
9f58a20946b47e190003ec716c1c457d
```
- hex 编码，128bit/16 字节，`AES/CBC/PKCS5Padding`
- 读取逻辑：`PropertiesUtils.getProperty("encrypt.defaultKey", "<上面默认值>")` —— 配置文件可覆盖
- 用途：通用 AES 加解密（参数加密、ID 加密、cookie 等）
- 渗透用法：目标未改默认 key 时，抓密文可本地解密；也可自加密伪造参数（需先摸清明文格式）

## 3. Shiro rememberMe（反序列化线）
- 新版 4.x：`ShiroAutoConfiguration.webSecurityManager` 中
  `bean.setRememberMeManager(null)` 被注释掉 = **默认关闭 RememberMe**，无此攻击面
- 老版本（3.x / 早期 4.x）：CVE-2016-4437 Shiro 默认 AES key
  `kPH+bIxk5D2deZiIxcaaaA==` 反序列化 RCE（Gitee 官方 issue I3UD3K / I3UQBM 承认
  4.x/5.x 早期存在 "Shiro AES Key 可枚举" 问题）

## 验证方法（只读无害）
抓登录/接口的加密字段，本地用 9f58a20946b47e190003ec716c1c457d 解（ECB/CBC 都试），
能解出明文（用户ID/时间戳）→ 未改默认 key。system/admin 登录尝试属登录行为，需用户确认。

## 报告里出现的其他"默认密钥"判定（2026-08 调查）

某报告写"默认密钥 = thinkgemsystem0804 的 MD5"。调查结论：
- `thinkgemsystem0804` 的 MD5 = `cc395706e6b0817fb564981b3c0a98c8`
- 该字符串 GitHub commits/issues、DDG、Gitee **全网零命中** → 不是公开通用默认值；
  属报告作者从定制版本/0day 圈子/付费情报渠道看到的东西（"thinkgem" 前缀暗示与
  JeeSite 作者相关，可能是个别发行版/私有配置）
- 判据：源码硬编码默认只有 `9f58a20946b47e190003ec716c1c457d`；配置文件键
  `encrypt.defaultKey` 可覆盖成任意值——报告值 ≠ 通用默认，验证需拿目标密文实测
- 附带发现：官方 docker-compose-mysql.yml 的 MySQL root 密码是 `123456`
  （healthcheck 的 `mysqladmin ping -p123456` 暴露，YAML 里 MYSQL_ROOT_PASSWORD 写 ***）
