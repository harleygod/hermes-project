# 补丁分析候选池 + 实战记录(2026-08)

## changelog 安全词筛选法(免费攻击面地图,不需要 Wordfence key)

```python
# 核心:wp.org API 的 sections.changelog 含作者修复记录
# 1. query_plugins 搜文件操作类关键词,过滤 25-10000 装
# 2. plugin_information 拿 sections.changelog(注意:是 sections 下的 key,不是顶层 changelog!)
# 3. 去 HTML 后 grep 安全词:security/vulnerability/xss/sql injection/csrf/nonce/arbitrary/bypass/sanitize/escape/cross-site/injection/auth
# 4. 过滤 120+ 天未更新
# 5. 下载修复前/后两版 zip → diff -r → 定位修复点 → 找漏修
```

关键 API 结构:`plugin_information` 响应里 `sections.changelog`(HTML 字符串),不是 `changelog` key。

## NVD API 的坑(2026-08 实测)

- `pubStartDate/pubEndDate` 日期参数:URL 编码不当返回 404(冒号要 %3A 编码;有时即便编码正确也失败)——NVD 限流/版本问题,不稳定
- `keywordSearch` 按相关性排序:2008-2022 的旧 CVE 占前排,查"最近的文件类漏洞"效率极低
- 结论:补丁分析数据源用 wp.org changelog,不用 NVD 日期查询

## 3 连审结论(2026-08-10 第一轮)

| 插件 | 版本 diff | 修复内容 | 漏修? | 结论 |
|------|-----------|---------|-------|------|
| download-after-email | 2.1.9→2.1.10(7000装) | dae_is_file_allowed_for_download 白名单(媒体库附件+被引用) | 无 | 修复完整放弃 |
| simple-membership-wp-user-import | 1.9.1→1.9.2(4000装) | add_all 加 check_admin_referer | add_selective 分支无 nonce(仅 CSRF+manage_options 页,低危) | 不交 |
| moving-media-library | 1.23→1.24(2000装) | 仅 ABSPATH 检查 | 无(导入上传防护完整) | 放弃 |

## 4 连审结论(2026-08-10 第二轮)

| 插件 | 版本 diff | 修复内容 | 发现 | 结论 |
|------|-----------|---------|------|------|
| gallery-lightbox-slider | 1.0.0.39→1.0.0.41→latest(10000装) | 两次 XSS 修复(1.0.0.41 前端 escapeHtml;1.0.0.43 重构式全量 esc_html/esc_url + glg_ajax_save_settings 加 manage_options) | 无(残留:free_plugins 远程 feed 未转义=供应链不交) | 放弃(重构式完整修复难挖) |
| bulk-media-register | 1.39→1.40(8000装) | 排序加 nonce + 文件操作换 WP_Filesystem | 无 | 放弃(upload_files 权限基线超范围) |
| wp-attachments | 5.2.1→5.3.4(3000装) | meta-box 权限 edit_posts→upload_files 收紧 | 5.3.4 引入 noheader nonce 绕过(仅 unattach 低危) | 放弃 |
| gd-bbpress-attachments | 4.7.2→4.7.3→4.9.4(6000装) | 4.7.3 修反射 XSS(仅 front.php 输出转义) | **★ 订阅者任意附件删除 IDOR** | **保留候选待靶场** |

### gd-bbpress-attachments IDOR 细节(候选洞)
- 位置: code/class.php:105 delete_attachments (init 钩子, 任意请求触发)
- 链: `?d4pbbaction=delete&att_id=<任意附件>&bbp_id=<自己帖子>&_wpnonce=<自己的nonce>` → wp_delete_attachment(任意附件) 物理删除
- 缺陷: 权限只看 get_post($bbp_id)->post_author == $user_ID, **att_id 无归属校验**
- nonce: 固定 action 'd4p-bbpress-attachments'(登录用户自己的即有效); 可达性 = 前端按钮渲染条件(作者 allow 时才输出)
- 前置: delete_visible_to_author = 'delete'/'both'(默认 'no', code/defaults.php:39) → 配置依赖
- 查重: NVD 无已披露 CVE ✓; 4.7.2→4.9.4 逻辑未变(只加 absint/sanitize) 多版本存活
- 角色判定严格(administrator/bbp_moderator 硬编码 in_array) 无绕过; 上传面 wp_handle_upload 标准函数

## 5-6 连审结论(2026-08-10 第三轮)

| 插件 | 版本 diff | 修复内容 | 发现 | 结论 |
|------|-----------|---------|------|------|
| pdf-viewer-block | 1.0→1.1(10000装) | 前端 JS encodeURI(href)(DOM XSS 属性注入修复) | 无(修复有效单点, 触发面=作者级写 post_content 超范围) | 放弃 |
| media-library-helper | 1.2.0→1.3.2(10000装) | image_metadata nonce 硬检查→OR 逻辑(admin 免检) | **★ OR 逻辑 nonce 模式**: admin CSRF 改附件元数据(低危) | 放弃(影响低不交) |
| download-theme | 1.0.9→1.1.2(4000装) | dtwap_download 加 nonce(之前无) | 无(四层防护: nonce+switch_themes+wp_get_themes 白名单+realpath) | 放弃 |

### 新增判定法(5-6 连审沉淀, 见 SKILL.md 对应段落)
- **OR 逻辑 nonce 模式**: `if (!current_user_can('X') && !wp_verify_nonce(...))` = X 权限用户免 nonce → 查该权限用户的 CSRF 后果(元数据/解除关联=低危; 选项写/文件操作/权限变更=硬洞)
- **Block 插件攻击面**: PHP 端极小, 攻击面在 JS save/render + post_content 可写性(作者级写=超范围)
- **SVN 单文件拉取**是 zip 下载失败时的替代方案(block 插件核心 3-5 文件即可 diff)

## 待审候选池(2026-08-10 更新,已审 10 个,剩余 5 个)

### 次优先(最优先 4 个已审完)
- ~~pdf-viewer-block~~(10000装) [审] XSS 修复有效+作者级超范围, 见 D:\Pentest\审计进度\pdf-viewer-block.md
- ~~media-library-helper~~(10000装) [审] OR 逻辑 nonce=admin CSRF 低危, 见 D:\Pentest\审计进度\media-library-helper.md
- ~~download-theme~~(4000装, 474天, 修 security) [审] 四层防护完整放弃, 见 D:\Pentest\审计进度\download-theme.md
- dk-pdf(3000装, 207天, 修 SSRF=同代码区可能有文件读取)

### 一般
- pdf-forms-for-contact-form-7(3000装, 130天, escape 修复)
- upload-larger-plugins(6000装, 138天, permission 修复)
- canonical-attachments(300装, 350天, nonce/permission/auth 修复)
- backup-bolt(800装, 309天, "improved security" 泛词) ← 已粗扫, 见 D:\Pentest\审计进度\backup-bolt+bp-msgat.md
- attachments(8000装, 223天, escape/nonce 修复)

## 修复完整度判定清单(下载端点/白名单类)

1. 路径回退:修复后的白名单检查是否覆盖所有下载路径(如 uploads 根目录兜底分支)
2. nonce 绑定:nonce 是否与 file/参数绑定(换参数 nonce 是否仍有效——option 名含 file hash 才算绑定)
3. 白名单绕过:LIKE 匹配是否可注入/误匹配、引用检查是否完整(post_status/meta 结构)
4. 分支漏修:修复只加主路径时,检查兄弟分支(selective/批量/其他 action 值)是否漏加

## 2026-08-10 新增判定法(4 连审沉淀)

1. **权限基线速判**: 文件操作类插件全在 upload_files(作者级)权限门后+nonce = 直接超 Wordfence 范围(作者级排除), 粗扫即弃
2. **修复引入的 nonce 绕过评估实际影响**: 绕过后只做 post_parent=0 类低影响操作 = 不交; 物理删除/写 option = 硬洞
3. **IDOR 判定公式**: 权限判定对象(bbp_id 帖子作者)≠ 操作对象(att_id 附件)且无关联校验 = IDOR
4. **前端 XSS 修复 ≠ 后端逻辑安全**: XSS 修复只在渲染文件时, 核心文件操作/权限逻辑单独查
5. **版本 zip 404 = trunk 版**: changelog 版本号不在 SVN tags → 下 {slug}.zip(无版本号)拿最新版
6. **大 zip 下载**: 带 Freemius SDK 插件 zip 1MB+, 代理 SSL 间歇失败 → 后台下载+重试+zipfile.testzip() 校验; 解压用 python zipfile 别用 unzip(MSYS 路径坑); SVN 单文件比整包轻量
