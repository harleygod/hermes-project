# 审计进度 — essential-real-estate 5.3.3

> 状态: 粗扫完成,未深挖(用户决定换目标) | 日期: 2026-08-09
> 源码: D:\Documents\sources\Wordpress插件\essential-real-estate\
> 安装量 7000 | changelog 修过: xss, csrf | NVD 无已披露 CVE(干净)

## 结论
防护中等偏上。注册/密码重置/上传/删除/属性操作均有 nonce + 归属校验。唯一发现: contact_agent 未认证任意邮件发送(中低危)。**如需回头挖,优先:评论 submit_review_ajax(存储XSS)、收藏 favorite_ajax(IDOR)、属性表单保存(meta SQLi)、property_print_ajax。**

## 结构
- 550 PHP / 6.4万行
- includes/class-ere-role.php — ere_customer 自定义角色(注册时分配,含 property CRUD 能力,无 unfiltered_upload)
- public/partials/property/class-ere-property.php — 房产相关 nopriv AJAX(上传/删除/联系/评论/收藏)
- public/partials/account/class-ere-login-register.php — 登录/注册/密码重置
- includes/shortcodes/system/class-ere-shortcode-property.php — 我的房产管理(删除/标记)

## 已查面
| 面 | 结论 | 位置 |
|---|---|---|
| nopriv 端点 | ~20 个,注册于 includes/class-essential-real-estate.php:350-418 | |
| 注册 | nonce+校验齐全,set_role('ere_customer') 固定 ✓ | class-ere-login-register.php:93-180 |
| 密码重置 | nonce+get_password_reset_key 标准 ✓(用户枚举) | :211-250 |
| 图片/附件上传 | ere_is_cap_customer(ere_customer 角色)+ wp_handle_upload MIME 白名单,无 unfiltered_upload ✓ | class-ere-property.php:173-240 |
| 删除附件 | nonce 绑定(uid+aid+pid)+ property_id>0 时作者校验 ✓ | :98-135, validate_remove_attachment:34-64 |
| 属性删除/标记 | nonce + user_can_edit_property(作者校验)✓ | class-ere-shortcode-property.php:65-80 |
| 联系经纪人 | **未认证任意邮件:nopriv + target_email POST 可控 + nonce 前端可拿** ⚠️ 中低危 | class-ere-property.php:747-782 |

## 待查(未做)
- submit_review_ajax(评论存储 XSS)
- favorite_ajax(IDOR)
- submit-property 表单保存(meta 处理 SQLi)
- property_print_ajax(文件读/PDF)
- ere_login_ajax(登录实现)
