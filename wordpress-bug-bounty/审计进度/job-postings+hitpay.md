# 审计进度 — job-postings 2.8.1 / hitpay-payment-gateway 4.2.1

> 日期: 2026-08-10 | 均已按完整规则重新评估

## job-postings 2.8.1(10000装, 191天)
**已放弃**:
- nopriv ajax_submit(class-job-application-submit.php:15):未认证创建 publish job-entry 文章(job-entry public=false 前端不可见)+ 文件上传(media_handle_upload 标准 MIME,php 不可传)+ recaptcha 可选
- 简历下载 /job-postings-get-file/<文件>(class-job-get-uploaded-file.php:25):需登录 + 文件名=时间戳-原名不可枚举
- **新规则评估**:订阅者下载简历文件(需文件名)+ 未认证批量申请=DoS/垃圾 → 均非硬洞,放弃

## hitpay-payment-gateway 4.2.1(4000装, 253天)
**已放弃**:
- webhook 验证完整(HMAC salt 非空强制 + 金额 + 货币)
- return_from_hitpay(:1313):未认证 GET 取消任意订单(status=canceled)
- **新规则评估**:取消订单 = Business Logic Flaw + DoS → **Out of Scope**,放弃
