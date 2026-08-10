# 审计进度 — bangladeshi-payment-gateways 4.0.4

> 状态: 已放弃(人工确认型支付,无自动流程) | 日期: 2026-08-10
> 源码: D:\Documents\sources\Wordpress插件\bangladeshi-payment-gateways\
> 安装量 5000 | 224 天前更新 | NVD 干净

## 结论
bKash/Rocket 人工确认型支付:买家结账填账号+交易号,存订单 meta,商家后台人工核对确认。**无自动回调/webhook/确认流程,无 nopriv 端点**。Admin 导出(nonce+manage_woocommerce ✓)。无洞,放弃。

## 关键代码
- includes/BDPG_Gateway.php:578 payment_process(结账校验账号数字格式);:626 fields_update(交易号存 meta)——均人工流程
- includes/Admin/Statistics.php:246/271 ajax_get_transactions/ajax_export_transactions(nonce + manage_woocommerce ✓)
- :301 export_csv / :341 export_pdf

## 待办
- 无(放弃)
