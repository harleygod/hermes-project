---
name: mobile-app-recon
description: "移动端 APK 反编译侦察：dex/libapp.so 字符串提取、Flutter 陷阱、第三方供应链配置泄露。"
version: 1.0.0
metadata:
  hermes:
    tags: [pentest, mobile, apk, flutter, recon, supply-chain]
---

# 移动端 APK 反编译侦察

黑盒渗透中，从应用分发平台/下载页拿到的 APK 是信息金矿：硬编码内部域名、内网 IP、接口路径、第三方供应链配置。

## 触发条件
- 目标有 App 下载链接（APK/IPA）
- 应用分发平台（如"应用资源平台"类站点）未授权接口返回安装包下载地址
- 发现 `com.example.*` 包名的"官方"App

## 流程（快速信息挖掘）

1. 下载 APK：`curl -sk -o app.apk "URL"`
2. 解包 + 提取字符串（见 scripts/apk_strings.py，自动处理 dex 和 libapp.so）
3. grep 关键词：
   - 域名：`[a-z0-9-]+\.(com|cn|net|com\.cn)` 过滤目标公司关键字
   - 内网 IP：`\b(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)` 
   - 公网 IP：目标公司已知 IP 段
   - 密钥：`secret|api[_-]?key|app[_-]?secret|BEGIN (RSA|PRIVATE)|password\s*[:=]`
   - 接口：`/api/|/rest/|/policy/` 等业务前缀
4. 新域名逐个测可达性（curl 状态码 + DNS 解析），区分：公网在线 / 公网可解析但防火墙 DROP / 纯内网 DNS 失败

## Flutter 陷阱（关键，易踩坑）

- **包名 `com.example.*` 的"官方"App 多为第三方壳/测试包**，业务代码不在 dex
- Flutter App 的 Dart 业务代码编译在 `lib/arm64-v8a/libapp.so`（和 `libflutter.so` 同目录），classes.dex 里只有框架库
- **dex 字符串无货时必查 libapp.so**：`strings lib/arm64-v8a/libapp.so | grep -E 'https?://|gitee|github'`
- 识别 Flutter：APK 里有 `libflutter.so`、大量 `assets/flutter_assets/`、`sqflite` 等库

## 供应链线索（高价值）

- App 配置从第三方服务器拉取：搜 `http://` 开头的 .json 配置 URL → **抓取配置内容**（常含机构列表、环境域名、内网/公网服务器地址）
- 隐私协议/更新链接指向的第三方域名 = 开发商线索（可关联开发商其他项目）
- **公开代码仓库（gitee/github raw 链接）里的配置文件可能是金矿**：第三方开发商把客户环境配置提交到公开仓库，直接泄露内网 IP + 多环境域名
- 实测案例：小米市场"太保销售App"（com.example.taibao_sale_app）→ libapp.so 挖出 `gitee.com/hzaxun/sale-api/raw/master/taibaosale.json` → 泄露内网 IP 192.168.110.57:8081、公网 IP 114.215.183.66:8083、4 个合作环境域名

## 验证与证据

- 泄露的每个域名记录 DNS 解析结果 + 端口状态（区分：防火墙 DROP 超时 / 连接拒绝 / 握手后切断=安全网关应用层过滤）
- 可访问的环境立即测（403 全路径 = IP 白名单，记录即可）
- 证据保存：字符串提取结果全文（可 grep 复现）+ 配置 JSON 原文

## 工具

- 本机：D:\Pentest\反编译工具\（jadx-gui、jd-gui）、Tesseract OCR
- 无需重装 Playwright 等——纯本地 python 脚本即可完成字符串级侦察

## 红线

- 只读分析（下载+本地解包）可自行进行；用 App 凭据登录目标系统属写操作范畴，先确认
- 供应链第三方资产（开发商服务器）超出授权范围时只记录不深入
