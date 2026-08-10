# Hermes 环境同步目录 (hermes-config)

下班电脑装好 Hermes 后，把本目录内容恢复到 Hermes 配置目录即可完整还原环境。

## ⚠️ 敏感警告
本目录含 **API 密钥明文**（.env / config.yaml 里的 vision api_key）！
- 本仓库**必须保持私有**（GitHub Private）
- 不要把仓库分享/公开/加协作者
- 恢复后建议把密钥换成下班电脑自己的（如需）

## 恢复步骤（下班电脑）

1. 安装 Hermes（官方安装方式）
2. 找到 Hermes 配置目录：`C:\Users\<用户名>\AppData\Local\hermes\`
3. 从仓库拷贝（覆盖）：
   - `skills/` → 配置目录 `skills/`（全部 101 个 skill）
   - `.env` → 配置目录 `.env`（API keys + 微信配置）
   - `config.yaml` → 配置目录 `config.yaml`（模型/provider/vision 配置）
   - `cron/` → 配置目录 `cron/`（定时任务，可选）
   - `scripts/` → 配置目录 `scripts/`（同步脚本等）
   - `SOUL.md` → 配置目录 `SOUL.md`（可选）
4. 重启 Hermes → skill/记忆/定时任务全部恢复

## 本目录内容
| 项 | 说明 |
|----|------|
| skills/ | 101 个 skill（方法论资产，含 wordpress-plugin-bug-bounty、pentest 系列等） |
| .env | DEEPSEEK/KIMI_CN/WEIXIN 密钥配置 |
| config.yaml | 主配置：deepseek-flash 主模型 + kimi-cn vision 辅助 |
| cron/ | 定时任务（含 hermes-project 自动同步） |
| scripts/ | 同步脚本等 |
| SOUL.md | Hermes 人格/风格配置（如有） |

## 同步机制
每小时自动同步（cron 任务跑 `audit_sync.sh`）：
- wordpress-bug-bounty/ ← 审计进度 + 该项目的 skill + 工具
- hermes-config/ ← 本目录（skills/.env/config.yaml 等）
- 有改动才 commit + push（GitHub 私有仓库，走代理）

手动同步：`bash /d/Pentest/audit_sync.sh`
