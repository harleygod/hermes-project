#!/bin/bash
# hermes-project 自动同步脚本 (2026-08-10)
# 用法: bash /d/Pentest/audit_sync.sh [--force]
# 行为: 同步 wordpress-bug-bounty 进度/skill + hermes-config 环境 → git commit → push
# 无改动时静默退出 (exit 0, 无输出) — 适配 cron no_agent 静默模式
# 密钥安全: 真实 .env/config.yaml 不进入仓库, 仓库只存脱敏模板 (.env.example)

REPO="/d/Pentest/hermes-project"
SRC_PROGRESS="/d/Pentest/审计进度"
SRC_SKILL="/c/Users/user/AppData/Local/hermes/skills/software-development/wordpress-plugin-bug-bounty"
H="/c/Users/user/AppData/Local/hermes"
PROXY="http://127.0.0.1:7890"

# 1. wordpress-bug-bounty 子项目: 进度 + 该项目 skill + 工具
WPB="$REPO/wordpress-bug-bounty"
cp -f "$SRC_PROGRESS"/*.md "$WPB/审计进度/" 2>/dev/null
rm -rf "$WPB/skill"
cp -r "$SRC_SKILL" "$WPB/skill/" 2>/dev/null

# 2. hermes-config: skills (全量) + SOUL + cron + scripts (排除密钥/缓存)
HC="$REPO/hermes-config"
rm -rf "$HC/skills"
cp -r "$H/skills" "$HC/skills" 2>/dev/null
rm -rf "$HC/skills/.curator_backups" "$HC/skills/.hub" 2>/dev/null
cp -f "$H/SOUL.md" "$HC/" 2>/dev/null
rm -rf "$HC/cron"; cp -r "$H/cron" "$HC/cron" 2>/dev/null
rm -rf "$HC/scripts"; cp -r "$H/scripts" "$HC/scripts" 2>/dev/null
# 注意: .env / config.yaml 真实密钥文件永不拷贝进仓库; 模板 .env.example/config.yaml.example 手工维护

cd "$REPO" || exit 1

# 3. 有改动才 commit
if ! git diff --quiet HEAD -- 2>/dev/null; then
    git add -A
    git commit -m "auto-sync $(date '+%Y-%m-%d %H:%M')" >/dev/null 2>&1
    echo "[sync] committed changes at $(date '+%H:%M')"
else
    echo ""
    exit 0
fi

# 4. push (GitHub 走代理)
git -c http.proxy="$PROXY" -c https.proxy="$PROXY" push origin main 2>&1 | tail -2
exit ${PIPESTATUS[0]}
