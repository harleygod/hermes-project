---
name: hermes-multi-model
description: "Set up vision model and other auxiliary models in Hermes."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [hermes, configuration, multi-model, vision, auxiliary, china]
---

# Hermes Multi-Model Configuration

Configure Hermes to use different models/providers for different tasks —
vision, context compression, approval gating, and other auxiliary functions —
without switching the main conversation model.

## When to Use

- Main model lacks vision support (e.g., DeepSeek V4 Pro) but you want image analysis
- You want cheap models for background tasks (compression, approval) and a powerful model for chat
- You're in China and need to route different capabilities through different providers
- Setting up a multi-provider Hermes instance

## Auxiliary Model Sections

Hermes exposes these auxiliary model slots, each independently configurable:

| Section | Purpose | Importance |
|---------|---------|-----------|
| `vision` | Image analysis (screenshots, photos, diagrams) | ⭐ High |
| `compression` | Context window summarization | Medium |
| `approval` | Dangerous-command safety gating | Medium |
| `web_extract` | Web page content extraction | Low |
| `skills_hub` | Skill catalog queries | Low |
| `title_generation` | Auto-naming sessions | Low |
| `memory_query_rewrite` | Memory search query optimization | Low |
| `mcp` | MCP server tool selection | Low |
| `background_review` | Background task review | Low |
| `curator` | Skill/knowledge consolidation | Low |
| `goal_judge` | Goal completion assessment | Low |
| `kanban_decomposer` | Task decomposition | Low |
| `monitor` | Session monitoring | Low |

Each section accepts: `provider`, `model`, `base_url`, `api_key`, `timeout`, `extra_body`, `reasoning_effort`.

## Step 1 — Vision Model (most common)

When your main model doesn't support images, add a vision-capable auxiliary:

```bash
# Example: DeepSeek main + Kimi vision
# 注意: 必须用 auxiliary.vision.* 键位! 顶层 vision.* 不生效——
# 源码 resolve 只读 auxiliary.* (2026-08 实测: 配顶层后重启仍无 vision_analyze)
hermes config set auxiliary.vision.provider kimi-cn
hermes config set auxiliary.vision.model kimi-k2.6
```

API key goes in `~/.hermes/.env`:
```
KIMI_CN_API_KEY=sk-xxx
```

**Provider options for vision:**
| Provider | Config value | Key env var |
|----------|-------------|-------------|
| Kimi (国内) | `kimi-cn` | `KIMI_CN_API_KEY` |
| Kimi (国际) | `kimi-coding` | `KIMI_API_KEY` |
| Qwen (通义千问) | `qwen-oauth` | OAuth via `hermes auth add qwen-oauth` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI | (main provider) | `OPENAI_API_KEY` |
| Gemini | `gemini` | `GOOGLE_API_KEY` |
| MiniMax | `minimax-cn` | `MINIMAX_CN_API_KEY` |

Verify with:
```bash
hermes config get auxiliary.vision          # 确认键位/模型 (勿用顶层 vision, 假阳性)
hermes doctor | grep -i vision             # ✓ = 后端可用, ⚠ = 解析失败
# 源码级诊断 (在 hermes-agent 源码目录执行):
python -c "from agent.auxiliary_client import resolve_vision_provider_client; print(resolve_vision_provider_client())"
#  期望 (provider, OpenAI client, model) 三元组; client=None 时开 DEBUG 看缺什么:
HERMES_LOG_LEVEL=DEBUG python -c "from agent.auxiliary_client import resolve_provider_client; print(resolve_provider_client('<provider>', model='<m>'))"
#  日志会打印 "has no API key configured (tried: XXX)" —— XXX 就是 .env 里正确的变量名
# 布尔检查: python -c "from tools.vision_tools import check_vision_requirements; print(check_vision_requirements())"
```

## Step 2 — Other Auxiliaries (optional)

Set compression and approval to cheaper models to save cost:

```bash
hermes config set compression.provider kimi-cn
hermes config set compression.model kimi-k2.6
hermes config set approval.provider kimi-cn
hermes config set approval.model kimi-k2.6
```

## China-Specific Setup

See `references/china-setup.md` for:
- Electron mirror configuration
- npm dependency conflict resolution on Windows
- Provider selection guide for Chinese users

## Verification

```bash
# Check all auxiliary model configs
hermes config show | grep -A 4 "vision\|compression\|approval"

# Test vision is working
hermes chat -q "Describe this image" --image /path/to/test.png
```

## Pitfalls

- **API key 必须放 .env 的正确变量名** — config.yaml 里 `auxiliary.vision.api_key` **不生效**！`resolve_provider_client` 只从 .env 的 provider 专属变量读 key。变量名映射：kimi-cn→`KIMI_CN_API_KEY`、kimi-coding(国际)→`KIMI_API_KEY`、minimax-cn→`MINIMAX_CN_API_KEY`。变量名查法：`HERMES_LOG_LEVEL=DEBUG` 跑 resolve_provider_client，日志打印 "(tried: XXX)" 直接指出。写 .env 时用 `grep | sed 's/=sk-.*/=sk-***/'` 打码验证
- **kimi-cn 别名与图像限制** — `kimi-cn` 是 `kimi-coding-cn` 的别名（base_url api.moonshot.cn/v1，OpenAI 协议）。sk-kimi-* 前缀的 Coding Plan key 走 api.kimi.com/coding（Anthropic 协议）**无图像能力**（源码 `_PROVIDERS_WITHOUT_VISION` 排除）；普通 sk- 开头 legacy key 走 moonshot.cn OpenAI 协议可用。`auxiliary.vision.model=kimi-k2.6` 显式指定有效（provider 默认 aux 模型是 kimi-k2-turbo-preview）
- **Vision model must support images** — not all models do. Kimi k2.6, Qwen-VL, Claude 3+, GPT-4V, Gemini support vision. DeepSeek V3/V4 do NOT.
- **API keys are per-provider** — each auxiliary provider needs its own key in `.env`.
- **`provider: auto` means "use main provider"** — if main model supports vision, no separate config needed. Auto 链会跳过 _PROVIDERS_WITHOUT_VISION 的主 provider 直接走聚合器
- **Timeout applies to image download** — `vision.download_timeout` (default 30s) controls how long Hermes waits to fetch the image; increase for large/slow sources.
- **Auxiliary model changes take effect on next session** — vision_analyze 工具在会话启动时按 check_fn 加载，配置修好后必须 `/reset` 或新开会话才出现在工具列表；当前会话永远看不到
- **hermes tools 交互输出不可靠** — `hermes tools` 是交互式菜单（会挂起等输入），状态判断用 `hermes doctor | grep -i vision` 或源码 resolve 调用
