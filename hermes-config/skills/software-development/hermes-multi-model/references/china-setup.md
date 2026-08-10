# Hermes Setup in China

## Electron Binary Download

Electron downloads its binaries directly from GitHub Releases, bypassing npm registry
mirrors. Even with npm set to a domestic registry, Electron installs will fail with
`ECONNRESET` or `read ECONNRESET`.

### Fix: Set Electron mirror

**Permanent (recommended):**
```bash
setx ELECTRON_MIRROR "https://npmmirror.com/mirrors/electron/"
```
Then restart your terminal.

**Per-session:**
```bash
export ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/"
```

Applies to both `hermes desktop` auto-install and manual `npm install`.

## npm Dependency Conflicts on Windows

Hermes desktop workspace may encounter peer dependency conflicts during install:
```
npm error ERESOLVE unable to resolve dependency tree
npm error peer @assistant-ui/react@"^0.15.0" from @assistant-ui/react-streamdown@0.3.8
```

### Fix: `--legacy-peer-deps`

```bash
cd ~/AppData/Local/hermes/hermes-agent
npm install --legacy-peer-deps
```

Or for desktop workspace specifically:
```bash
cd ~/AppData/Local/hermes/hermes-agent/apps/desktop
npm install --legacy-peer-deps
```

## Windows node_modules Cleanup

`rm -rf node_modules` in git-bash often times out due to deep path nesting.
Use Windows native command instead:

```bash
cmd //c "rmdir /s /q node_modules"
```

## Provider Selection for China

| Task | Recommended Provider | Vision? |
|------|---------------------|---------|
| Main chat | DeepSeek (`deepseek`) | No |
| Vision/Images | Kimi (`kimi-cn`), Qwen (`qwen-oauth`) | Yes |
| Auxiliary (compression, approval) | Kimi (`kimi-cn`) | Not needed |

All domestic providers work without VPN. API keys go in `~/.hermes/.env`.
