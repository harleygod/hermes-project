#!/usr/bin/env python3
# High Threat 目标筛选器 v2 (2026-08-11 优化版)
# 相对 v1 的改进: 15s 超时(原40s) / 实时进度落盘 / 分阶段日志 / 输出路径用 Windows 格式
# 用法: python wp_filter_highthreat_v2.py [输出文件]
# 前置: export HTTPS_PROXY=http://127.0.0.1:7890 (api.wordpress.org HTTP 代理可通, 不必 socks5h)
# 原理: query_plugins 关键词搜索 -> 本地过滤 25-5000 装 -> 逐个查 last_updated -> 120+ 天未更新候选
import json, sys, urllib.request, urllib.parse, datetime, time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_KW = ['file manager', 'file upload', 'backup', 'attachment', 'download',
              'zip', 'reset', 'option', 'role', 'upload', 'avatar', 'migration',
              'import', 'csv', 'pdf', 'shortcode']
MAX_INSTALLS = 5000
MIN_INSTALLS = 25
STALE_DAYS = 120
TIMEOUT = 15

def fetch(kw):
    try:
        url = ("https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
               "&request%5Bsearch%5D=" + urllib.parse.quote(kw) + "&request%5Bper_page%5D=40")
        d = json.loads(urllib.request.urlopen(url, timeout=TIMEOUT).read().decode())
        return d.get('plugins', [])
    except Exception:
        return []

def analyze(p):
    slug = p['slug']
    try:
        d = json.loads(urllib.request.urlopen(
            f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D={slug}",
            timeout=TIMEOUT).read().decode())
    except Exception:
        return None
    lu = d.get('last_updated', '')
    days = None
    if lu:
        try:
            days = (datetime.date.today() - datetime.date.fromisoformat(lu[:10])).days
        except Exception:
            pass
    return slug, days, p.get('active_installs', 0), d.get('version')

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'D:/Pentest/筛选结果.txt'  # Windows 原生路径(MSYS 坑)
    fh = open(out, 'w', encoding='utf-8')
    def log(s):
        print(s, flush=True)
        fh.write(s + '\n'); fh.flush()

    seen = {}
    for i, kw in enumerate(DEFAULT_KW):
        t0 = time.time()
        pl = fetch(kw)
        for p in pl:
            s = p.get('slug')
            if s and s not in seen:
                seen[s] = p
        log(f"[fetch {i+1}/{len(DEFAULT_KW)}] {kw}: +{len(pl)} (累计 {len(seen)}, {time.time()-t0:.0f}s)")
    cands = [p for p in seen.values() if MIN_INSTALLS <= p.get('active_installs', 0) <= MAX_INSTALLS]
    log(f"\n候选池 {len(seen)} -> 25-5000 装 {len(cands)}")
    log("开始逐个查 last_updated (6并发)...")
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for i, r in enumerate(ex.map(analyze, cands)):
            if r and r[1]:
                results.append(r)
            if (i+1) % 20 == 0:
                log(f"  ... {i+1}/{len(cands)} 完成, 已收集 {len(results)}, 耗时 {time.time()-t0:.0f}s")
    old = [r for r in results if r[1] > STALE_DAYS]
    old.sort(key=lambda r: -r[1])
    log(f"\n=== {STALE_DAYS}+ 天未更新(维护差)高危面候选: {len(old)} 个 ===")
    for slug, days, inst, ver in old:
        log(f"{slug:<50} {inst:>6}装  {days:>3}天  v{ver}")
    log(f"\n总耗时 {time.time()-t0:.0f}s")
    fh.close()

if __name__ == '__main__':
    main()
