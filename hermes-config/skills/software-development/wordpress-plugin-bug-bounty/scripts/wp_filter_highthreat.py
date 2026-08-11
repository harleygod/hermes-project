#!/usr/bin/env python3
# Wordfence 新范围(2026-08) High Threat 目标筛选器 v2 (2026-08-11 优化版)
#   25-5000 装 + 文件操作类关键词 + 120+ 天未更新(维护差)
# 用法: python wp_filter_highthreat.py [输出文件]
# 优化(相对 v1): 15s 超时(v1 是 40s, 慢网络下极慢) / 实时进度 flush / 分阶段输出可中途查看
# 坑: 输出文件路径必须 Windows 格式 (D:/...), /d/... 会被 Windows python 报 FileNotFoundError
# 代理: 跑前 export HTTPS_PROXY=http://127.0.0.1:7890 (api.wordpress.org HTTP 代理可通, urllib 自动读 env)
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
    out = sys.argv[1] if len(sys.argv) > 1 else 'D:/Pentest/筛选结果.txt'
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
