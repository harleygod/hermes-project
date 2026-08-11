#!/usr/bin/env python3
# SQLi/XSS 面目标筛选器 (2026-08-11): 10k-50k 装大插件, 表单/搜索/动态输出类
# 用法: python wp_filter_sqlxss.py [输出文件]
# 前置: export HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890
# 坑: 脚本内文件路径用 Windows 格式 (D:/...), 别用 /d/ (Windows 原生 python 报 FileNotFoundError)
import json, sys, urllib.request, urllib.parse, datetime, time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_KW = ['contact form', 'search', 'table', 'directory', 'listing', 'booking',
              'membership', 'donation', 'quiz', 'survey', 'event', 'gallery',
              'ajax', 'import', 'export', 'shortcode', 'subscription', 'order']
MAX_INSTALLS = 50000
MIN_INSTALLS = 10000
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
    out = sys.argv[1] if len(sys.argv) > 1 else 'D:/Pentest/筛选结果_sqlxss_YYYYMMDD.txt'
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
    log(f"\n候选池 {len(seen)} -> 10k-50k 装 {len(cands)}")
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for i, r in enumerate(ex.map(analyze, cands)):
            if r and r[1]:
                results.append(r)
            if (i+1) % 20 == 0:
                log(f"  ... {i+1}/{len(cands)} 完成, 已收集 {len(results)}, 耗时 {time.time()-t0:.0f}s")
    results.sort(key=lambda r: -r[2])
    log(f"\n=== 10k-50k 装候选 ({len(results)} 个, 按装量降序) ===")
    for slug, days, inst, ver in results:
        log(f"{slug:<50} {inst:>6}装  {days:>3}天  v{ver}")
    log(f"\n总耗时 {time.time()-t0:.0f}s")
    fh.close()

if __name__ == '__main__':
    main()
