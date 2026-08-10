#!/usr/bin/env python3
# Wordfence 新范围(2026-08)High Threat 目标筛选器:
#   25-5000 装 + 文件操作类关键词 + 120+ 天未更新(维护差)
# 用法: python wp_filter_highthreat.py [关键词...]
# 原理: query_plugins 关键词搜索 -> 本地过滤安装量 -> 逐个查 plugin_information
#       拿 last_updated 算维护间隔 -> 输出"维护差的高危面候选"
import json, re, sys, urllib.request, urllib.parse, datetime
from concurrent.futures import ThreadPoolExecutor

DEFAULT_KW = ['file manager', 'file upload', 'backup', 'attachment', 'download',
              'zip', 'reset', 'option', 'role', 'upload', 'avatar', 'migration',
              'import', 'csv', 'pdf', 'shortcode']
MAX_INSTALLS = 5000   # High Threat 门槛是 25,上限放宽到 5k(冷门小插件甜区)
MIN_INSTALLS = 25
STALE_DAYS = 120      # 维护差阈值

def fetch(kw):
    try:
        url = ("https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
               "&request%5Bsearch%5D=" + urllib.parse.quote(kw) + "&request%5Bper_page%5D=40")
        d = json.loads(urllib.request.urlopen(url, timeout=40).read().decode())
        return d.get('plugins', [])
    except Exception:
        return []

def analyze(p):
    slug = p['slug']
    try:
        d = json.loads(urllib.request.urlopen(
            f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D={slug}",
            timeout=40).read().decode())
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
    kws = sys.argv[1:] or DEFAULT_KW
    seen = {}
    for kw in kws:
        for p in fetch(kw):
            s = p.get('slug')
            if s and s not in seen:
                seen[s] = p
    cands = [p for p in seen.values() if MIN_INSTALLS <= p.get('active_installs', 0) <= MAX_INSTALLS]
    print(f"候选池 {len(seen)} -> 25-5000 装 {len(cands)}")
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = [r for r in ex.map(analyze, cands) if r and r[1]]
    old = [r for r in results if r[1] > STALE_DAYS]
    old.sort(key=lambda r: -r[1])
    print(f"\n=== {STALE_DAYS}+ 天未更新(维护差)的高危面候选: {len(old)} 个 ===")
    for slug, days, inst, ver in old:
        print(f"{slug:<50} {inst:>6}装  {days:>3}天  v{ver}")

if __name__ == '__main__':
    main()
