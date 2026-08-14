#!/usr/bin/env python3
# 表单引擎/前端CRUD 金矿筛选器 (2026-08-14 ChainQ 模式复制)
# 目标画像: 配置驱动表单引擎(前端提交/CRUD) × 25-50k装 × 150天+未更新
# 这类插件的金矿洞 = 配置来源可控→提权/认证绕过/任意对象操作 (ChainQ 同类)
# 用法: python wp_filter_formengine.py [输出文件]   (跑前 export HTTPS_PROXY=http://127.0.0.1:7890)
# 2026-08-14 实测: 307 候选 -> 40 个 STALE (结果 D:/Pentest/筛选结果_表单引擎_20260814.txt)
import json, sys, urllib.request, urllib.parse, datetime, time, re
from concurrent.futures import ThreadPoolExecutor

# 表单引擎语义关键词 (ChainQ 同类)
DEFAULT_KW = [
    'frontend form', 'frontend submit', 'frontend post', 'frontend edit',
    'frontend admin', 'user submitted', 'front-end form', 'form builder',
    'post form', 'submit form', 'crud', 'user frontend', 'frontend dashboard',
    'profile builder', 'frontend upload', 'ajax form', 'frontend login',
    'frontend register', 'frontend content', 'frontend publishing',
    'acf frontend', 'form element', 'frontend manager',
]
MAX_INSTALLS = 50000
MIN_INSTALLS = 25
STALE_DAYS = 150
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
    out = sys.argv[1] if len(sys.argv) > 1 else 'D:/Pentest/筛选结果_表单引擎.txt'
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
    log(f"\n候选池 {len(seen)} -> {MIN_INSTALLS}-{MAX_INSTALLS} 装 {len(cands)}")
    log("开始逐个查 last_updated (6并发)...")

    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(analyze, p): p for p in cands}
        done = 0
        for fut in futs:
            r = fut.result()
            done += 1
            if done % 20 == 0:
                log(f"  进度 {done}/{len(cands)}")
            if r:
                results.append(r)

    # 排序: 未更新天数降序(越旧越优先)
    results.sort(key=lambda x: (x[1] is not None, x[1] if x[1] is not None else 0), reverse=True)

    log(f"\n===== 结果 (未更新天数降序) =====")
    log(f"{'SLUG':<45} {'装量':>8} {'天数':>6} {'版本'}")
    log("-" * 75)
    stale = 0
    for slug, days, inst, ver in results:
        mark = ''
        if days is not None and days >= STALE_DAYS:
            mark = ' ★STALE'
            stale += 1
        log(f"{slug:<45} {inst:>8} {str(days):>6} {ver}{mark}")
    log(f"\n共 {len(results)} 个可达, 其中 {stale} 个 >= {STALE_DAYS} 天未更新(★STALE)")
    fh.close()

if __name__ == '__main__':
    main()
