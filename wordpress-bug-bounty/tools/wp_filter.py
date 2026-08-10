#!/usr/bin/env python3
# ============================================================
# WP 插件"三个数字快速过滤"工具
# 用法:
#   python wp_filter.py                # 拉热门榜前 ~3000 个插件过滤
#   python wp_filter.py 关键词          # 按关键词搜索后过滤
#   python wp_filter.py upload import  # 多个关键词
# 输出:安装量 1000-10000 的候选 + 更新时间 + 版本 + 标签
# ============================================================
import json, sys, time, urllib.request, urllib.parse, datetime

def api(action, params):
    url = f"https://api.wordpress.org/plugins/info/1.2/?action={action}&" + urllib.parse.urlencode(params)
    try:
        r = urllib.request.urlopen(url, timeout=30)
        return json.loads(r.read().decode('utf-8', 'replace'))
    except Exception as e:
        return {}

def fetch_batch(keyword=None, page=1, per_page=250):
    params = {'request[per_page]': per_page, 'request[page]': page}
    if keyword:
        params['request[search]'] = keyword
    else:
        params['request[browse]'] = 'popular'
    d = api('query_plugins', params)
    return d.get('plugins', []), d.get('info', {}).get('pages', 1)

def main():
    keywords = sys.argv[1:] or [None]
    today = datetime.date.today()
    cands = {}
    for kw in keywords:
        page = 1
        while page <= 12:   # 最多拉 12 页 ~3000 个
            plugs, pages = fetch_batch(kw, page)
            if not plugs:
                break
            for p in plugs:
                slug = p.get('slug', '')
                inst = p.get('active_installs', 0)
                if 1000 <= inst <= 10000 and slug not in cands:
                    updated = (p.get('last_updated') or '')[:10]
                    try:
                        upd = datetime.date.fromisoformat(updated) if updated else None
                    except Exception:
                        upd = None
                    ver = p.get('version', '')
                    age = ''
                    if upd:
                        days = (today - upd).days
                        age = '3个月内' if days <= 90 else ('>1年没更' if days > 365 else f'{days//30}月前')
                    # 版本标签
                    vtag = ''
                    major = ver.split('.')[0] if ver else ''
                    if major in ('1', '2'):
                        vtag = f'★老版本v{major}.x'
                    cands[slug] = {
                        'installs': inst, 'ver': ver, 'updated': updated,
                        'age': age, 'vtag': vtag,
                        'dl': p.get('downloaded', 0),
                        'desc': (p.get('short_description') or '')[:55],
                    }
            if page >= pages:
                break
            page += 1
            time.sleep(0.5)
        if kw:
            print(f"[关键词 '{kw}' 累计候选 {len(cands)}]\n")
            time.sleep(1)

    rows = sorted(cands.values(), key=lambda x: -x['installs'])
    print(f"{'installs':>8} {'ver':<10} {'updated':<11} {'age':<8} {'tag':<12} desc / slug")
    print('-' * 115)
    for r in rows:
        print(f"{r['installs']:>8} {r['ver']:<10} {r['updated']:<11} {r['age']:<8} {r['vtag']:<12} {r['desc']}")

if __name__ == '__main__':
    main()
