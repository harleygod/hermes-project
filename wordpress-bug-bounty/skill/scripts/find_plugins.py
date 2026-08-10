#!/usr/bin/env python3
# 找 1k-10k 安装量的攻击面插件候选(Wordfence 赏金目标筛选)
# "三个数字快速过滤": 安装量区间 + 更新时间 + 版本号老新
# 用法:
#   python find_plugins.py                    # 热门榜前 ~3000 个过滤
#   python find_plugins.py booking            # 按关键词搜索过滤
#   python find_plugins.py upload import      # 多个关键词
# 输出字段: installs(10000=1万-2万档,API向下取整) / ver / updated / age(3个月内|>1年没更|N月前) / ★老版本v1.x|v2.x
# 下一步:对候选查 changelog 判断维护质量与安全修复历史
#   curl "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>"
#   → sections.changelog 字段搜 security/XSS/CSRF/injection/escalation
import json, sys, time, urllib.request, urllib.parse, datetime

def api(action, params):
    url = f"https://api.wordpress.org/plugins/info/1.2/?action={action}&" + urllib.parse.urlencode(params)
    try:
        r = urllib.request.urlopen(url, timeout=30)
        return json.loads(r.read().decode('utf-8', 'replace'))
    except Exception:
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
                    major = ver.split('.')[0] if ver else ''
                    vtag = f'★老版本v{major}.x' if major in ('1', '2') else ''
                    cands[slug] = {
                        'installs': inst, 'ver': ver, 'updated': updated,
                        'age': age, 'vtag': vtag,
                        'desc': (p.get('short_description') or '')[:55],
                    }
            if page >= pages:
                break
            page += 1
            time.sleep(0.5)
        if kw:
            print(f"[关键词 '{kw}' 累计候选 {len(cands)}]")
            time.sleep(1)

    rows = sorted(cands.values(), key=lambda x: -x['installs'])
    print(f"{'installs':>8} {'ver':<10} {'updated':<11} {'age':<8} {'tag':<12} desc")
    print('-' * 100)
    for r in rows:
        print(f"{r['installs']:>8} {r['ver']:<10} {r['updated']:<11} {r['age']:<8} {r['vtag']:<12} {r['desc']}")

if __name__ == '__main__':
    main()
