#!/usr/bin/env python3
# 理想目标筛选器: 1k-10k安装 + changelog 修过安全漏洞 + 更新间隔 60-400 天(修过洞但不勤快)
# 用法: python wp_filter_vuln.py [关键词...]
# 2026-08 实测: 默认关键词跑出 43 个候选(woo-addon-uploads/sliced-invoices/wc-multivendor-membership 等)
import json, re, sys, time, urllib.request, urllib.parse, datetime

SEC_WORDS = ['security', 'xss', 'csrf', 'injection', 'vulnerab', 'escalat', 'unauthor', 'privilege', 'nonce', 'sanitize', 'capabilit', 'sqli', 'rce']

def api(action, params):
    url = f"https://api.wordpress.org/plugins/info/1.2/?action={action}&" + urllib.parse.urlencode(params)
    try:
        r = urllib.request.urlopen(url, timeout=30)
        return json.loads(r.read().decode('utf-8', 'replace'))
    except Exception:
        return {}

def get_detail(slug):
    d = api('plugin_information', {'request[slug]': slug})
    if not d:
        return None
    ch = (d.get('sections') or {}).get('changelog', '') or ''
    upd = (d.get('last_updated') or '')[:10]
    return {
        'changelog': ch.lower(),
        'updated': upd,
        'installs': d.get('active_installs', 0),
        'ver': d.get('version', ''),
    }

def main():
    keywords = sys.argv[1:] or ['upload', 'import', 'booking', 'form', 'directory', 'listing', 'subscription', 'invoice', 'membership']
    today = datetime.date.today()
    seen, results = {}, []
    for kw in keywords:
        plugs = api('query_plugins', {'request[search]': kw, 'request[per_page]': 60})
        for p in plugs.get('plugins', []):
            slug = p.get('slug', '')
            inst = p.get('active_installs', 0)
            if 1000 <= inst <= 10000 and slug not in seen:
                seen[slug] = True
                results.append(slug)
        time.sleep(0.8)
    print(f"候选池: {len(results)} 个,逐个查 changelog...\n")
    hits = []
    for i, slug in enumerate(results):
        d = get_detail(slug)
        if not d:
            continue
        ch = d['changelog']
        sec_hits = [w for w in SEC_WORDS if w in ch]
        if not sec_hits:
            continue
        try:
            upd = datetime.date.fromisoformat(d['updated'])
            days = (today - upd).days
        except Exception:
            days = -1
        # 理想画像: 修过洞 + 更新间隔 60~400 天(不勤快也不死透)
        if 60 <= days <= 400:
            hits.append((slug, d['installs'], d['ver'], d['updated'], days, sec_hits[:4]))
        if i % 10 == 0:
            time.sleep(1)
        time.sleep(0.4)
    hits.sort(key=lambda x: -x[1])
    print(f"{'slug':<40} {'inst':>6} {'ver':<11} {'updated':<11} {'days':>5}  安全记录")
    print('-' * 120)
    for h in hits:
        print(f"{h[0]:<40} {h[1]:>6} {h[2]:<11} {h[3]:<11} {h[4]:>5}  {','.join(h[5])}")

if __name__ == '__main__':
    main()
