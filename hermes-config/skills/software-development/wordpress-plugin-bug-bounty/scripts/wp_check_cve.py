#!/usr/bin/env python3
# 候选插件查重: 批量查 NVD/CVE 已披露记录(占坑检测)
# 用法: python wp_check_cve.py <slug1> <slug2> ...
# 注意: slug 必须显式传参(不要从 /tmp 文件读——git-bash 的 /tmp 在 Windows Python 下不可见)
# 2026-08 实战: 43 个候选中 11 个已被披露(sliced-invoices/woo-addon-uploads/checkout-files-upload-woocommerce 等)
#   已披露 = Wordfence 不收重复, 排除或只找不同根因的洞
import json, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def check(slug):
    url = f"{NVD}?keywordSearch=" + urllib.parse.quote(slug)
    try:
        r = urllib.request.urlopen(url, timeout=45)
        vulns = json.loads(r.read().decode('utf-8', 'replace')).get('vulnerabilities', [])
        return slug, vulns
    except Exception:
        return slug, []

def main():
    if len(__import__('sys').argv) < 2:
        print("用法: python wp_check_cve.py <slug1> <slug2> ...")
        return
    slugs = __import__('sys').argv[1:]
    with ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(check, slugs))
    dirty, clean = [], []
    for slug, vulns in results:
        if vulns:
            dirty.append(slug)
            ids = [v['cve']['id'] for v in vulns[:3]]
            print(f"[已披露] {slug}: {', '.join(ids)}")
        else:
            clean.append(slug)
    print(f"\n=== 干净(无NVD记录): {len(clean)} 个 ===")
    print(' '.join(clean))
    print(f"\n=== 已披露(占坑): {len(dirty)} 个 ===")
    print(' '.join(dirty))
    # 局限提示: NVD keywordSearch 按描述匹配, slug 与显示名不同可能漏报;
    # 关键目标(决定投入审计前)再手动搜 Patchstack/WPScan 数据库确认

if __name__ == '__main__':
    main()
