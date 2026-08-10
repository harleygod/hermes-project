# -*- coding: utf-8 -*-
"""
APK 静态字符串提取：dex + Flutter libapp.so
用法: python extract_apk_strings.py app.apk [输出目录]
输出: <输出目录>/strings_all.txt (dex) 和 strings_so.txt (libapp.so)
敏感信息速查:
  grep -E 'cpic|com\.cn' strings_*.txt        # 内部域名
  grep -E '\b10\.|192\.168|172\.(1[6-9]|2[0-9]|3[01])' strings_*.txt  # 内网 IP
  grep -oE 'https?://[a-zA-Z0-9._:-]+' strings_*.txt | sort -u      # URL
  grep -E 'gitee|github|raw\.' strings_*.txt   # 供应链配置源
  grep -iE 'secret|apikey|appsecret|BEGIN (RSA|PRIVATE)' strings_*.txt
"""
import sys, os, re, zipfile

def extract_strings(data, min_len=6):
    return [s.decode('ascii', 'ignore') for s in re.findall(rb'[\x20-\x7e]{%d,}' % min_len, data)]

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    apk = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else '.'
    os.makedirs(outdir, exist_ok=True)
    z = zipfile.ZipFile(apk)
    names = z.namelist()

    dex_strs = []
    for n in names:
        if n.endswith('.dex'):
            print(f'[*] dex: {n} ({z.getinfo(n).file_size}B)')
            dex_strs.extend(extract_strings(z.read(n)))
    if dex_strs:
        with open(os.path.join(outdir, 'strings_all.txt'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(dex_strs))
        print(f'[+] dex 字符串: {len(dex_strs)} → strings_all.txt')

    # Flutter: libapp.so 才是业务字符串所在地
    so_hits = [n for n in names if n.endswith('.so') and ('libapp.so' in n or 'libflutter.so' in n)]
    if so_hits:
        for n in so_hits:
            if 'libapp.so' in n:  # 只提 libapp（libflutter 是框架噪音）
                print(f'[*] Flutter libapp.so: {n}')
                so_strs = extract_strings(z.read(n), min_len=8)
                with open(os.path.join(outdir, 'strings_so.txt'), 'w', encoding='utf-8') as f:
                    f.write('\n'.join(so_strs))
                print(f'[+] libapp.so 字符串: {len(so_strs)} → strings_so.txt')
                # 自动提示供应链线索
                for kw in ('gitee', 'github', 'raw.', 'update', 'config'):
                    hits = [s for s in so_strs if kw in s.lower() and 'http' in s.lower()]
                    if hits:
                        print(f'[!] 供应链线索({kw}):')
                        for h in hits[:3]:
                            print(f'    {h[:140]}')

if __name__ == '__main__':
    main()
