#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 下载 20260804 批域名的APK到 E:\...\20260804(纯网络,不占云手机;并发+增量+可续)
import subprocess, os, re, csv, concurrent.futures as cf

DOMAIN_FILE = "/mnt/e/Work/App-analyze/Apks/Duoyun-apks/20260804/【外部公开】违规APP下载链接260804.txt"
OUT_DIR = "/mnt/e/Work/App-analyze/Apks/Duoyun-apks/20260804"
LOG = "/home/ninini/Agents/APK-Research/data/dl_20260804.csv"

def landing_apk_url(domain):
    """访问域名首页,抠出android apk下载链接"""
    for scheme in ("https","http"):
        try:
            r = subprocess.run(['curl','-sk','-L','--connect-timeout','8','-m','20','-A','Mozilla/5.0 (Linux; Android 13)',
                                f'{scheme}://{domain}/'], capture_output=True, text=True, timeout=25)
            html = r.stdout or ""
        except Exception:
            html = ""
        if not html: continue
        for pat in (r'android\s*:\s*"([^"]+)"', r'androidUrl\s*:\s*"([^"]+)"',
                    r'href="([^"]+\.apk[^"]*)"', r'(https?://[^\s"\'<>]+\.apk[^\s"\'<>]*)'):
            m = re.findall(pat, html, re.I)
            if m:
                u = m[0]
                if u.startswith('//'): u = 'https:'+u
                elif u.startswith('/'): u = f'{scheme}://{domain}'+u
                elif not u.startswith('http'): u = f'{scheme}://{domain}/'+u
                return u
    return None

def dl_one(domain):
    out = os.path.join(OUT_DIR, f"{domain}.apk")
    if os.path.exists(out) and os.path.getsize(out) > 1_000_000:
        return (domain, "exist", os.path.getsize(out)//1024//1024)
    url = landing_apk_url(domain)
    if not url:
        return (domain, "no_link", 0)
    try:
        subprocess.run(['curl','-sk','-L','--connect-timeout','15','-m','180','-A','Mozilla/5.0 (Linux; Android 13)',
                        '-o', out, url], capture_output=True, timeout=140)
    except Exception:
        pass
    sz = os.path.getsize(out) if os.path.exists(out) else 0
    if sz > 1_000_000:
        return (domain, "ok", sz//1024//1024)
    else:
        if os.path.exists(out): os.remove(out)
        return (domain, "dl_fail", 0)

def main():
    # 关键:清掉Clash代理env,否则curl走127.0.0.1:7890下载会失败(这些国内CDN拒代理)
    for k in ("http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY","all_proxy","ALL_PROXY"):
        os.environ.pop(k, None)
    os.makedirs(OUT_DIR, exist_ok=True)
    domains=[]
    for line in open(DOMAIN_FILE, encoding='utf-8-sig'):
        d=line.strip()
        if d and d!="pre_host": domains.append(d)
    print(f"域名总数 {len(domains)}", flush=True)
    done=set()
    if os.path.exists(LOG):
        for r in csv.reader(open(LOG)):
            if r: done.add(r[0])
    todo=[d for d in domains if d not in done]
    print(f"待下载 {len(todo)}", flush=True)
    fout=open(LOG,"a"); w=csv.writer(fout)
    n_ok=n_no=n_fail=n_exist=0
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        for domain,status,mb in ex.map(dl_one, todo):
            w.writerow([domain,status,mb]); fout.flush()
            if status=="ok": n_ok+=1
            elif status=="exist": n_exist+=1
            elif status=="no_link": n_no+=1
            else: n_fail+=1
            print(f"  {domain} -> {status} {mb}MB  (ok={n_ok} exist={n_exist} 无链接={n_no} 失败={n_fail})", flush=True)
    fout.close()
    print(f"完成. ok={n_ok} exist={n_exist} no_link={n_no} fail={n_fail}", flush=True)

if __name__=="__main__":
    main()
