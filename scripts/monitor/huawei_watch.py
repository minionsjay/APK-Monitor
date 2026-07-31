#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 扫 cloud_json_results.csv,统计云厂商分布 + 揪出华为云IP(不影响正在跑的批量)
import csv, sys, os
from collections import Counter

CSV = "/home/ninini/Agents/APK-Research/data/cloud_json_results.csv"
HUAWEI = ('110.41','113.45','113.46','116.205','121.37','124.71')

def cloud(ip):
    ip = ip.split(':')[0]
    if any(ip.startswith(p) for p in HUAWEI): return "华为云"
    if any(ip.startswith(p) for p in ('8.13','8.138','8.148','8.163','39.','47.')): return "阿里云"
    if any(ip.startswith(p) for p in ('43.','42.','106.','114.132','139.','111.230','119.','123.207','1.14','1.202','159.75','175.178','134.175','193.112')): return "腾讯云"
    return "其他"

def main():
    if not os.path.exists(CSV): print("还没有结果文件"); return
    rows = list(csv.DictReader(open(CSV)))
    done = [r for r in rows if r.get('got_json')=='yes']
    allips=set(); cc=Counter(); hw_hits=[]
    for r in rows:
        for ip in (r.get('ips') or '').split(';'):
            ip=ip.strip()
            if not ip: continue
            allips.add(ip); c=cloud(ip); cc[c]+=1
            if c=="华为云": hw_hits.append((r['domain'], ip))
    print(f"已处理记录:{len(rows)}  拿到json:{len(done)}  去重IP总数:{len(allips)}")
    print("云厂商分布(按出现次数):", dict(cc))
    hw_ips = sorted({ip for _,ip in hw_hits})
    print(f"\n★华为云IP:{len(hw_ips)} 个唯一")
    for ip in hw_ips:
        samples = sorted({d for d,i in hw_hits if i==ip})
        print(f"  {ip}  <- {len(samples)}个样本: {', '.join(samples[:5])}{'...' if len(samples)>5 else ''}")
    if not hw_ips: print("  (暂无华为云IP)")

if __name__=="__main__":
    main()
