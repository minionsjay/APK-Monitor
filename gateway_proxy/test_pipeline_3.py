#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小跑:复用 fast_pipeline_pixel4 的真实函数,对3个样本跑完整换IP流程,不写真实DB。"""
import sys, os, time, subprocess, glob
sys.path.insert(0, "/home/ninini/Agents/APK-Research/scripts/monitor")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "fp", "/home/ninini/Agents/APK-Research/scripts/monitor/fast_pipeline_pixel4.py")
fp = importlib.util.module_from_spec(spec); spec.loader.exec_module(fp)

ADB = fp.ADB
# 过滤掉<1MB的空/失败下载,选正常大小里最小的3个
cand = [a for a in glob.glob(f"{fp.APK_DIR}/*.apk") if os.path.getsize(a) > 1_000_000]
APKS = sorted(cand, key=os.path.getsize)[:3]
print(f"ADB={ADB}  PROXY_ENABLED={fp.PROXY_ENABLED}  MAX_IP_RETRY={fp.MAX_IP_RETRY}")
print(f"测试样本: {[os.path.basename(a) for a in APKS]}\n")

print("=== 预热代理池 ===")
fp.proxy_refill()

for apk in APKS:
    name = os.path.basename(apk)
    print(f"\n===== {name} ({os.path.getsize(apk)//1024}KB) =====")
    score, pkg, label = fp.detect_apk(apk)
    if not pkg:
        print("  detect失败,跳过"); continue
    print(f"  包名: {pkg}  label={label} score={score}")

    subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
    r = subprocess.run(f'{ADB} install -r {apk}'.split(), capture_output=True, text=True, timeout=120)
    if 'Success' not in (r.stdout or ''):
        print(f"  安装失败: {r.stdout[:60]}"); continue
    print("  安装OK")

    nodes = []
    attempts = fp.MAX_IP_RETRY if fp.PROXY_ENABLED else 1
    for attempt in range(attempts):
        if fp.PROXY_ENABLED:
            newip = fp.rotate_proxy()
            print(f"  [尝试{attempt+1}] 出口IP={newip}", end='  ')
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                       capture_output=True, timeout=10)
        time.sleep(3); fp.click_popup()
        nodes = fp.get_proxy_nodes(pkg) or fp.get_proxy_nodes_via_proc(pkg)
        print(f"节点数={len(nodes)}")
        if nodes: break
        if fp.PROXY_ENABLED and attempt < attempts-1:
            subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell pm clear {pkg}'.split(), capture_output=True, timeout=15)
            print("  → 疑似限流,清数据换IP重试"); time.sleep(1)

    subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=5)
    subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
    print(f"  结果: {len(nodes)}个节点 {nodes[:5]}")

print("\n=== 拆隧道恢复 ===")
fp.proxy_down()
print("done")
