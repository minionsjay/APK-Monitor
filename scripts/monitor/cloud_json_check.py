#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""云手机批量检测 new_samples 能否拿到 sdk_forwarder_fixed.json
- 用 Windows adb.exe 驱动云手机(直连,能过C2反代理)
- 每个: 检测包名 -> 拷到Win盘 -> 安装 -> 起 -> poll json -> 记录 -> 卸
- 增量写 CSV,可断点续跑(重跑自动跳过已完成)
"""
import subprocess, os, time, re, csv, sys, shutil

WADB = "/mnt/c/Users/minions/AppData/Local/Android/Sdk/platform-tools/adb.exe"
DEV  = "127.0.0.1:62493"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
APK_DIR = "/home/ninini/Agents/APK-Research/new_samples"
WINTMP_WSL = "/mnt/e/Work/App-analyze/Apks/Duoyun-apks/tmp"
WINTMP_WIN = r"E:\Work\App-analyze\Apks\Duoyun-apks\tmp\t.apk"
OUT = "/home/ninini/Agents/APK-Research/data/cloud_json_results.csv"
POLL_MAX = 25   # 秒
FIELDS = ["domain","package","got_json","ip_count","port","ips","seconds"]

def adb(args, timeout=60):
    try:
        r = subprocess.run([WADB,"-s",DEV]+args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "")+(r.stderr or "")
    except Exception as e:
        return 1, str(e)

def detect_pkg(apk):
    try:
        r = subprocess.run([AAPT,"dump","badging",apk], capture_output=True, text=True, timeout=20)
        m = re.search(r"package: name='([^']+)'", r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

def read_json(pkg):
    jf = f"/sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json"
    _, out = adb(["shell", f"cat {jf} 2>/dev/null"], timeout=15)
    if out and out.strip().startswith("{"):
        ips = re.findall(r'"(\d{1,3}(?:\.\d{1,3}){3})"', out)
        port = ""
        pm = re.search(r'"app_line_port"\s*:\s*(\d+)', out)
        if pm: port = pm.group(1)
        return ips, port
    return [], ""

def load_done():
    done=set()
    if os.path.exists(OUT):
        for r in csv.DictReader(open(OUT)):
            done.add(r["domain"])
    return done

def main():
    os.makedirs(WINTMP_WSL, exist_ok=True)
    done = load_done()
    newfile = not os.path.exists(OUT)
    fout = open(OUT,"a",newline="")
    w = csv.DictWriter(fout, fieldnames=FIELDS)
    if newfile: w.writeheader(); fout.flush()

    apks = sorted(f for f in os.listdir(APK_DIR) if f.endswith(".apk")
                  and os.path.getsize(os.path.join(APK_DIR,f))>1_000_000)
    print(f"共 {len(apks)} 个有效APK,已完成 {len(done)},待测 {len(apks)-len(done)}", flush=True)
    n_ok=n_no=n_fail=0
    for i,af in enumerate(apks,1):
        domain = af[:-4]
        if domain in done: continue
        apk = os.path.join(APK_DIR, af)
        pkg = detect_pkg(apk)
        if not pkg:
            w.writerow({"domain":domain,"package":"","got_json":"detect_fail","ip_count":0,"port":"","ips":"","seconds":0}); fout.flush()
            n_fail+=1; print(f"[{i}] {domain} detect失败", flush=True); continue
        adb(["uninstall",pkg], timeout=30)
        try: shutil.copy(apk, os.path.join(WINTMP_WSL,"t.apk"))
        except Exception as e:
            print(f"[{i}] {domain} 拷贝失败{e}", flush=True); continue
        rc,out = adb(["install","-r",WINTMP_WIN], timeout=300)
        if "Success" not in out:
            # 设备掉线? 别记假失败(否则被当已完成跳过),直接停下等人重连
            if any(k in out for k in ("not found","offline","cannot connect","refused","closed","device unauthorized","protocol fault")):
                print(f"[{i}] {domain} 设备掉线({out.strip()[:60]}) —— 停止,勿记录。重连后重跑即可续。", flush=True)
                fout.close(); sys.exit(2)
            # 真实安装拒绝(存储不足/损坏等)才记 install_fail
            w.writerow({"domain":domain,"package":pkg,"got_json":"install_fail","ip_count":0,"port":"","ips":"","seconds":0}); fout.flush()
            n_fail+=1; print(f"[{i}] {domain} 装失败 {out.strip()[:50]}", flush=True); continue
        adb(["shell",f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1"], timeout=15)
        t0=time.time(); ips=[]; port=""
        while time.time()-t0 < POLL_MAX:
            time.sleep(5)
            ips,port = read_json(pkg)
            if ips: break
        secs=round(time.time()-t0,1)
        got = "yes" if ips else "no"
        w.writerow({"domain":domain,"package":pkg,"got_json":got,"ip_count":len(ips),"port":port,
                    "ips":";".join(ips),"seconds":secs}); fout.flush()
        adb(["shell",f"am force-stop {pkg}"], timeout=10)
        adb(["uninstall",pkg], timeout=30)
        if ips: n_ok+=1
        else: n_no+=1
        print(f"[{i}/{len(apks)}] {domain} -> json={got} {len(ips)}节点 {secs}s  (累计 ok={n_ok} no={n_no} fail={n_fail})", flush=True)
    fout.close()
    print(f"完成. ok={n_ok} no={n_no} fail={n_fail}", flush=True)

if __name__=="__main__":
    main()
