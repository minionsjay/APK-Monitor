#!/usr/bin/env python3
"""
按时间命名文件夹保存监控结果
每次运行创建 outputs/YYYYMMDD_HHMMSS/ 目录
"""

import subprocess, json, os, time, re
from datetime import datetime

ADB = "adb -s 192.168.1.16:38399"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
DB_PATH = "/home/ninini/Agents/APK-Research/data/proxy_monitor_db.json"
BASE_DIR = "/home/ninini/Agents/APK-Research"

# 按时间命名输出目录
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR = f"{BASE_DIR}/outputs/{ts}"
os.makedirs(OUT_DIR, exist_ok=True)

def get_cloud(ip):
    if ip.startswith('8.13') or ip.startswith('8.138') or ip.startswith('8.148') or ip.startswith('8.163'): return "阿里云"
    elif any(ip.startswith(p) for p in ['43.','42.','106.','159.75','139.','175.178','134.175','1.1','111.230','119.','123.207','129.204','193.112','115.175','139.9']): return "腾讯云"
    elif any(ip.startswith(p) for p in ['110.41','113.45','113.46','114.132','116.205','121.37','124.71']): return "华为云"
    return "未知"

# 已知的 APK 包名
KNOWN_PKGS = {
    'fhvbdg': 'ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc',
    'exdyfb': 'bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns',
    '0714': 'gjithpd.enjfpfakiubo.amkrrlirim',
    '718c257': 'ldp.swtacwpthqoe.cyfueitnswummxsjngda',
    '718xssp20': 'cii.gjjvikjqhhupaab.aaoknxedxpgnwa',
    '714cpk28': 'ldp.swtacwpthqoe.cyfueitnswummxsjngda',
    '720a275': 'cngjlbmff.evjkbhwcetabwgyw.chqnfkne',
    '720bh282': 'sgv.wdbijuhlemtbj.unvvkhfxfameqhldorq',
    '720pt1': 'ybp.kdxrbdjkfyfa.khdcpdgopxndqpbuyj',
    '721cpa5': 'jlu.clisymxohrsrbcw.otmxtcihooocbacdecuc',
    '721cpc06': 'ait.bwucaomsepjdbgy.dbpndjdbpunguop',
    '721yh118': 'oow.fufsegdrnlxs.obarucmklnbikqfiqyxr',
}

print(f"[{ts}] 监控运行开始")
print(f"输出目录: {OUT_DIR}")

results = []

for name, pkg in KNOWN_PKGS.items():
    print(f"\n--- {name} ---")
    
    # 启动 APP
    subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=5)
    subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                  capture_output=True, timeout=10)
    time.sleep(3)
    
    # 点击通知弹窗
    for _ in range(2):
        subprocess.run(f'{ADB} shell uiautomator dump /sdcard/ui.xml'.split(),
                     capture_output=True, timeout=10)
        subprocess.run(f'{ADB} pull /sdcard/ui.xml /tmp/ui_check.xml'.split(),
                     capture_output=True, timeout=5)
        try:
            with open('/tmp/ui_check.xml') as f:
                ui = f.read()
            matches = re.findall(r'text="(允许)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
            if matches:
                _, x1, y1, x2, y2 = matches[0]
                cx = (int(x1) + int(x2)) // 2
                cy = (int(y1) + int(y2)) // 2
                subprocess.run(f'{ADB} shell input tap {cx} {cy}'.split(),
                             capture_output=True, timeout=5)
                time.sleep(2)
                break
        except:
            break
    
    # 等待获取代理节点（每5秒检查，最多30秒）
    proxy_nodes = []
    for i in range(6):
        time.sleep(5)
        result = subprocess.run(f'{ADB} shell cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json'.split(),
                              capture_output=True, text=True, timeout=5)
        if result.stdout and result.stdout.strip().startswith('{'):
            try:
                data = json.loads(result.stdout)
                proxy_nodes = data.get('app_line_ips', [])
                if proxy_nodes:
                    break
            except:
                pass
    
    # 截图
    subprocess.run(f'{ADB} shell screencap -p /sdcard/shot.png'.split(),
                  capture_output=True, timeout=5)
    subprocess.run(f'{ADB} pull /sdcard/shot.png {OUT_DIR}/{name}.png'.split(),
                  capture_output=True, timeout=10)
    
    # force-stop
    subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(),
                  capture_output=True, timeout=5)
    
    hw_ips = [ip for ip in proxy_nodes if get_cloud(ip) == "华为云"]
    
    result = {
        'name': name,
        'package': pkg,
        'proxy_nodes': proxy_nodes,
        'proxy_count': len(proxy_nodes),
        'huawei_ips': hw_ips,
        'huawei_count': len(hw_ips),
        'timestamp': ts,
    }
    results.append(result)
    print(f"  代理节点: {len(proxy_nodes)}, 华为: {len(hw_ips)}")

# 保存结果到时间目录
with open(f'{OUT_DIR}/result.json', 'w') as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# 保存节点列表
with open(f'{OUT_DIR}/proxy_nodes.txt', 'w') as f:
    for r in results:
        for ip in r['proxy_nodes']:
            f.write(f"{ip}\n")

with open(f'{OUT_DIR}/huawei_ips.txt', 'w') as f:
    for r in results:
        for ip in r['huawei_ips']:
            f.write(f"{ip}\n")

# CSV
import csv
with open(f'{OUT_DIR}/nodes.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['APK', 'IP', '厂商', '是否华为'])
    for r in results:
        for ip in r['proxy_nodes']:
            cloud = get_cloud(ip)
            writer.writerow([r['name'], ip, cloud, '是' if cloud == '华为云' else '否'])

# 更新数据库
with open(DB_PATH) as f:
    db = json.load(f)

now = datetime.now().strftime('%Y-%m-%d %H:%M')
all_proxy = set(db.get('all_proxy_nodes', []))

for r in results:
    for apk in db['apks']:
        if apk['id'] == r['name']:
            apk['proxy_nodes'] = r['proxy_nodes']
            apk['proxy_count'] = r['proxy_count']
            apk['last_collected'] = now
            break
    for ip in r['proxy_nodes']:
        all_proxy.add(ip)

db['all_proxy_nodes'] = sorted(all_proxy)
with open(DB_PATH, 'w') as f:
    json.dump(db, f, indent=2, ensure_ascii=False)

total_proxy = sum(r['proxy_count'] for r in results)
total_hw = sum(r['huawei_count'] for r in results)
print(f"\n=== [{ts}] 监控完成 ===")
print(f"APK: {len(results)}, 代理节点: {total_proxy}, 华为: {total_hw}")
print(f"结果保存到: {OUT_DIR}/")

# 在 output 目录中也生成 HTML 报告
print(f"正在生成本次监控的 HTML 报告...")
subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py', OUT_DIR], timeout=60)
print(f"HTML 报告已生成: {OUT_DIR}/report.html")

# 同时更新主报告
subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py'], timeout=60)
print("主 HTML 报告已更新")
