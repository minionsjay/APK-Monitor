#!/usr/bin/env python3
import subprocess, json, os, time, re, csv, threading, queue
from datetime import datetime

ADB = "adb -s 192.168.1.16:39653"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
APK_DIR = f"{BASE_DIR}/new_samples"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db.json"
STATE_CSV = f"{BASE_DIR}/data/apk_state.csv"
DOMAIN_CSV_OLD = f"{BASE_DIR}/data/apk-domain.csv"
DOMAIN_CSV_NEW = f"{BASE_DIR}/data/apk-domain-260724.csv"
STORAGE_THRESHOLD_GB = 5
STATE_FIELDS = ['apk_id','package','label','score','size_mb','first_installed','last_monitored','proxy_count','huawei_count','installed_on_device','apk_path','domain','download_url','status','download_time','detect_time','install_time','node_time']
apk_queue = queue.Queue()
stats = {'installed':0, 'skipped':0, 'failed':0, 'total_install':0, 'total_node':0, 'downloaded':0}

def load_state():
    if not os.path.exists(STATE_CSV): return []
    with open(STATE_CSV, encoding='utf-8-sig') as f: return list(csv.DictReader(f))

def get_storage_gb():
    r = subprocess.run(f'{ADB} shell df /sdcard'.split(), capture_output=True, text=True, timeout=10)
    for line in r.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 4 and ('fuse' in line or '/storage' in line):
            try: return int(parts[3]) // 1024 // 1024
            except: continue
    return 999

def detect_apk(apk_path):
    r = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
    pkg = ''; label = ''
    for line in r.stdout.split('\n'):
        if line.startswith('package:') and "name='" in line: pkg = line.split("name='")[1].split("'")[0]
        if line.startswith('application-label:') and "'" in line: label = line.split("'")[1]
    score = 100 if pkg and len(pkg) > 8 else 0
    return score, pkg, label

def get_cloud(ip):
    first = ip.split('.')[0] if '.' in ip else '0'
    if first in ['8','39','47','59','60','101','106','118','120','121','122','123','139','140','150','152','153','159','175','182','183','184']: return "阿里云"
    elif first in ['49','81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96','97','98','99','100','103','111','112','113','114','115','116','117','119','128','129','130','131','132','133','134','135','136','137','138','141','142','143','144','145','146','147','148','149','150','151','154','155','156','157','158','159','160','161','162','163','164','165']: return "腾讯云"
    return "其他"

def get_proxy_nodes(pkg, max_wait=15):
    for i in range(max_wait // 5):
        time.sleep(5)
        r = subprocess.run(f'{ADB} shell su -c "cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json 2>/dev/null"', capture_output=True, text=True, timeout=5, shell=True)
        if r.stdout and r.stdout.strip().startswith('{'):
            try:
                data = json.loads(r.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes: return nodes
            except: pass
        r2 = subprocess.run(f'{ADB} shell cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json', capture_output=True, text=True, timeout=5, shell=True)
        if r2.stdout and r2.stdout.strip().startswith('{'):
            try:
                data = json.loads(r2.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes: return nodes
            except: pass
    return []

def get_proxy_nodes_via_proc(pkg, max_wait=15):
    all_nodes = set()
    for i in range(max_wait // 5):
        time.sleep(5)
        try:
            r = subprocess.run(f'{ADB} shell pidof {pkg}'.split(), capture_output=True, text=True, timeout=5)
            pid = r.stdout.strip()
            if not pid: continue
            r = subprocess.run(f'{ADB} shell cat /proc/{pid}/net/tcp'.split(), capture_output=True, text=True, timeout=5)
            for line in r.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) < 4: continue
                if parts[3] != "01": continue
                ip_hex, port_hex = parts[2].split(':')
                port = int(port_hex, 16)
                if port <= 100: continue
                if len(ip_hex) == 8:
                    b = bytes.fromhex(ip_hex)
                    ip = f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
                    if ip.startswith("127.") or ip.startswith("192.168."): continue
                    all_nodes.add(f"{ip}:{port}")
        except: pass
    return sorted(all_nodes) if all_nodes else []

def install_worker():
    while True:
        item = apk_queue.get()
        if item is None: break
        domain = item['domain']; pkg = item['package']; label = item['label']; apk_path = item['apk_path']
        print(f"  [I] {domain}({label})", end=' ', flush=True)
        if get_storage_gb() < STORAGE_THRESHOLD_GB:
            print(f'存储不足'); stats['skipped']+=1; continue
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
        t3 = time.time()
        try:
            r = subprocess.run(f'{ADB} install -r {apk_path}'.split(), capture_output=True, text=True, timeout=120)
            t_inst = time.time() - t3; stats['total_install'] += t_inst
            if 'Success' not in r.stdout:
                print(f'安装失败({t_inst:.1f}s)'); stats['failed']+=1; continue
        except: print('安装异常'); stats['failed']+=1; continue
        t4 = time.time()
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(), capture_output=True, timeout=10)
        time.sleep(3)
        nodes = get_proxy_nodes(pkg)
        if not nodes: nodes = get_proxy_nodes_via_proc(pkg)
        t_node = time.time() - t4; stats['total_node'] += t_node
        hw_ips = [ip for ip in nodes if get_cloud(ip.split(':')[0] if ':' in ip else ip) == "华为云"]
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=10)
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
        stats['installed']+=1
        print(f'安装{t_inst:.1f}s 节点{t_node:.1f}s -> {len(nodes)}节点 {len(hw_ips)}华为')

def main():
    state = load_state()
    existing_ids = {e['apk_id'] for e in state}
    existing_pkgs = {e.get('package','') for e in state if e.get('package')}
    all_apks = [f for f in os.listdir(APK_DIR) if f.endswith('.apk')]
    pending = []
    for apk_file in all_apks:
        domain = apk_file.replace('.apk', '')
        if domain in existing_ids: continue
        apk_path = os.path.join(APK_DIR, apk_file)
        if os.path.getsize(apk_path) < 1000000: continue
        score, pkg, label = detect_apk(apk_path)
        if score < 80: continue
        if pkg in existing_pkgs: continue
        pending.append({'domain': domain, 'apk_path': apk_path, 'package': pkg, 'label': label})
    print(f"=== 安装已下载APK ===")
    print(f"已下载APK: {len(all_apks)}")
    print(f"已处理: {len(existing_ids)}")
    print(f"待安装(已下载未处理): {len(pending)}")
    print(f"手机存储: {get_storage_gb()}GB")
    print(flush=True)
    it = threading.Thread(target=install_worker)
    it.start()
    t_start = time.time()
    for i, item in enumerate(pending):
        print(f"[A {i+1}/{len(pending)}] {item['domain']}", flush=True)
        apk_queue.put(item)
    print("=== 后台下载新域名 ===", flush=True)
    domains = []
    for csv_path in [DOMAIN_CSV_OLD, DOMAIN_CSV_NEW]:
        if os.path.exists(csv_path):
            with open(csv_path, encoding='utf-8-sig') as f:
                for row in csv.DictReader(f): domains.append(row)
    seen = set()
    unique_domains = []
    for d in domains:
        domain = d.get('pre_host','')
        if domain and domain not in seen and domain not in existing_ids:
            seen.add(domain)
            unique_domains.append(d)
    print(f"待下载域名: {len(unique_domains)}", flush=True)
    def download_thread():
        for i, d in enumerate(unique_domains):
            domain = d.get('pre_host','')
            if domain in existing_ids: continue
            print(f"[D {i+1}/{len(unique_domains)}] {domain}", end=' ', flush=True)
            try:
                url = d.get('max(prev)', f'https://{domain}/')
                r = subprocess.run(['curl','-sk','-L','--connect-timeout','6','-A','Mozilla/5.0',url], capture_output=True, text=True, timeout=10)
                html = r.stdout
                if not html or len(html) < 50: print('无响应'); continue
                urls = re.findall(r'android\s*:\s*"([^"]+)"', html)
                if not urls: urls = re.findall(r'androidUrl\s*:\s*"([^"]+)"', html)
                if not urls: print('无链接'); continue
                dl = urls[0]
                out_path = f'{APK_DIR}/{domain}.apk'
                if os.path.exists(out_path) and os.path.getsize(out_path) > 1000000: print('已存在'); continue
                subprocess.run(['curl','-sk','-L','--connect-timeout','15','-o',out_path,dl], capture_output=True, timeout=90)
                if os.path.exists(out_path) and os.path.getsize(out_path) > 1000000:
                    with open(out_path,'rb') as f:
                        if f.read(4) == b'PK\x03\x04':
                            score, pkg, label = detect_apk(out_path)
                            if score >= 80 and pkg not in existing_pkgs:
                                apk_queue.put({'domain':domain,'apk_path':out_path,'package':pkg,'label':label})
                                print(f'OK {label}'); stats['downloaded']+=1
                            else: print(f'跳过')
                        else: print('非APK')
                else: print('下载失败')
            except: print('异常')
    dt = threading.Thread(target=download_thread)
    dt.start()
    apk_queue.put(None)
    it.join()
    dt.join()
    elapsed = time.time() - t_start
    n = stats['installed'] if stats['installed'] > 0 else 1
    print(f"\n=== 完成 ===")
    print(f"总耗时: {elapsed/60:.1f}分钟")
    print(f"安装: {stats['installed']} 跳过: {stats['skipped']} 失败: {stats['failed']}")
    print(f"新下载: {stats['downloaded']}")
    print(f"平均安装: {stats['total_install']/n:.1f}s 节点: {stats['total_node']/n:.1f}s")

if __name__ == '__main__':
    main()
