#!/usr/bin/env python3
"""
Pixel 4 流水线 v5 — 260728域名
- 从xlsx提取的CSV读取域名
- 下载APK到 E:\Work\App-analyze\Apks\Duoyun-apks\20260728\apks\
- 安装到Pixel 4 (root)
- 每个APK创建文件夹保存: 抓包(pcap), sdk_cache, sdk_forwarder_fixed.json, uuid, .dat
- 总节点IP保存到 nodes/
- HTML报告保存到 results/ (每次更新)
- 新华为IP告警+推送GitHub
"""
import subprocess, json, os, time, re, csv, zipfile, hashlib, threading, queue, shutil
from datetime import datetime

ADB = "adb -s 192.168.1.16:38997"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
WIN_BASE = "/mnt/e/Work/App-analyze/Apks/Duoyun-apks/20260728"
APK_DIR = f"{WIN_BASE}/apks"
RESULTS_DIR = f"{WIN_BASE}/results"
NODES_DIR = f"{WIN_BASE}/nodes"
DOMAIN_CSV = f"{WIN_BASE}/apk-domain-260728.csv"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db_260728.json"
STATE_CSV = f"{BASE_DIR}/data/apk_state_260728.csv"
IP_HISTORY = f"{BASE_DIR}/data/ip_history_260728.json"
STORAGE_THRESHOLD_GB = 5
STATE_FIELDS = ['apk_id','package','label','score','size_mb','first_installed','last_monitored','proxy_count','huawei_count','installed_on_device','apk_path','domain','download_url','status','download_time','detect_time','install_time','node_time']

apk_queue = queue.Queue()
stats = {'installed':0, 'skipped':0, 'failed':0, 'total_install':0, 'total_node':0, 'downloaded':0, 'total_dl':0, 'total_detect':0}
current_run_details = []
state_lock = threading.Lock()

def load_json(path):
    if not os.path.exists(path): return {}
    with open(path) as f: return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f: json.dump(data, f, indent=2, ensure_ascii=False)

def load_state():
    if not os.path.exists(STATE_CSV): return []
    with open(STATE_CSV, encoding='utf-8-sig') as f: return list(csv.DictReader(f))

def save_state(state):
    with open(STATE_CSV, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=STATE_FIELDS)
        writer.writeheader()
        writer.writerows(state)

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
    ip = ip.split(':')[0] if ':' in ip else ip
    if any(ip.startswith(p) for p in ['8.13','8.138','8.148','8.163','39.','47.']): return "阿里云"
    elif any(ip.startswith(p) for p in ['43.','42.','106.','114.132','159.75','139.','175.178','134.175','1.1','111.230','119.','123.207','129.204','193.112','115.175','1.14','1.202']): return "腾讯云"
    elif any(ip.startswith(p) for p in ['110.41','113.45','113.46','116.205','121.37','124.71']): return "华为云"
    return "其他"

def get_proxy_nodes(pkg, max_wait=60):
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

def get_proxy_nodes_via_proc(pkg, max_wait=30):
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
                    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("172.217.") or ip.startswith("142.250.") or ip.startswith("10."): continue
                    all_nodes.add(f"{ip}:{port}")
        except: pass
    return sorted(all_nodes) if all_nodes else []

def extract_icon(apk_path, apk_id):
    """从APK提取图标"""
    try:
        result = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
        icon_path = None
        for line in result.stdout.split('\n'):
            if 'application-icon-640' in line:
                m = re.search(r"'([^']+)'"  , line)
                if m: icon_path = m.group(1); break
        with zipfile.ZipFile(apk_path) as zf:
            webps = [(n, zf.getinfo(n).file_size) for n in zf.namelist() if n.endswith('.webp')]
            if not webps:
                pngs = [(n, zf.getinfo(n).file_size) for n in zf.namelist() if n.endswith('.png') and 'res/' in n]
                if pngs:
                    pngs.sort(key=lambda x: x[1], reverse=True)
                    data = zf.read(pngs[0][0])
                else: return None
            else:
                found = False
                if icon_path:
                    path_parts = icon_path.replace('\\','/').split('/')
                    last_part = path_parts[-1] if path_parts else ''
                    for name, size in webps:
                        name_parts = name.replace('\\','/').split('/')
                        if last_part and name_parts[-1] == last_part:
                            data = zf.read(name); found = True; break
                if not found:
                    webps.sort(key=lambda x: x[1], reverse=True)
                    data = zf.read(webps[0][0])
            icon_file = f'{BASE_DIR}/screenshots/icons/{apk_id}.png'
            os.makedirs(os.path.dirname(icon_file), exist_ok=True)
            with open(icon_file, 'wb') as f: f.write(data)
            return icon_file
    except: return None

def screenshot(apk_id, pkg):
    """截图"""
    try:
        subprocess.run(f'{ADB} shell screencap -p /sdcard/shot.png'.split(), capture_output=True, timeout=5)
        shot_path = f'{BASE_DIR}/screenshots/{apk_id}.png'
        subprocess.run(f'{ADB} pull /sdcard/shot.png {shot_path}'.split(), capture_output=True, timeout=10)
        return shot_path if os.path.exists(shot_path) else None
    except: return None

def collect_apk_artifacts(pkg, domain):
    """收集APK的sdk_cache, sdk_forwarder_fixed, uuid, .dat文件"""
    apk_artifact_dir = f"{APK_DIR}/{domain}"
    os.makedirs(apk_artifact_dir, exist_ok=True)
    device_files_dir = f"/sdcard/Android/data/{pkg}/files"
    
    # 1. sdk_forwarder_fixed.json
    try:
        r = subprocess.run(f'{ADB} shell su -c "cat {device_files_dir}/sdk_forwarder_fixed.json 2>/dev/null"', capture_output=True, timeout=5, shell=True)
        if r.stdout and r.stdout.strip().startswith(b'{' if isinstance(r.stdout, bytes) else '{'):
            with open(f"{apk_artifact_dir}/sdk_forwarder_fixed.json", 'w') as f:
                f.write(r.stdout.decode('utf-8', errors='replace') if isinstance(r.stdout, bytes) else r.stdout)
    except: pass
    
    # 2. sdk_cache.json + .dat payload
    try:
        r = subprocess.run(f'{ADB} shell su -c "cat {device_files_dir}/sdk_cache.json 2>/dev/null"', capture_output=True, timeout=5, shell=True)
        if r.stdout:
            txt = r.stdout.decode('utf-8', errors='replace') if isinstance(r.stdout, bytes) else r.stdout
            if txt.strip().startswith('{'):
                cache_data = json.loads(txt)
                with open(f"{apk_artifact_dir}/sdk_cache.json", 'w') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
                # 提取.dat payload_b64
                entries = cache_data if isinstance(cache_data, list) else cache_data.get('entries', [])
                if isinstance(entries, dict): entries = list(entries.values())
                for entry in (entries if isinstance(entries, list) else []):
                    if isinstance(entry, dict) and entry.get('payload_b64'):
                        url = entry.get('url', 'unknown')
                        dat_name = url.split('/')[-1] if '/' in url else 'payload.dat'
                        import base64
                        try:
                            with open(f"{apk_artifact_dir}/{dat_name}", 'wb') as f:
                                f.write(base64.b64decode(entry['payload_b64']))
                        except: pass
    except: pass
    
    # 3. uuid
    try:
        r = subprocess.run(f'{ADB} shell su -c "cat {device_files_dir}/sdk_device_uuid.txt 2>/dev/null"', capture_output=True, timeout=5, shell=True)
        if r.stdout:
            with open(f"{apk_artifact_dir}/uuid.txt", 'w') as f:
                f.write(r.stdout.decode('utf-8', errors='replace') if isinstance(r.stdout, bytes) else r.stdout)
    except: pass

def download_worker(domains):
    existing_ids = {e['apk_id'] for e in load_state()}
    existing_pkgs = {e.get('package','') for e in load_state() if e.get('package')}
    
    # 先预加载已下载的APK
    if os.path.exists(APK_DIR):
        for apk_file in os.listdir(APK_DIR):
            if not apk_file.endswith('.apk'): continue
            domain = apk_file.replace('.apk', '')
            if domain in existing_ids: continue
            apk_path = os.path.join(APK_DIR, apk_file)
            if os.path.getsize(apk_path) < 1000000: continue
            score, pkg, label = detect_apk(apk_path)
            if score < 80 or pkg in existing_pkgs: continue
            apk_queue.put({'domain':domain,'url':'','apk_path':apk_path,'score':score,'package':pkg,'label':label,'size_mb':os.path.getsize(apk_path)//1024//1024,'download_time':0,'detect_time':0})
    
    for i, domain in enumerate(domains):
        if domain in existing_ids: continue
        print(f"[D {i+1}/{len(domains)}] {domain}", end=' ', flush=True)
        try:
            url = f'https://{domain}/'
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
                            apk_queue.put({'domain':domain,'url':url,'apk_path':out_path,'score':score,'package':pkg,'label':label,'size_mb':os.path.getsize(out_path)//1024//1024,'download_time':0,'detect_time':0})
                            print(f'OK {label}'); stats['downloaded']+=1
                        else: print('跳过')
                    else: print('非APK')
            else: print('下载失败')
        except: print('异常')
    # 等待安装队列处理完所有已下载的APK
    while not apk_queue.empty():
        time.sleep(5)
    apk_queue.put(None)

def install_worker():
    state = load_state()
    existing_ids = {e['apk_id'] for e in state}
    existing_pkgs = {e.get('package','') for e in state if e.get('package')}
    db = load_json(DB_PATH)
    if 'apks' not in db: db['apks'] = []
    if 'all_proxy_nodes' not in db: db['all_proxy_nodes'] = []
    all_proxy = set(db.get('all_proxy_nodes', []))
    
    while True:
        item = apk_queue.get()
        if item is None: break
        domain = item['domain']; pkg = item['package']; label = item['label']; apk_path = item['apk_path']
        print(f"  [I] {domain}({label})", end=' ', flush=True)
        if get_storage_gb() < STORAGE_THRESHOLD_GB:
            print('存储不足'); stats['skipped']+=1; continue
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
        # 设置adb reverse + iptables(排除shell/root,其他全DNAT到mihomo)
        try:
            subprocess.run(f'{ADB} reverse tcp:7890 tcp:7890'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1001 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 0 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 38997 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p udp --dport 53 -j RETURN"'.split(), capture_output=True, timeout=5)
            subprocess.run(f'{ADB} shell su -c "iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:7890"'.split(), capture_output=True, timeout=5)
        except: pass
        # 获取节点: 重试3次
        nodes = []
        for retry in range(3):
            if retry > 0:
                subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=10)
                time.sleep(2)
                subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(), capture_output=True, timeout=10)
                time.sleep(3)
            nodes = get_proxy_nodes(pkg)
            if nodes:
                no_port = [ip for ip in nodes if ':' not in ip]
                if no_port:
                    break
                elif retry == 2:
                    break
        if not nodes:
            nodes = get_proxy_nodes_via_proc(pkg)
        t_node = time.time() - t4; stats['total_node'] += t_node
        hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]
        
        # 收集APK artifacts (抓包/sdk_cache/sdk_forwarder/uuid/.dat)
        collect_apk_artifacts(pkg, domain)
        
        # 截图 + 提取图标
        screenshot(domain, pkg)
        extract_icon(apk_path, domain)

        # 清除iptables + force-stop + uninstall
        subprocess.run(f'{ADB} shell su -c "iptables -t nat -F OUTPUT"'.split(), capture_output=True, timeout=5)
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(), capture_output=True, timeout=10)
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
        stats['installed']+=1
        
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        entry = {'apk_id':domain,'package':pkg,'label':label,'score':str(item['score']),'size_mb':str(item['size_mb']),'first_installed':now,'last_monitored':now,'proxy_count':str(len(nodes)),'huawei_count':str(len(hw_ips)),'installed_on_device':'false','apk_path':apk_path,'domain':domain,'download_url':item['url'],'status':'ok' if nodes else 'no_nodes','download_time':'0.0','detect_time':'0.0','install_time':f'{t_inst:.1f}','node_time':f'{t_node:.1f}'}
        with state_lock:
            state.append(entry); existing_ids.add(domain); existing_pkgs.add(pkg)
            save_state(state)
            db['apks'].append({'id':domain,'package':pkg,'label':label,'app_name':'','app_domain_port':'','proxy_nodes':nodes,'proxy_count':len(nodes),'first_seen':now,'last_collected':now})
            for ip in nodes: all_proxy.add(ip)
            db['all_proxy_nodes'] = sorted(all_proxy)
            save_json(DB_PATH, db)
            # 保存总节点IP到nodes/
            with open(f"{NODES_DIR}/all_nodes.txt", 'w') as f:
                for ip in sorted(all_proxy): f.write(ip + ' [' + get_cloud(ip) + ']\n')
            hw_list = [ip for ip in all_proxy if get_cloud(ip) == "华为云"]
            with open(f"{NODES_DIR}/huawei_nodes.txt", 'w') as f:
                for ip in sorted(hw_list): f.write(ip + '\n')
            current_run_details.append({'domain':domain,'label':label,'package':pkg,'nodes':nodes,'hw_ips':hw_ips,'install_time':t_inst,'node_time':t_node})
        print(f'安装{t_inst:.1f}s 节点{t_node:.1f}s -> {len(nodes)}节点 {len(hw_ips)}华为', flush=True)
        # 每次安装1个就生成报告
        generate_report(db, all_proxy)

def generate_report(db, all_proxy):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    changes = compute_ip_changes(db, all_proxy)
    history = load_json(IP_HISTORY)
    history[ts] = changes
    save_json(IP_HISTORY, history)
    
    # 写run_result.json到results/
    run_result = {'timestamp': ts, 'stats': stats, 'apk_details': current_run_details, 'ip_changes': changes}
    save_json(f'{RESULTS_DIR}/run_result.json', run_result)
    
    # 写旧格式result.json到results/时间戳/
    ts_dir = f'{RESULTS_DIR}/{ts}'
    os.makedirs(ts_dir, exist_ok=True)
    old_format = []
    for a in db.get('apks', []):
        nodes = a.get('proxy_nodes', [])
        hw = [ip for ip in nodes if get_cloud(ip) == "华为云"]
        old_format.append({'name': a.get('label', a.get('id','')), 'package': a.get('package',''), 'proxy_nodes': nodes, 'proxy_count': len(nodes), 'huawei_count': len(hw)})
    save_json(f'{ts_dir}/result.json', old_format)
    
    # 新华为IP告警
    old_hw_path = '/tmp/old_hw_ips.json'
    if os.path.exists(old_hw_path):
        with open(old_hw_path) as f: old_hw = set(json.load(f))
        new_hw = {ip for ip in all_proxy if get_cloud(ip) == "华为云"} - old_hw
        if new_hw:
            print("*** 告警! 发现" + str(len(new_hw)) + "个新华为IP! ***")
            for ip in sorted(new_hw): print("  新华为IP: " + ip)
            # 写告警文件
            with open(f"{NODES_DIR}/new_huawei_alert.txt", 'a') as f:
                f.write(f"[{ts}] 新华为IP: {', '.join(sorted(new_hw))}\n")
    
    # 用独立脚本生成HTML(只包含今天检测的APK)
    try:
        subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html_260728.py'], capture_output=True, timeout=60)
    except Exception as e:
        print(f'HTML生成失败: {e}')
    
    print(f"IP: {changes['total_current']}节点 {changes['total_huawei_current']}华为", flush=True)
    
    # git push
    try:
        subprocess.run(['git', 'add', '-A'], cwd=BASE_DIR, capture_output=True, timeout=30)
        subprocess.run(['git', 'commit', '-m', f'260728更新: {stats["installed"]}APK, {changes["total_current"]}节点, {changes["total_huawei_current"]}华为'], cwd=BASE_DIR, capture_output=True, timeout=30)
        env = os.environ.copy(); env['GIT_SSH_COMMAND'] = 'ssh -o ConnectTimeout=15'
        subprocess.run(['git', 'push', 'origin', 'main'], cwd=BASE_DIR, capture_output=True, timeout=60, env=env)
    except: pass

def generate_html(db, all_proxy):
    """生成独立HTML报告,只包含今天检测的APK"""
    apks = db.get('apks', [])
    hw_ips = [ip for ip in all_proxy if get_cloud(ip) == '华为云']
    ali_ips = [ip for ip in all_proxy if get_cloud(ip) == '阿里云']
    tencent_ips = [ip for ip in all_proxy if get_cloud(ip) == '腾讯云']
    other_ips = [ip for ip in all_proxy if get_cloud(ip) not in ('华为云','阿里云','腾讯云')]
    has_nodes = [a for a in apks if a.get('proxy_count',0) > 0]
    
    parts = []
    parts.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>260728 APK检测报告</title>')
    parts.append('<style>body{font-family:sans-serif;margin:20px;background:#f5f5f5}h1{color:#333;border-bottom:3px solid #e74c3c;padding-bottom:10px}h2{color:#2c3e50;border-left:4px solid #3498db;padding-left:10px}table{border-collapse:collapse;width:100%;margin:10px 0;background:white;box-shadow:0 1px 3px rgba(0,0,0,.1)}th{background:#2c3e50;color:white;padding:10px;text-align:left}td{padding:8px;border-bottom:1px solid #ddd}tr:hover{background:#f0f0f0}.stat-card{background:white;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,.1);display:inline-block;margin:5px;text-align:center;min-width:120px}.stat-number{font-size:2em;font-weight:bold;color:#2c3e50}.tag{display:inline-block;padding:3px 10px;border-radius:3px;font-size:13px;margin:1px}.tag-huawei{background:#e60012;color:white}.tag-aliyun{background:#ff6600;color:white}.tag-tencent{background:#00a4ef;color:white}.tag-unknown{background:#95a5a6;color:white}</style></head><body>')
    parts.append(f'<h1>260728 APK检测报告</h1>')
    parts.append(f'<p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
    parts.append(f'<div><div class="stat-card"><div class="stat-number">{len(apks)}</div>APK总数</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(has_nodes)}</div>有节点</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(all_proxy)}</div>总节点IP</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(hw_ips)}</div>华为云IP</div></div>')
    
    parts.append('<h2>APK信息与网络请求详情</h2>')
    parts.append('<table><tr><th>APP名称</th><th>包名</th><th>域名</th><th>节点数</th><th>华为数</th><th>节点IP列表</th></tr>')
    for a in apks:
        nodes = a.get('proxy_nodes', [])
        hw = [ip for ip in nodes if get_cloud(ip) == '华为云']
        label = a.get('label', a.get('id',''))
        domain = a.get('id','')
        pkg = a.get('package','')
        ip_tags = ' '.join(['<span class="tag tag-' + ('huawei' if get_cloud(ip)=='华为云' else 'aliyun' if get_cloud(ip)=='阿里云' else 'tencent' if get_cloud(ip)=='腾讯云' else 'unknown') + '">' + ip + '</span>' for ip in nodes[:20]])
        parts.append(f'<tr><td><strong>{label}</strong></td><td>{pkg}</td><td>{domain}</td><td>{len(nodes)}</td><td>{len(hw)}</td><td>{ip_tags}</td></tr>')
    parts.append('</table>')
    
    parts.append('<h2>华为云IP列表</h2>')
    for ip in sorted(hw_ips):
        apks_with = [a.get('label','?') for a in apks if ip in a.get('proxy_nodes',[])]
        apks_str = ', '.join(apks_with[:3])
        parts.append('<div><span class="tag tag-huawei">' + ip + '</span> (' + str(len(apks_with)) + '个APK) ' + apks_str + '</div>')
    
    parts.append(f'<h2>IP分布</h2>')
    parts.append(f'<p>阿里云: {len(ali_ips)} | 腾讯云: {len(tencent_ips)} | 华为云: {len(hw_ips)} | 其他: {len(other_ips)}</p>')
    
    parts.append('</body></html>')
    return ''.join(parts)

def compute_ip_changes(db, all_proxy):
    current_ips = set(all_proxy)
    history = load_json(IP_HISTORY)
    timestamps = sorted(history.keys()) if history else []
    prev_ips = set(history[timestamps[-1]]['all_proxy']) if timestamps else set()
    new_ips = current_ips - prev_ips
    removed_ips = prev_ips - current_ips
    unchanged = current_ips & prev_ips
    current_hw = {ip for ip in current_ips if get_cloud(ip) == "华为云"}
    prev_hw = {ip for ip in prev_ips if get_cloud(ip) == "华为云"}
    new_hw = current_hw - prev_hw
    removed_hw = prev_hw - current_hw
    return {'new_proxy': sorted(new_ips), 'removed_proxy': sorted(removed_ips), 'unchanged_proxy': sorted(unchanged), 'new_huawei': sorted(new_hw), 'removed_huawei': sorted(removed_hw), 'total_current': len(current_ips), 'total_previous': len(prev_ips), 'total_huawei_current': len(current_hw), 'total_huawei_previous': len(prev_hw), 'all_proxy': sorted(current_ips)}

def main():
    # 读取域名
    domains = []
    with open(DOMAIN_CSV, encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            d = row.get('pre_host','').strip()
            if d: domains.append(d)
    
    os.makedirs(APK_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(NODES_DIR, exist_ok=True)
    
    state = load_state()
    print(f"=== Pixel 4 流水线 v5 (260728) ===")
    print(f"域名总数: {len(domains)}")
    print(f"已处理: {len(state)}")
    print(f"待处理: {len(domains) - len(state)}")
    print(f"手机存储: {get_storage_gb()}GB")
    print(f"APK目录: {APK_DIR}")
    print(f"结果目录: {RESULTS_DIR}")
    print(f"节点目录: {NODES_DIR}")
    print(flush=True)
    
    t_start = time.time()
    dt = threading.Thread(target=download_worker, args=(domains,))
    it = threading.Thread(target=install_worker)
    dt.start(); it.start()
    dt.join(); it.join()
    
    # 最终报告
    db = load_json(DB_PATH)
    all_proxy = set(db.get('all_proxy_nodes', []))
    generate_report(db, all_proxy)
    
    elapsed = time.time() - t_start
    n = stats['installed'] if stats['installed'] > 0 else 1
    print(f"\n=== 完成 ===")
    print(f"总耗时: {elapsed/60:.1f}分钟")
    print(f"下载: {stats['downloaded']} 安装: {stats['installed']} 跳过: {stats['skipped']} 失败: {stats['failed']}")

if __name__ == '__main__':
    main()
