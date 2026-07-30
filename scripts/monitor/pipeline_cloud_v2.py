#!/usr/bin/env python3
"""云手机流水线v2 — 批量传APK到设备,本地安装,减少传输时间
"""
import subprocess, json, os, time, re, csv, zipfile, base64, threading, queue, shutil
from datetime import datetime
from PIL import Image
import io

ADB = "/mnt/c/Users/minions/AppData/Local/Android/Sdk/platform-tools/adb.exe"
ADB_DEVICE = "127.0.0.1:53610"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
WIN_BASE = "/mnt/e/Work/App-analyze/Apks/Duoyun-apks/20260728"
APK_DIR = f"{WIN_BASE}/apks"
RESULTS_DIR = f"{WIN_BASE}/results"
NODES_DIR = f"{WIN_BASE}/nodes"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db_cloud.json"
STATE_CSV = f"{BASE_DIR}/data/apk_state_cloud.csv"
IP_HISTORY = f"{BASE_DIR}/data/ip_history_cloud.json"
BATCH_SIZE = 10  # 每批传10个APK
DEVICE_APK_DIR = "/data/local/tmp/apks"  # 云手机上的APK临时目录
STATE_FIELDS = ['apk_id','package','label','score','size_mb','first_installed','last_monitored','proxy_count','huawei_count','installed_on_device','apk_path','domain','download_url','status','download_time','detect_time','install_time','node_time']

stats = {'installed':0, 'skipped':0, 'failed':0, 'total_install':0, 'total_node':0}
current_run_details = []
state_lock = threading.Lock()

def run_adb(cmd_list, timeout=30):
    full = [ADB, '-s', ADB_DEVICE] + cmd_list
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except: 
        return subprocess.run(['echo',''], capture_output=True, text=True, timeout=1)

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
        writer.writeheader(); writer.writerows(state)

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
    elif any(ip.startswith(p) for p in ['43.','42.','106.','114.132','139.','111.230','119.','123.207','1.14','1.202','159.75','175.178']): return "腾讯云"
    elif any(ip.startswith(p) for p in ['110.41','113.45','113.46','116.205','121.37','124.71']): return "华为云"
    return "未知"

def get_proxy_nodes(pkg, max_wait=60):
    for i in range(max_wait // 10):
        time.sleep(10)
        r = run_adb(['shell', f'cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json 2>/dev/null'], timeout=5)
        if r.stdout and r.stdout.strip().startswith('{'):
            try:
                data = json.loads(r.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes: return nodes
            except: pass
    return []

def get_proxy_nodes_via_proc(pkg, max_wait=30):
    all_nodes = set()
    for i in range(max_wait // 10):
        time.sleep(10)
        try:
            r = run_adb(['shell', f'pidof {pkg}'], timeout=5)
            pid = r.stdout.strip()
            if not pid: continue
            r = run_adb(['shell', f'cat /proc/{pid}/net/tcp'], timeout=5)
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
                    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("172.217.") or ip.startswith("142.250."): continue
                    all_nodes.add(f"{ip}:{port}")
        except: pass
    return sorted(all_nodes) if all_nodes else []

def collect_artifacts(pkg, domain):
    apk_dir = f"{APK_DIR}/{domain}"
    os.makedirs(apk_dir, exist_ok=True)
    files_dir = f"/sdcard/Android/data/{pkg}/files"
    # sdk_forwarder_fixed.json
    r = run_adb(['shell', f'cat {files_dir}/sdk_forwarder_fixed.json 2>/dev/null'], timeout=5)
    if r.stdout and r.stdout.strip().startswith('{'):
        with open(f"{apk_dir}/sdk_forwarder_fixed.json", 'w') as f: f.write(r.stdout)
    # sdk_cache.json + .dat
    r = run_adb(['shell', f'cat {files_dir}/sdk_cache.json 2>/dev/null'], timeout=5)
    if r.stdout and r.stdout.strip().startswith('{'):
        try:
            cache = json.loads(r.stdout)
            with open(f"{apk_dir}/sdk_cache.json", 'w') as f: json.dump(cache, f, indent=2, ensure_ascii=False)
            entries = cache if isinstance(cache, list) else cache.get('entries', [])
            if isinstance(entries, dict): entries = list(entries.values())
            for entry in (entries if isinstance(entries, list) else []):
                if isinstance(entry, dict) and entry.get('payload_b64'):
                    url = entry.get('url', 'unknown')
                    dat_name = url.split('/')[-1] if '/' in url else 'payload.dat'
                    try:
                        with open(f"{apk_dir}/{dat_name}", 'wb') as f: f.write(base64.b64decode(entry['payload_b64']))
                    except: pass
        except: pass
    # uuid
    r = run_adb(['shell', f'cat {files_dir}/sdk_device_uuid.txt 2>/dev/null'], timeout=5)
    if r.stdout:
        with open(f"{apk_dir}/uuid.txt", 'w') as f: f.write(r.stdout)

def screenshot(domain, pkg):
    try:
        run_adb(['shell', 'screencap', '-p', '/sdcard/shot.png'], timeout=5)
        shot_path = f'{BASE_DIR}/screenshots/{domain}.png'
        os.makedirs(os.path.dirname(shot_path), exist_ok=True)
        subprocess.run([ADB, '-s', ADB_DEVICE, 'pull', '/sdcard/shot.png', shot_path], capture_output=True, timeout=10)
    except: pass

def extract_icon(apk_path, apk_id):
    try:
        result = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
        icon_path = None
        for line in result.stdout.split('\n'):
            if 'application-icon-640' in line:
                m = re.search(r"'([^']+)'", line)
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
                webps.sort(key=lambda x: x[1], reverse=True)
                data = zf.read(webps[0][0])
            icon_file = f'{BASE_DIR}/screenshots/icons/{apk_id}.png'
            os.makedirs(os.path.dirname(icon_file), exist_ok=True)
            with open(icon_file, 'wb') as f: f.write(data)
    except: pass

def push_batch_to_device(apk_list):
    """批量推送APK到云手机设备"""
    # 先清除旧APK
    run_adb(['shell', f'rm -rf {DEVICE_APK_DIR}'], timeout=10)
    run_adb(['shell', f'mkdir -p {DEVICE_APK_DIR}'], timeout=5)
    for apk_path, domain in apk_list:
        win_path = apk_path.replace('/mnt/e/', 'E:\\').replace('/mnt/c/', 'C:\\').replace('/', '\\')
        device_path = f"{DEVICE_APK_DIR}/{domain}.apk"
        r = subprocess.run([ADB, '-s', ADB_DEVICE, 'push', win_path, device_path], capture_output=True, timeout=300)
        if r.returncode != 0:
            print(f"  push失败: {domain}", flush=True)
            return False
    return True

def install_from_device(domain, pkg, label, apk_path, item):
    """从设备本地安装APK"""
    device_apk = f"{DEVICE_APK_DIR}/{domain}.apk"
    t3 = time.time()
    r = run_adb(['install', '-r', device_apk], timeout=120)
    t_inst = time.time() - t3
    stats['total_install'] += t_inst
    if 'Success' not in r.stdout:
        print(f'安装失败({t_inst:.1f}s)', flush=True)
        stats['failed'] += 1
        return False, 0, 0
    t4 = time.time()
    run_adb(['shell', f'monkey -p {pkg} -c android.intent.category.LAUNCHER 1'], timeout=10)
    time.sleep(3)
    # 获取节点(重试2次)
    nodes = []
    for retry in range(2):
        if retry > 0:
            run_adb(['shell', f'am force-stop {pkg}'], timeout=10)
            time.sleep(2)
            run_adb(['shell', f'monkey -p {pkg} -c android.intent.category.LAUNCHER 1'], timeout=10)
            time.sleep(3)
        nodes = get_proxy_nodes(pkg)
        if nodes: break
    if not nodes:
        nodes = get_proxy_nodes_via_proc(pkg)
    t_node = time.time() - t4
    stats['total_node'] += t_node
    hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]
    # 收集artifacts
    collect_artifacts(pkg, domain)
    screenshot(domain, pkg)
    extract_icon(apk_path, domain)
    # 删除设备APK(释放空间)
    run_adb(['shell', f'rm {device_apk}'], timeout=5)
    # force-stop + uninstall
    run_adb(['shell', f'am force-stop {pkg}'], timeout=10)
    run_adb(['uninstall', pkg], timeout=30)
    stats['installed'] += 1
    print(f'安装{t_inst:.1f}s 节点{t_node:.1f}s -> {len(nodes)}节点 {len(hw_ips)}华为', flush=True)
    return True, t_inst, t_node

def get_pending_apks():
    """获取待安装的APK列表"""
    state = load_state()
    existing_ids = {e['apk_id'] for e in state}
    all_apks = []
    for f in os.listdir(APK_DIR):
        if not f.endswith('.apk'): continue
        domain = f.replace('.apk', '')
        if domain in existing_ids: continue
        apk_path = os.path.join(APK_DIR, f)
        if os.path.getsize(apk_path) < 1000000: continue
        score, pkg, label = detect_apk(apk_path)
        if score < 80: continue
        all_apks.append((apk_path, domain, score, pkg, label))
    return all_apks, existing_ids

def generate_html(db, all_proxy):
    def img_b64(path, max_size=200):
        if not os.path.exists(path): return ""
        img = Image.open(path); w,h = img.size; ratio = max_size/max(w,h)
        if ratio<1: img = img.resize((int(w*ratio),int(h*ratio)))
        buf = io.BytesIO(); img.save(buf,format='PNG'); return base64.b64encode(buf.getvalue()).decode()
    apks = db.get('apks', [])
    hw_ips = [ip for ip in all_proxy if get_cloud(ip) == "华为云"]
    ali_ips = [ip for ip in all_proxy if get_cloud(ip) == "阿里云"]
    tencent_ips = [ip for ip in all_proxy if get_cloud(ip) == "腾讯云"]
    other_ips = [ip for ip in all_proxy if get_cloud(ip) not in ("华为云","阿里云","腾讯云")]
    has_nodes = [a for a in apks if a.get('proxy_count',0) > 0]
    parts = []
    parts.append('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>云手机APK检测报告</title>')
    parts.append('<style>body{font-family:sans-serif;margin:20px;background:#f5f5f5}h1{color:#333;border-bottom:3px solid #e74c3c;padding-bottom:10px}h2{color:#2c3e50;border-left:4px solid #3498db;padding-left:10px;margin-top:30px}table{border-collapse:collapse;width:100%;margin:10px 0;background:white;box-shadow:0 1px 3px rgba(0,0,0,.1)}th{background:#2c3e50;color:white;padding:10px;text-align:left}td{padding:8px;border-bottom:1px solid #ddd}tr:hover{background:#f0f0f0}.tag{display:inline-block;padding:3px 10px;border-radius:3px;font-size:13px;margin:1px}.tag-aliyun{background:#ff6600;color:white}.tag-tencent{background:#00a4ef;color:white}.tag-huawei{background:#e60012;color:white}.tag-unknown{background:#95a5a6;color:white}.stat-card{background:white;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,.1);display:inline-block;margin:5px;text-align:center;min-width:120px}.stat-number{font-size:2em;font-weight:bold;color:#2c3e50}img.icon{width:100px;height:100px;border-radius:10px}img.screenshot-thumb{width:120px;border-radius:5px;border:1px solid #ddd;cursor:pointer}.mono{font-family:monospace;font-size:13px}.btn-download{display:inline-block;background:#27ae60;color:white;padding:8px 16px;border-radius:5px;cursor:pointer}.lightbox{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.9);z-index:9999;justify-content:center;align-items:center}.lightbox.active{display:flex}.lightbox img{max-width:90%;max-height:85%}.lb-close{position:absolute;top:20px;right:30px;color:white;font-size:40px;cursor:pointer}</style></head><body>')
    parts.append('<div class="lightbox" id="lightbox" onclick="if(event.target===this)closeLb()"><span class="lb-close" onclick="closeLb()">&times;</span><img id="lb-img" src=""></div>')
    parts.append('<script>function openLb(b){var lb=document.getElementById("lightbox");document.getElementById("lb-img").src="data:image/png;base64,"+b;lb.classList.add("active")}function closeLb(){document.getElementById("lightbox").classList.remove("active")}</script>')
    parts.append('<h1>云手机APK检测报告</h1>')
    parts.append('<p>生成时间: ' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' | 云手机(rk3588s,Android10) | 批量安装模式</p>')
    parts.append(f'<div><div class="stat-card"><div class="stat-number">{len(apks)}</div>APK总数</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(has_nodes)}</div>有节点</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(all_proxy)}</div>代理节点</div>')
    parts.append(f'<div class="stat-card"><div class="stat-number">{len(hw_ips)}</div>华为云IP</div></div>')
    parts.append('<h2>APK信息与网络请求详情</h2>')
    parts.append('<table><tr><th>APP名称</th><th>APP包名</th><th>安装包图标</th><th>运行截图</th><th>端口</th><th>首次发现</th><th>监控时间</th><th>服务器地址（华为云IP）</th><th>代理节点数</th></tr>')
    for a in apks:
        aid=a.get('id','');pkg=a.get('package','');nodes=a.get('proxy_nodes',[])
        port=a.get('app_domain_port','');first=a.get('first_seen','');last=a.get('last_collected','')
        hw=[ip for ip in nodes if get_cloud(ip)=="华为云"]
        label=a.get('label',aid)
        icon_path=f'{BASE_DIR}/screenshots/icons/{aid}.png'
        icon_b64=img_b64(icon_path,200) if os.path.exists(icon_path) else ''
        icon_html='<img class="icon" src="data:image/png;base64,'+icon_b64+'">' if icon_b64 else 'N/A'
        shot_path=f'{BASE_DIR}/screenshots/{aid}.png'
        shot_b64=img_b64(shot_path,240) if os.path.exists(shot_path) else ''
        shot_cell='<img class="screenshot-thumb" src="data:image/png;base64,'+shot_b64+'" onclick="openLb(\''+shot_b64+'\')">' if shot_b64 else 'N/A'
        server_cell='<br>'.join([f'<span class="tag tag-huawei">{ip}</span>' for ip in hw]) if hw else '-'
        parts.append(f'<tr><td><strong>{label}</strong></td><td class="mono">{pkg}</td><td>{icon_html}</td><td>{shot_cell}</td><td>{port}</td><td>{first}</td><td>{last}</td><td>{server_cell}</td><td>{len(nodes)}</td></tr>')
    parts.append('</table>')
    parts.append('<h2>全部代理节点</h2>')
    parts.append(f'<p>共{len(all_proxy)}个IP | 阿里云{len(ali_ips)} | 腾讯云{len(tencent_ips)} | 华为云{len(hw_ips)} | 其他{len(other_ips)}</p>')
    parts.append('<table><tr><th>IP</th><th>厂商</th><th>出现在APK</th></tr>')
    for ip in sorted(all_proxy):
        cloud=get_cloud(ip);apks_list=[a['id'] for a in apks if ip in a.get('proxy_nodes',[])]
        tag='tag-huawei' if cloud=='华为云' else 'tag-aliyun' if cloud=='阿里云' else 'tag-tencent' if cloud=='腾讯云' else 'tag-unknown'
        parts.append(f'<tr><td class="mono">{ip}</td><td><span class="tag {tag}">{cloud}</span></td><td>{", ".join(apks_list[:5])}</td></tr>')
    parts.append('</table>')
    if hw_ips:
        parts.append('<h2>华为云IP列表</h2>')
        for ip in sorted(hw_ips):
            apks_list=[a.get('label','?') for a in apks if ip in a.get('proxy_nodes',[])]
            parts.append(f'<div><span class="tag tag-huawei">{ip}</span> ({len(apks_list)}个APK) {", ".join(apks_list[:3])}</div>')
    parts.append('</body></html>')
    html_path = f'{RESULTS_DIR}/report.html'
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(html_path,'w') as f: f.write('\n'.join(parts))
    return os.path.getsize(html_path)

def generate_report(db, all_proxy):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    history = load_json(IP_HISTORY)
    history[ts] = {'total': len(all_proxy), 'huawei': len([ip for ip in all_proxy if get_cloud(ip)=="华为云"])}
    save_json(IP_HISTORY, history)
    run_result = {'timestamp': ts, 'stats': stats, 'apk_details': current_run_details}
    save_json(f'{RESULTS_DIR}/run_result.json', run_result)
    old_hw_path = '/tmp/old_hw_ips.json'
    if os.path.exists(old_hw_path):
        with open(old_hw_path) as f: old_hw = set(json.load(f))
        new_hw = {ip for ip in all_proxy if get_cloud(ip) == "华为云"} - old_hw
        if new_hw:
            print("*** 告警! 发现" + str(len(new_hw)) + "个新华为IP! ***", flush=True)
            for ip in sorted(new_hw): print("  新华为IP: " + ip, flush=True)
            with open(f"{NODES_DIR}/new_huawei_alert.txt", 'a') as f:
                f.write(f"[{ts}] 新华为IP: {', '.join(sorted(new_hw))}\n")
    try:
        size = generate_html(db, all_proxy)
        hw_count = len([ip for ip in all_proxy if get_cloud(ip)=="华为云"])
        print(f"HTML: {size} bytes, IP: {len(all_proxy)}节点 {hw_count}华为", flush=True)
    except Exception as e:
        print(f"HTML生成失败: {e}")
    try:
        subprocess.run(['git', 'add', '-A'], cwd=BASE_DIR, capture_output=True, timeout=30)
        subprocess.run(['git', 'commit', '-m', f'云手机v2: {stats["installed"]}APK, {len(all_proxy)}节点'], cwd=BASE_DIR, capture_output=True, timeout=30)
        env = os.environ.copy(); env['GIT_SSH_COMMAND'] = 'ssh -o ConnectTimeout=15'
        subprocess.run(['git', 'push', 'origin', 'main'], cwd=BASE_DIR, capture_output=True, timeout=60, env=env)
    except: pass

def main():
    all_apks, existing_ids = get_pending_apks()
    existing_pkgs = {e.get('package','') for e in load_state() if e.get('package')}
    print(f"=== 云手机流水线v2 (批量安装) ===")
    print(f"待安装: {len(all_apks)}")
    print(f"每批: {BATCH_SIZE}个", flush=True)

    db = load_json(DB_PATH)
    if 'apks' not in db: db['apks'] = []
    if 'all_proxy_nodes' not in db: db['all_proxy_nodes'] = []
    all_proxy = set(db.get('all_proxy_nodes', []))
    state = load_state()

    t_start = time.time()
    for batch_start in range(0, len(all_apks), BATCH_SIZE):
        batch = all_apks[batch_start:batch_start+BATCH_SIZE]
        batch_num = batch_start // BATCH_SIZE + 1
        total_batches = (len(all_apks) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"\n=== 批次 {batch_num}/{total_batches} (传{len(batch)}个APK) ===", flush=True)
        
        # 1. 批量推送APK到设备
        t_push_start = time.time()
        apk_list = [(apk[0], apk[1]) for apk in batch]
        push_ok = push_batch_to_device(apk_list)
        t_push = time.time() - t_push_start
        if not push_ok:
            print(f"推送失败,跳过此批", flush=True)
            continue
        print(f"推送完成({t_push:.1f}s)", flush=True)

        # 2. 逐个安装检测
        for apk_path, domain, score, pkg, label in batch:
            if pkg in existing_pkgs:
                print(f"  [S] {domain}({label}) 包名冲突,跳过", flush=True)
                continue
            print(f"  [I] {domain}({label}) ", end='', flush=True)
            ok, t_inst, t_node = install_from_device(domain, pkg, label, apk_path, 
                {'score':score,'size_mb':os.path.getsize(apk_path)//1024//1024,'url':''})
            if ok:
                now = datetime.now().strftime('%Y-%m-%d %H:%M')
                entry = {'apk_id':domain,'package':pkg,'label':label,'score':str(score),
                         'size_mb':str(os.path.getsize(apk_path)//1024//1024),
                         'first_installed':now,'last_monitored':now,
                         'proxy_count':str(0),'huawei_count':'0',
                         'installed_on_device':'false','apk_path':apk_path,
                         'domain':domain,'download_url':'','status':'ok',
                         'download_time':'0.0','detect_time':'0.0',
                         'install_time':f'{t_inst:.1f}','node_time':f'{t_node:.1f}'}
                with state_lock:
                    state.append(entry)
                    existing_ids.add(domain)
                    existing_pkgs.add(pkg)
                    save_state(state)
                    # 获取最新节点
                    r = run_adb(['shell', f'cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json 2>/dev/null'], timeout=5)
                    nodes = []
                    if r.stdout and r.stdout.strip().startswith('{'):
                        try:
                            nodes = json.loads(r.stdout).get('app_line_ips', [])
                        except: pass
                    if not nodes:
                        nodes = get_proxy_nodes_via_proc(pkg)
                    hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]
                    entry['proxy_count'] = str(len(nodes))
                    entry['huawei_count'] = str(len(hw_ips))
                    save_state(state)
                    db['apks'].append({'id':domain,'package':pkg,'label':label,
                        'app_name':'','app_domain_port':'','proxy_nodes':nodes,
                        'proxy_count':len(nodes),'first_seen':now,'last_collected':now})
                    for ip in nodes: all_proxy.add(ip)
                    db['all_proxy_nodes'] = sorted(all_proxy)
                    save_json(DB_PATH, db)
                    with open(f"{NODES_DIR}/all_nodes.txt", 'w') as f:
                        for ip in sorted(all_proxy): f.write(ip + ' [' + get_cloud(ip) + ']\n')
                    hw_list = [ip for ip in all_proxy if get_cloud(ip) == "华为云"]
                    with open(f"{NODES_DIR}/huawei_nodes.txt", 'w') as f:
                        for ip in sorted(hw_list): f.write(ip + '\n')
                    current_run_details.append({'domain':domain,'label':label,'package':pkg,'nodes':nodes,'hw_ips':hw_ips})
                    generate_report(db, all_proxy)

        # 3. 清除设备上的APK
        run_adb(['shell', f'rm -rf {DEVICE_APK_DIR}'], timeout=10)
        
    # 最终报告
    db = load_json(DB_PATH)
    all_proxy = set(db.get('all_proxy_nodes', []))
    generate_report(db, all_proxy)
    elapsed = time.time() - t_start
    n = stats['installed'] if stats['installed'] > 0 else 1
    print(f"\n=== 完成 ===")
    print(f"总耗时: {elapsed/60:.1f}分钟")
    print(f"安装: {stats['installed']} 失败: {stats['failed']}")
    print(f"平均安装: {stats['total_install']/n:.1f}s 节点: {stats['total_node']/n:.1f}s")

if __name__ == '__main__':
    main()
