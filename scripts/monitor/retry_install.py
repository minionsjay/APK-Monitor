#!/usr/bin/env python3
"""重新安装之前失败的 APK（已有本地文件，直接安装+获取节点）"""
import subprocess, json, os, time, re, csv, threading, queue

ADB = "adb -s 192.168.1.5:37773"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db_newdev.json"
STATE_CSV = f"{BASE_DIR}/data/apk_state_newdev.csv"
IP_HISTORY = f"{BASE_DIR}/data/ip_history_newdev.json"

STATE_FIELDS = ['apk_id','package','label','score','size_mb',
                'first_installed','last_monitored','proxy_count',
                'huawei_count','installed_on_device','apk_path',
                'domain','download_url','status',
                'download_time','detect_time','install_time','node_time']

def get_cloud(ip):
    if ip.startswith('8.13') or ip.startswith('8.138') or ip.startswith('8.148') or ip.startswith('8.163') or ip.startswith('47.113'): return "阿里云"
    elif any(ip.startswith(p) for p in ['43.','42.','106.','159.75','139.','175.178','134.175','1.14','1.202','111.230','119.','123.207','129.204','193.112','115.175','139.9']): return "腾讯云"
    elif any(ip.startswith(p) for p in ['110.41','113.45','113.46','114.132','116.205','121.37','124.71']): return "华为云"
    return "未知"

def load_json(path):
    if not os.path.exists(path): return {}
    with open(path) as f: return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f: json.dump(data, f, indent=2, ensure_ascii=False)

def load_state():
    if not os.path.exists(STATE_CSV): return []
    with open(STATE_CSV, encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

def save_state(state):
    with open(STATE_CSV, 'a', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=STATE_FIELDS)
        writer.writerows(state)

def dump_ui():
    subprocess.run(f'{ADB} shell uiautomator dump /sdcard/ui.xml'.split(),
                   capture_output=True, timeout=10)
    subprocess.run(f'{ADB} pull /sdcard/ui.xml /tmp/ui_check.xml'.split(),
                   capture_output=True, timeout=5)
    try:
        with open('/tmp/ui_check.xml') as f: return f.read()
    except: return ''

def click_button(texts, max_tries=3, wait=2):
    for i in range(max_tries):
        ui = dump_ui()
        for text in texts:
            for pat in [
                r'text="' + text + r'"[^>]*clickable="true"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                r'text="' + text + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            ]:
                matches = re.findall(pat, ui)
                if matches:
                    x1, y1, x2, y2 = matches[0]
                    subprocess.run(f'{ADB} shell input tap {(int(x1)+int(x2))//2} {(int(y1)+int(y2))//2}'.split(),
                                 capture_output=True, timeout=5)
                    return True
        time.sleep(wait)
    return False

def install_apk(apk_path, timeout=90):
    """通过 MT管理器安装 APK"""
    remote_apk = '/sdcard/Download/install.apk'
    subprocess.run(f'{ADB} push {apk_path} {remote_apk}'.split(),
                   capture_output=True, timeout=60)
    
    for attempt in range(3):
        subprocess.run(f'{ADB} shell input keyevent KEYCODE_HOME'.split(),
                       capture_output=True, timeout=5)
        time.sleep(1)
        
        subprocess.run(
            f'{ADB} shell am start -a android.intent.action.VIEW '
            f'-d "file://{remote_apk}" '
            f'-t "application/vnd.android.package-archive" -f 0x10000000'.split(),
            capture_output=True, timeout=10)
        time.sleep(5)
        
        ui = dump_ui()
        mt_match = re.search(r'text="MT管理器"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
        if not mt_match:
            install_match = re.search(r'text="安装"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
            if install_match:
                x1, y1, x2, y2 = [int(v) for v in install_match.groups()]
                subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                               capture_output=True, timeout=5)
                time.sleep(3)
                break
            if attempt < 2:
                time.sleep(2)
                continue
            return False
        
        x1, y1, x2, y2 = [int(v) for v in mt_match.groups()]
        subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                       capture_output=True, timeout=5)
        time.sleep(3)
        break
    
    # 点安装
    ui = dump_ui()
    install_match = re.search(r'text="安装"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
    if install_match:
        x1, y1, x2, y2 = [int(v) for v in install_match.groups()]
        subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                       capture_output=True, timeout=5)
        time.sleep(3)
    
    # 安装未知应用权限
    ui = dump_ui()
    if '允许来自此来源' in ui or '安装未知应用' in ui:
        switch = re.search(r'text="(开启|关闭)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
        if switch:
            x1, y1, x2, y2 = [int(v) for v in switch.groups()]
            subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                           capture_output=True, timeout=5)
            time.sleep(2)
        subprocess.run(f'{ADB} shell input keyevent KEYCODE_BACK'.split(),
                       capture_output=True, timeout=5)
        time.sleep(2)
        ui = dump_ui()
        install_match = re.search(r'text="安装"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
        if install_match:
            x1, y1, x2, y2 = [int(v) for v in install_match.groups()]
            subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                           capture_output=True, timeout=5)
            time.sleep(3)
    
    # 处理"安装信息收集提醒"
    for _ in range(3):
        ui = dump_ui()
        if '继续安装' in ui:
            match = re.search(r'text="继续安装"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
            if match:
                x1, y1, x2, y2 = [int(v) for v in match.groups()]
                subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                               capture_output=True, timeout=5)
                time.sleep(5)
                break
        time.sleep(2)
    
    # 处理"安装增强防护提醒"（中高风险应用）
    for _ in range(8):
        ui = dump_ui()
        if '安装增强防护提醒' in ui or '中高风险应用' in ui:
            # 点击右上角设置按钮
            subprocess.run(f'{ADB} shell input tap 1009 169'.split(),
                           capture_output=True, timeout=5)
            time.sleep(2)
            # 在设置页面找开关
            ui2 = dump_ui()
            switch = re.search(r'text="(开启|已开启)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui2)
            if switch:
                # 开关是开的，需要关闭
                x1, y1, x2, y2 = [int(v) for v in switch.groups()[1:]]
                subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                               capture_output=True, timeout=5)
                time.sleep(2)
                # 确认关闭
                ui3 = dump_ui()
                close_match = re.search(r'text="关闭"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui3)
                if close_match:
                    x1, y1, x2, y2 = [int(v) for v in close_match.groups()]
                    subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                                   capture_output=True, timeout=5)
                    time.sleep(3)
            elif '未开启' in ui2:
                # 已经关闭了，直接返回
                subprocess.run(f'{ADB} shell input keyevent KEYCODE_BACK'.split(),
                               capture_output=True, timeout=5)
                time.sleep(3)
            continue
        # 检测安装确认界面（有"继续安装"和"取消安装"）
        if '继续安装' in ui:
            match = re.search(r'text="继续安装"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
            if match:
                x1, y1, x2, y2 = [int(v) for v in match.groups()]
                subprocess.run(f'{ADB} shell input tap {(x1+x2)//2} {(y1+y2)//2}'.split(),
                               capture_output=True, timeout=5)
                time.sleep(5)
                break
        time.sleep(2)
    
    time.sleep(5)
    subprocess.run(f'{ADB} shell input keyevent KEYCODE_HOME'.split(),
                   capture_output=True, timeout=5)
    return True

def start_pcapdroid(pkg=None):
    cmd = f'{ADB} shell am broadcast -a com.emanuelef.remote_capture.CaptureCtrl --es action start'
    if pkg:
        cmd += f' --es target_app {pkg}'
    cmd += ' --es pcap_dump_mode PCAP_FILE --es pcap_dir /sdcard/Download/PCAPdroid/'
    subprocess.run(cmd.split(), capture_output=True, timeout=10)
    time.sleep(2)

def stop_pcapdroid_and_extract_ips():
    subprocess.run(f'{ADB} shell am broadcast -a com.emanuelef.remote_capture.CaptureCtrl --es action stop'.split(),
                   capture_output=True, timeout=10)
    time.sleep(2)
    
    r = subprocess.run(f'{ADB} shell ls -t /sdcard/Download/PCAPdroid/*.pcap'.split(),
                     capture_output=True, text=True, timeout=10)
    if not r.stdout.strip():
        return []
    
    latest_pcap = r.stdout.strip().split('\n')[0]
    local_pcap = '/tmp/pcapdroid_latest.pcap'
    subprocess.run(f'{ADB} pull {latest_pcap} {local_pcap}'.split(),
                   capture_output=True, timeout=30)
    
    if not os.path.exists(local_pcap) or os.path.getsize(local_pcap) < 100:
        return []
    
    r = subprocess.run(
        ['tshark', '-r', local_pcap, '-T', 'fields', '-e', 'ip.dst', '-e', 'tcp.dstport'],
        capture_output=True, text=True, timeout=15)
    
    nodes = set()
    local_ips = {'10.215.173.1', '10.215.173.2', '127.0.0.1', '192.168.1.1', '192.168.1.5', '0.0.0.0', '10.27.93.153', '10.27.93.154'}
    
    for line in r.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) >= 2:
            ip = parts[0].strip()
            port = parts[1].strip()
            if not ip or not port or ip in local_ips:
                continue
            try:
                port_num = int(port)
                if port_num > 100:
                    nodes.add(f"{ip}:{port}")
            except:
                pass
    
    return sorted(nodes)

def get_proxy_nodes_via_proc(pkg, max_wait=60):
    all_nodes = set()
    for i in range(max_wait // 5):
        time.sleep(5)
        try:
            r = subprocess.run(f'{ADB} shell pidof {pkg}'.split(),
                             capture_output=True, text=True, timeout=5)
            pid = r.stdout.strip()
            if not pid:
                continue
            for proto in ['tcp', 'tcp6']:
                r = subprocess.run(f'{ADB} shell cat /proc/{pid}/net/{proto}'.split(),
                                 capture_output=True, text=True, timeout=5)
                for line in r.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    remote = parts[2]
                    state = parts[3]
                    if state not in ("01", "02", "06"):
                        continue
                    ip_hex, port_hex = remote.split(':')
                    port = int(port_hex, 16)
                    if port <= 100:
                        continue
                    if len(ip_hex) == 8:
                        b = bytes.fromhex(ip_hex)
                        ip = f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
                        if ip.startswith("127.") or ip.startswith("0.0.") or ip.startswith("192.168."):
                            continue
                        all_nodes.add(f"{ip}:{port}")
                    elif len(ip_hex) == 32 and ip_hex.startswith("00000000000000000000ffff"):
                        hex_ip = ip_hex[24:]
                        b = bytes.fromhex(hex_ip)
                        ip = f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
                        if ip.startswith("127.") or ip.startswith("0.0.") or ip.startswith("192.168."):
                            continue
                        all_nodes.add(f"{ip}:{port}")
        except:
            pass
    return sorted(all_nodes) if all_nodes else []

def main():
    # 读取待安装列表
    with open('/tmp/retry_install5.csv', encoding='utf-8-sig') as f:
        items = list(csv.DictReader(f))
    
    print(f"=== 重新安装失败 APK ===")
    print(f"待安装: {len(items)} 个")
    
    state = load_state()
    existing_ids = {e['apk_id'] for e in state}
    existing_pkgs = {e['package'] for e in state if e.get('package')}
    db = load_json(DB_PATH)
    if 'apks' not in db: db['apks'] = []
    if 'all_proxy_nodes' not in db: db['all_proxy_nodes'] = []
    
    success = 0
    failed = 0
    
    for i, item in enumerate(items):
        domain = item['pre_host']
        apk_path = item['max(prev)']
        
        if domain in existing_ids:
            continue
        
        # 获取包名
        r = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
        pkg = ''
        label = ''
        for line in r.stdout.split('\n'):
            if line.startswith('package:'):
                pkg = line.split("name='")[1].split("'")[0] if "name='" in line else ''
            if line.startswith('application-label:'):
                label = line.split("'")[1] if "'" in line else ''
        
        if pkg in existing_pkgs:
            continue
        
        print(f"[{i+1}/{len(items)}] {domain}({label}) ", end='', flush=True)
        
        # 卸载同包名
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
        
        # 安装
        t3 = time.time()
        if not install_apk(apk_path):
            print(f'安装失败'); failed += 1; continue
        t_inst = time.time() - t3
        
        # 启动 PCAPdroid
        start_pcapdroid(pkg)
        
        # 启动 APP
        t4 = time.time()
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                      capture_output=True, timeout=10)
        time.sleep(8)
        click_button(["允许"], max_tries=3, wait=2)
        
        # 获取节点
        nodes = get_proxy_nodes_via_proc(pkg)
        pcap_nodes = stop_pcapdroid_and_extract_ips()
        all_node_set = set(nodes)
        for n in pcap_nodes:
            all_node_set.add(n)
        nodes = sorted(all_node_set)
        
        hw_ips = [ip for ip in nodes if get_cloud(ip.split(':')[0]) == "华为云"]
        
        # 停止 APP
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(),
                      capture_output=True, timeout=5)
        t_node = time.time() - t4
        
        now = time.strftime('%Y-%m-%d %H:%M')
        size_mb = os.path.getsize(apk_path) // 1024 // 1024
        
        entry = {'apk_id':domain,'package':pkg,'label':label,
                 'score':'80','size_mb':str(size_mb),
                 'first_installed':now,'last_monitored':now,
                 'proxy_count':str(len(nodes)),'huawei_count':str(len(hw_ips)),
                 'installed_on_device':'true','apk_path':apk_path,
                 'domain':domain,'download_url':'',
                 'status':'ok' if nodes else 'no_nodes',
                 'download_time':'0','detect_time':'0',
                 'install_time':f'{t_inst:.1f}','node_time':f'{t_node:.1f}'}
        
        existing_ids.add(domain)
        existing_pkgs.add(pkg)
        save_state([entry])
        
        db['apks'].append({'id':domain,'package':pkg,'label':label,
                          'app_name':'','app_domain_port':'',
                          'proxy_nodes':nodes,'proxy_count':len(nodes),
                          'first_seen':now,'last_collected':now})
        all_proxy = set(db.get('all_proxy_nodes', []))
        for ip in nodes:
            all_proxy.add(ip)
        db['all_proxy_nodes'] = sorted(all_proxy)
        save_json(DB_PATH, db)
        
        print(f'安装{t_inst:.1f}s 节点{t_node:.1f}s → {len(nodes)}节点 {len(hw_ips)}华为')
        success += 1
    
    print(f"\n=== 完成 ===")
    print(f"成功: {success} 失败: {failed}")

if __name__ == '__main__':
    main()
