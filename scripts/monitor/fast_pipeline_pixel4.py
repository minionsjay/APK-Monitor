#!/usr/bin/env python3
"""
Pixel 4 (root, Android 13, Magisk) 快速流水线 v4
- 合并两个CSV域名列表 (apk-domain.csv + apk-domain-260724.csv)
- 线程1: 下载+检测 → 队列
- 线程2: adb install -r (无需MT管理器) + 直接读 sdk_forwarder_fixed.json (root)
- IP变更对比, 华为IP自动推送GitHub
- 每5个APK生成一次报告
"""

import subprocess, json, os, time, re, csv, zipfile, hashlib, threading, queue
from datetime import datetime

# ====== Pixel 4 配置 ======
ADB = "adb -s 192.168.1.16:39653"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
APK_DIR = f"{BASE_DIR}/new_samples"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db.json"          # Pixel 4 主数据库
STATE_CSV = f"{BASE_DIR}/data/apk_state.csv"                # Pixel 4 状态表
IP_HISTORY = f"{BASE_DIR}/data/ip_history.json"            # Pixel 4 IP历史
DOMAIN_CSV_OLD = f"{BASE_DIR}/data/apk-domain.csv"         # 旧域名列表 (1000)
DOMAIN_CSV_NEW = f"{BASE_DIR}/data/apk-domain-260724.csv"   # 新域名列表 (1112)
OUTPUTS_DIR = f"{BASE_DIR}/outputs"
STORAGE_THRESHOLD_GB = 5

STATE_FIELDS = ['apk_id','package','label','score','size_mb',
                'first_installed','last_monitored','proxy_count',
                'huawei_count','installed_on_device','apk_path',
                'domain','download_url','status',
                'download_time','detect_time','install_time','node_time']

def get_cloud(ip):
    ip = ip.split(':')[0] if ':' in ip else ip
    if ip.startswith('8.13') or ip.startswith('8.138') or ip.startswith('8.148') or ip.startswith('8.163'): return "阿里云"
    elif any(ip.startswith(p) for p in ['43.','42.','106.','159.75','139.','175.178','134.175','1.1','111.230','119.','123.207','129.204','193.112','115.175','139.9','1.14','1.202']): return "腾讯云"
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
    with open(STATE_CSV, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=STATE_FIELDS)
        writer.writeheader()
        writer.writerows(state)

def get_storage_gb():
    """获取设备可用存储 (GB) - Pixel 4 的 df /data 被 Magisk 重定向到 /system/..."""
    result = subprocess.run(f'{ADB} shell df /sdcard'.split(), capture_output=True, text=True, timeout=10)
    for line in result.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 4 and ('fuse' in line or '/sdcard' in line or '/storage' in line):
            try:
                return int(parts[3]) // 1024 // 1024
            except (ValueError, IndexError):
                continue
    return 999  # 默认返回大值，不阻止安装

def detect_apk(apk_path):
    result = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
    pkg = ''; label = ''
    for line in result.stdout.split('\n'):
        if line.startswith('package:'):
            pkg = line.split("name='")[1].split("'")[0] if "name='" in line else ''
        if line.startswith('application-label:'):
            label = line.split("'")[1] if "'" in line else ''
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            so_files = [n for n in names if n.endswith('.so')]
            score = 0
            if any('libgojni' in n for n in so_files): score += 40
            if any(len(n) > 20 and n.startswith('lib/') and n.endswith('.so') and 'gojni' not in n for n in so_files): score += 40
            if any('WgSnp' in n or 'TifMz' in n for n in names): score += 40
    except zipfile.BadZipFile:
        return 0, pkg, label
    return score, pkg, label

def click_popup():
    """点击通知弹窗"允许"按钮"""
    for _ in range(3):
        subprocess.run(f'{ADB} shell uiautomator dump /sdcard/ui.xml'.split(),
                     capture_output=True, timeout=10)
        subprocess.run(f'{ADB} pull /sdcard/ui.xml /tmp/ui_check.xml'.split(),
                     capture_output=True, timeout=5)
        try:
            with open('/tmp/ui_check.xml') as f: ui = f.read()
            matches = re.findall(r'text="(允许)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', ui)
            if matches:
                _, x1, y1, x2, y2 = matches[0]
                subprocess.run(f'{ADB} shell input tap {(int(x1)+int(x2))//2} {(int(y1)+int(y2))//2}'.split(),
                             capture_output=True, timeout=5)
                time.sleep(2)
                return True
        except:
            pass
        time.sleep(2)
    return False

def get_proxy_nodes(pkg, max_wait=30):
    """通过root直接读取 sdk_forwarder_fixed.json"""
    for i in range(max_wait // 5):
        time.sleep(5)
        # 方法1: 直接cat (Pixel 4有root)
        result = subprocess.run(
            f'{ADB} shell su -c "cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json 2>/dev/null"',
            capture_output=True, text=True, timeout=5, shell=True)
        if result.stdout and result.stdout.strip().startswith('{'):
            try:
                data = json.loads(result.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes:
                    return nodes
            except:
                pass
        # 方法2: 不用su直接cat (Android 13允许读)
        result2 = subprocess.run(
            f'{ADB} shell cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json',
            capture_output=True, text=True, timeout=5, shell=True)
        if result2.stdout and result2.stdout.strip().startswith('{'):
            try:
                data = json.loads(result2.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes:
                    return nodes
            except:
                pass
    return []

def get_proxy_nodes_via_proc(pkg, max_wait=30):
    """备用方法: 通过 /proc/PID/net/tcp 获取节点 (root不需要但可作为补充)"""
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
                    if len(parts) < 4: continue
                    remote = parts[2]
                    state = parts[3]
                    if state not in ("01", "02", "06"): continue
                    ip_hex, port_hex = remote.split(':')
                    port = int(port_hex, 16)
                    if port <= 100: continue
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

def extract_icon(apk_path, apk_id):
    """从APK提取图标"""
    try:
        result = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
        icon_path = None
        for line in result.stdout.split('\n'):
            if 'application-icon-640' in line:
                m = re.search(r"'([^']+)'", line)
                if m:
                    icon_path = m.group(1)
                    break
        with zipfile.ZipFile(apk_path) as zf:
            webps = [(n, zf.getinfo(n).file_size) for n in zf.namelist() if n.endswith('.webp')]
            if not webps:
                pngs = [(n, zf.getinfo(n).file_size) for n in zf.namelist() if n.endswith('.png') and 'res/' in n]
                if pngs:
                    pngs.sort(key=lambda x: x[1], reverse=True)
                    data = zf.read(pngs[0][0])
                else:
                    return None
            else:
                found = False
                if icon_path:
                    path_parts = icon_path.replace('\\','/').split('/')
                    last_part = path_parts[-1] if path_parts else ''
                    for name, size in webps:
                        name_parts = name.replace('\\','/').split('/')
                        if last_part and name_parts[-1] == last_part:
                            data = zf.read(name)
                            found = True
                            break
                if not found:
                    webps.sort(key=lambda x: x[1], reverse=True)
                    data = zf.read(webps[0][0])
            icon_file = f'{BASE_DIR}/screenshots/icons/{apk_id}.png'
            os.makedirs(os.path.dirname(icon_file), exist_ok=True)
            with open(icon_file, 'wb') as f: f.write(data)
            return icon_file
    except:
        return None

def screenshot(apk_id, pkg):
    """截图"""
    try:
        subprocess.run(f'{ADB} shell screencap -p /sdcard/shot.png'.split(),
                       capture_output=True, timeout=5)
        shot_path = f'{BASE_DIR}/screenshots/{apk_id}.png'
        subprocess.run(f'{ADB} pull /sdcard/shot.png {shot_path}'.split(),
                       capture_output=True, timeout=10)
        return shot_path if os.path.exists(shot_path) else None
    except:
        return None

# ====== 全局状态 ======
state_lock = threading.Lock()
state = load_state()
existing_ids = {e['apk_id'] for e in state}
existing_pkgs = {e['package'] for e in state if e.get('package')}

apk_queue = queue.Queue(maxsize=3)
stats = {'downloaded':0,'installed':0,'failed':0,'skipped':0,
         'total_dl':0.0,'total_detect':0.0,'total_install':0.0,'total_node':0.0,
         'total_icon':0.0}

current_run_nodes = set()
current_run_details = []

def load_all_domains():
    """合并两个CSV的域名列表"""
    all_domains = []
    seen = set()
    for csv_path in [DOMAIN_CSV_OLD, DOMAIN_CSV_NEW]:
        if not os.path.exists(csv_path):
            continue
        with open(csv_path, encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                domain = row.get('pre_host','').strip()
                if domain and domain not in seen:
                    seen.add(domain)
                    all_domains.append(row)
    return all_domains

def download_worker(domains):
    """线程1：下载+检测→队列"""
    for i, d in enumerate(domains):
        domain = d.get('pre_host','')
        url = d.get('max(prev)', f'https://{domain}/')
        if domain in existing_ids:
            continue

        print(f"[D {i+1}/{len(domains)}] {domain}", end=' ')

        try:
            t0 = time.time()
            r = subprocess.run(['curl','-sk','-L','--connect-timeout','6',
                              '-A','Mozilla/5.0 (Linux; Android 13; Pixel 4) AppleWebKit/537.36',url],
                             capture_output=True, text=True, timeout=10)
            t_html = time.time() - t0
            html = r.stdout
            if not html or len(html) < 50:
                print(f'无响应({t_html:.1f}s)'); stats['failed']+=1; continue

            android_urls = re.findall(r'android\s*:\s*"([^"]+)"', html)
            android_url2 = re.findall(r'androidUrl\s*:\s*"([^"]+)"', html)
            redirect = re.findall(r'window\.location\s*=\s*"([^"]+)"', html)
            dl = None
            if android_urls: dl = android_urls[0]
            elif android_url2: dl = android_url2[0]
            elif redirect: dl = redirect[0]
            else:
                print(f'无链接({t_html:.1f}s)'); stats['failed']+=1; continue

            out_path = f'{APK_DIR}/{domain}.apk'
            t1 = time.time()
            subprocess.run(['curl','-sk','-L','--connect-timeout','15','-o',out_path,dl],
                          capture_output=True, timeout=90)
            t_dl = time.time() - t1
            stats['total_dl'] += t_dl
            if not os.path.exists(out_path) or os.path.getsize(out_path) < 1000000:
                if os.path.exists(out_path): os.remove(out_path)
                print(f'下载失败({t_dl:.1f}s)'); stats['failed']+=1; continue
            with open(out_path,'rb') as f:
                if f.read(4) != b'PK\x03\x04':
                    os.remove(out_path); print(f'非APK({t_dl:.1f}s)'); stats['failed']+=1; continue
        except subprocess.TimeoutExpired:
            print('超时'); stats['failed']+=1; continue
        except Exception as e:
            print(f'异常({e})'); stats['failed']+=1; continue

        t2 = time.time()
        score, pkg, label = detect_apk(out_path)
        t_det = time.time() - t2
        stats['total_detect'] += t_det
        size_mb = os.path.getsize(out_path) // 1024 // 1024
        if score < 80:
            os.remove(out_path); print(f'非恶意({t_det:.1f}s)'); stats['skipped']+=1; continue
        if pkg in existing_pkgs:
            os.remove(out_path); print(f'包名冲突({t_det:.1f}s)'); stats['skipped']+=1; continue

        print(f'✅{label}({size_mb}MB) 下载{t_dl:.1f}s')
        stats['downloaded']+=1
        apk_queue.put({
            'domain':domain,'url':url,'apk_path':out_path,
            'score':score,'package':pkg,'label':label,'size_mb':size_mb,
            'download_time':t_dl,'detect_time':t_det
        })
    apk_queue.put(None)

def install_worker():
    """线程2：安装(adb install -r) + 获取节点(sdk_forwarder_fixed.json) → 记录"""
    while True:
        item = apk_queue.get()
        if item is None: break

        domain = item['domain']; pkg = item['package']; label = item['label']
        apk_path = item['apk_path']; size_mb = item['size_mb']
        t_dl = item['download_time']; t_det = item['detect_time']

        print(f"  [I] {domain}({label})", end=' ')

        # 存储检查
        storage_gb = get_storage_gb()
        if storage_gb < STORAGE_THRESHOLD_GB:
            print(f'存储不足({storage_gb}GB)')
            os.path.exists(apk_path) and os.remove(apk_path); stats['skipped']+=1; continue

        # 卸载同包名
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)

        # 安装 (Pixel 4 root, adb install直接可用)
        t3 = time.time()
        try:
            r = subprocess.run(f'{ADB} install -r {apk_path}'.split(),
                              capture_output=True, text=True, timeout=120)
            t_inst = time.time() - t3
            stats['total_install'] += t_inst
            if 'Success' not in r.stdout:
                print(f'安装失败({t_inst:.1f}s) {r.stdout[:50]}')
                os.path.exists(apk_path) and os.remove(apk_path); stats['failed']+=1; continue
        except subprocess.TimeoutExpired:
            print('安装超时(120s)'); stats['failed']+=1; continue
        except Exception as e:
            print(f'安装异常({e})'); stats['failed']+=1; continue

        # 启动APP
        t4 = time.time()
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                      capture_output=True, timeout=10)
        time.sleep(5)
        # 点击通知弹窗
        click_popup()
        # 获取节点 (优先 sdk_forwarder_fixed.json, 备用 /proc/PID/net/tcp)
        nodes = get_proxy_nodes(pkg)
        if not nodes:
            # 备用方法: /proc/PID/net/tcp
            nodes = get_proxy_nodes_via_proc(pkg)

        hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]

        # 截图
        shot_path = screenshot(domain, pkg)
        if shot_path and os.path.exists(shot_path) and os.path.getsize(shot_path) < 500000:
            time.sleep(3)
            shot_path = screenshot(domain, pkg)

        # 提取图标
        t5 = time.time()
        extract_icon(apk_path, domain)
        stats['total_icon'] += time.time() - t5

        # force-stop APP
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(),
                      capture_output=True, timeout=5)
        # 卸载APK
        subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)

        t_node = time.time() - t4
        stats['total_node'] += t_node

        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        entry = {'apk_id':domain,'package':pkg,'label':label,
                 'score':str(item['score']),'size_mb':str(size_mb),
                 'first_installed':now,'last_monitored':now,
                 'proxy_count':str(len(nodes)),'huawei_count':str(len(hw_ips)),
                 'installed_on_device':'false','apk_path':apk_path,
                 'domain':domain,'download_url':item['url'],
                 'status':'ok' if nodes else 'no_nodes',
                 'download_time':f'{t_dl:.1f}','detect_time':f'{t_det:.1f}',
                 'install_time':f'{t_inst:.1f}','node_time':f'{t_node:.1f}'}

        with state_lock:
            state.append(entry)
            existing_ids.add(domain)
            existing_pkgs.add(pkg)
            save_state(state)

            db = load_json(DB_PATH)
            if 'apks' not in db: db['apks'] = []
            if 'all_proxy_nodes' not in db: db['all_proxy_nodes'] = []
            all_proxy = set(db.get('all_proxy_nodes', []))
            db['apks'].append({'id':domain,'package':pkg,'label':label,
                              'app_name':'','app_domain_port':'',
                              'proxy_nodes':nodes,'proxy_count':len(nodes),
                              'first_seen':now,'last_collected':now})
            for ip in nodes:
                all_proxy.add(ip)
                current_run_nodes.add(ip)
            db['all_proxy_nodes'] = sorted(all_proxy)
            save_json(DB_PATH, db)

            current_run_details.append({
                'domain':domain,'label':label,'package':pkg,
                'nodes':nodes,'hw_ips':hw_ips,
                'download_time':t_dl,'detect_time':t_det,
                'install_time':t_inst,'node_time':t_node
            })

        print(f'安装{t_inst:.1f}s 节点{t_node:.1f}s → {len(nodes)}节点 {len(hw_ips)}华为')
        stats['installed']+=1

        if stats['installed'] % 5 == 0:
            generate_report()

def compute_ip_changes():
    db = load_json(DB_PATH)
    current_ips = set(db.get('all_proxy_nodes', []))
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
    return {
        'new_proxy': sorted(new_ips), 'removed_proxy': sorted(removed_ips),
        'unchanged_proxy': sorted(unchanged),
        'new_huawei': sorted(new_hw), 'removed_huawei': sorted(removed_hw),
        'total_current': len(current_ips), 'total_previous': len(prev_ips),
        'total_huawei_current': len(current_hw), 'total_huawei_previous': len(prev_hw),
        'all_proxy': sorted(current_ips),
    }

def generate_report():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    state = load_state()
    db = load_json(DB_PATH)
    changes = compute_ip_changes()
    history = load_json(IP_HISTORY)
    history[ts] = changes
    save_json(IP_HISTORY, history)
    out_dir = f'{OUTPUTS_DIR}/latest'
    os.makedirs(out_dir, exist_ok=True)
    run_result = {'timestamp': ts, 'stats': stats,
                  'apk_details': current_run_details, 'ip_changes': changes}
    save_json(f'{out_dir}/run_result.json', run_result)
    
    # 调用 regen_html.py 生成HTML
    try:
        subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py'], timeout=60)
        import shutil
        src = f'{BASE_DIR}/forensics/pcaps/hw_forensics_report.html'
        dst = f'{out_dir}/report.html'
        if os.path.exists(src):
            shutil.copy2(src, dst)
    except Exception as e:
        print(f'HTML生成失败: {e}')

    print(f"\n=== IP变更 ===")
    print(f"代理节点: {changes['total_previous']} → {changes['total_current']} (新增{len(changes['new_proxy'])} 消失{len(changes['removed_proxy'])})")
    print(f"华为IP: {changes['total_huawei_previous']} → {changes['total_huawei_current']} (新增{len(changes['new_huawei'])} 消失{len(changes['removed_huawei'])})")
    if changes['new_huawei']:
        print(f"  新增华为: {', '.join(changes['new_huawei'][:5])}...")
    if changes['new_huawei']:
        print("检测到新华为IP，推送到GitHub...")
        try:
            subprocess.run(['git', 'add', '-A'], cwd=BASE_DIR, capture_output=True, timeout=30)
            msg = f"新增华为IP: {', '.join(changes['new_huawei'][:5])} 共{len(changes['new_huawei'])}个"
            subprocess.run(['git', 'commit', '-m', msg], cwd=BASE_DIR, capture_output=True, timeout=30)
            env = os.environ.copy()
            env['GIT_SSH_COMMAND'] = 'ssh -o ConnectTimeout=10'
            subprocess.run(['git', 'push', 'origin', 'main'], cwd=BASE_DIR, capture_output=True, timeout=30, env=env)
            print("✅ 已推送到GitHub")
        except Exception as e:
            print(f"推送失败: {e}")

def main():
    domains = load_all_domains()
    print(f"=== 快速流水线 v4 启动 (Pixel 4, root, Android 13) ===")
    print(f"域名总数: {len(domains)} (合并旧+新CSV)")
    print(f"已处理: {len(existing_ids)}")
    print(f"待处理: {len(domains) - len(existing_ids)}")
    print(f"手机存储: {get_storage_gb()}GB")
    print(f"已下载APK: {len([f for f in os.listdir(APK_DIR) if f.endswith('.apk')])}")
    print()

    t_start = time.time()
    dt = threading.Thread(target=download_worker, args=(domains,))
    it = threading.Thread(target=install_worker)
    dt.start(); it.start()
    dt.join(); it.join()
    elapsed = time.time() - t_start

    generate_report()

    n = stats['installed'] if stats['installed'] > 0 else 1
    print(f"\n=== 流水线完成 ===")
    print(f"总耗时: {elapsed/60:.1f}分钟")
    print(f"下载: {stats['downloaded']} 安装: {stats['installed']} 跳过: {stats['skipped']} 失败: {stats['failed']}")
    print(f"平均下载: {stats['total_dl']/n:.1f}s 检测: {stats['total_detect']/n:.1f}s 安装: {stats['total_install']/n:.1f}s 节点: {stats['total_node']/n:.1f}s")
    print(f"流水线加速比: {(stats['total_dl']+stats['total_install']+stats['total_node'])/elapsed:.2f}x" if elapsed > 0 else "")

if __name__ == '__main__':
    main()
