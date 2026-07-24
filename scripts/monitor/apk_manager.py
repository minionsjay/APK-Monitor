#!/usr/bin/env python3
"""
APK 批量监控系统 (方案3+4 改进版)
- 分批轮询：每次只监控 N 个 APK，下一轮接上
- 记录上次轮询到哪个位置，下次从下一个开始
- 所有 APK 都能覆盖到，不会遗漏
- 新 APK 自动加入轮询队列
- 存储不够时按 LRU 卸载

用法:
  python3 apk_manager.py --monitor         # 分批轮询（每次5个）
  python3 apk_manager.py --monitor --all   # 一次性全量轮询
  python3 apk_manager.py --download       # 从域名下载新APK
  python3 apk_manager.py --install         # 安装已下载的APK
  python3 apk_manager.py --cleanup        # 清理存储
  python3 apk_manager.py --full           # 全流程
  python3 apk_manager.py --status         # 查看状态
"""

import subprocess, json, os, time, re, csv, hashlib, zipfile
from datetime import datetime

ADB = "adb -s 192.168.1.16:38399"
AAPT = "/home/ninini/Agents/AI-APK/research/MARD/sandbox/android-sdk/build-tools/34.0.0/aapt"
BASE_DIR = "/home/ninini/Agents/APK-Research"
APK_DIR = f"{BASE_DIR}/new_samples"
DB_PATH = f"{BASE_DIR}/data/proxy_monitor_db.json"
DOMAIN_CSV = f"{BASE_DIR}/data/apk-domain.csv"
STATE_CSV = f"{BASE_DIR}/data/apk_state.csv"
CURSOR_FILE = f"{BASE_DIR}/data/monitor_cursor.json"
OUTPUTS_DIR = f"{BASE_DIR}/outputs"
STORAGE_THRESHOLD_GB = 5
BATCH_SIZE = 5  # 每次轮询5个APK

STATE_FIELDS = ['apk_id', 'package', 'label', 'score', 'size_mb',
                'first_installed', 'last_monitored', 'proxy_count',
                'huawei_count', 'installed_on_device', 'apk_path',
                'domain', 'download_url', 'status',
                'download_time', 'detect_time', 'install_time', 'node_time']

def get_cloud(ip):
    if ip.startswith('8.13') or ip.startswith('8.138') or ip.startswith('8.148') or ip.startswith('8.163'): return "阿里云"
    elif any(ip.startswith(p) for p in ['43.','42.','106.','159.75','139.','175.178','134.175','1.1','111.230','119.','123.207','129.204','193.112','115.175','139.9']): return "腾讯云"
    elif any(ip.startswith(p) for p in ['110.41','113.45','113.46','114.132','116.205','121.37','124.71']): return "华为云"
    return "未知"

def load_state():
    if not os.path.exists(STATE_CSV): return []
    with open(STATE_CSV, encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

def save_state(state):
    with open(STATE_CSV, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=STATE_FIELDS)
        writer.writeheader()
        writer.writerows(state)

def load_db():
    with open(DB_PATH) as f: return json.load(f)

def save_db(db):
    with open(DB_PATH, 'w') as f: json.dump(db, f, indent=2, ensure_ascii=False)

def load_cursor():
    if not os.path.exists(CURSOR_FILE): return 0
    with open(CURSOR_FILE) as f: return json.load(f).get('cursor', 0)

def save_cursor(cursor):
    with open(CURSOR_FILE, 'w') as f: json.dump({'cursor': cursor, 'updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, f)

def get_storage_gb():
    result = subprocess.run(f'{ADB} shell df /data'.split(), capture_output=True, text=True, timeout=10)
    for line in result.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 4 and '/data' in line:
            return int(parts[3]) // 1024 // 1024
    return 0

def detect_apk(apk_path):
    result = subprocess.run([AAPT, 'dump', 'badging', apk_path], capture_output=True, text=True, timeout=10)
    pkg = ''; label = ''
    for line in result.stdout.split('\n'):
        if line.startswith('package:'):
            pkg = line.split("name='")[1].split("'")[0] if "name='" in line else ''
        if line.startswith('application-label:'):
            label = line.split("'")[1] if "'" in line else ''
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        so_files = [n for n in names if n.endswith('.so')]
        score = 0
        if any('libgojni' in n for n in so_files): score += 40
        if any(len(n) > 20 and n.startswith('lib/') and n.endswith('.so') and 'gojni' not in n for n in so_files): score += 40
        if any('WgSnp' in n or 'TifMz' in n for n in names): score += 40
    return score, pkg, label

def click_popup():
    """检测并点击通知弹窗"""
    for _ in range(2):
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
        time.sleep(1)
    return False

def get_proxy_nodes(pkg, max_wait=30):
    """获取代理节点，每5秒检查一次"""
    for i in range(max_wait // 5):
        time.sleep(5)
        result = subprocess.run(f'{ADB} shell cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json'.split(),
                              capture_output=True, text=True, timeout=5)
        if result.stdout and result.stdout.strip().startswith('{'):
            try:
                data = json.loads(result.stdout)
                nodes = data.get('app_line_ips', [])
                if nodes: return nodes
            except:
                pass
    return []

def monitor_batch(state, batch, cursor, total):
    """监控一批 APK"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f'{OUTPUTS_DIR}/{ts}'
    os.makedirs(out_dir, exist_ok=True)

    results = []
    for i, entry in enumerate(batch):
        pkg = entry['package']
        name = entry['apk_id']
        global_idx = cursor + i
        print(f"  [{global_idx+1}/{total}] {name} ({entry.get('label','')})...", end=' ')

        # 启动
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                      capture_output=True, timeout=10)
        time.sleep(3)

        # 点击弹窗
        click_popup()

        # 获取节点
        nodes = get_proxy_nodes(pkg)
        hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]

        # 停止
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(),
                      capture_output=True, timeout=5)

        # 更新状态
        entry['last_monitored'] = now
        entry['proxy_count'] = str(len(nodes))
        entry['huawei_count'] = str(len(hw_ips))
        entry['status'] = 'ok' if nodes else 'no_nodes'

        r = {'name': name, 'package': pkg, 'proxy_nodes': nodes,
             'proxy_count': len(nodes), 'huawei_ips': hw_ips,
             'huawei_count': len(hw_ips), 'timestamp': ts}
        results.append(r)
        print(f"{len(nodes)} 节点, {len(hw_ips)} 华为")

    # 保存结果
    with open(f'{out_dir}/result.json', 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # 更新数据库
    db = load_db()
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
    save_db(db)
    save_state(state)

    total_p = sum(r['proxy_count'] for r in results)
    total_h = sum(r['huawei_count'] for r in results)
    print(f"  本批: {len(results)} APK, {total_p} 节点, {total_h} 华为")
    print(f"  结果: {out_dir}/")

    # 生成 HTML
    subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py'], timeout=60)
    return results

def cmd_monitor(state, monitor_all=False):
    """分批轮询已安装的 APK"""
    installed = [e for e in state if e.get('installed_on_device') == 'true'
                 and e.get('status') in ('installed', 'ok', 'no_nodes')]
    total = len(installed)
    if not installed:
        print("没有已安装的 APK")
        return

    if monitor_all:
        print(f"全量轮询 {total} 个 APK...")
        monitor_batch(state, installed, 0, total)
        save_cursor(0)
        print(f"全量轮询完成，游标重置为 0")
    else:
        cursor = load_cursor()
        if cursor >= total:
            cursor = 0
            print(f"新的一轮，游标重置为 0")

        batch = installed[cursor:cursor + BATCH_SIZE]
        actual_batch = len(batch)
        print(f"分批轮询 [{cursor+1}-{cursor+actual_batch}/{total}]，本批 {actual_batch} 个 APK")
        monitor_batch(state, batch, cursor, total)
        new_cursor = cursor + actual_batch
        if new_cursor >= total:
            new_cursor = 0
            print(f"本轮全部覆盖完成，游标重置为 0，下次从头开始")
        save_cursor(new_cursor)
        print(f"下次从 {new_cursor+1}/{total} 开始")

def cmd_pipeline(state, max_count=0):
    """流水线：下载→检测→安装→获取节点→停止，一个一个来"""
    with open(DOMAIN_CSV, encoding='utf-8-sig') as f:
        domains = list(csv.DictReader(f))

    existing_ids = {e['apk_id'] for e in state}
    existing_pkgs = {e['package'] for e in state if e.get('package')}
    installed_pkgs = set()
    r = subprocess.run(f'{ADB} shell pm list packages -3'.split(), capture_output=True, text=True, timeout=10)
    for line in r.stdout.split('\n'):
        if line.startswith('package:'):
            installed_pkgs.add(line.replace('package:','').strip())

    processed = 0
    for i, d in enumerate(domains):
        if max_count and processed >= max_count:
            break

        domain = d.get('pre_host', '')
        url = d.get('max(prev)', f'https://{domain}/')

        if domain in existing_ids:
            continue

        print(f"[{i+1}/{len(domains)}] {domain}", end=' ')

        # 1. 下载
        try:
            r = subprocess.run(['curl','-sk','-L','--connect-timeout','8',url],
                             capture_output=True, text=True, timeout=12)
            html = r.stdout
            if not html or len(html) < 50:
                print('无响应'); continue

            android_urls = re.findall(r'android["\s]*:["\s]*"([^"]+)"', html)
            android_url2 = re.findall(r'androidUrl["\s]*:["\s]*"([^"]+)"', html)
            redirect = re.findall(r'window\.location\s*=\s*"([^"]+)"', html)
            dl = None
            if android_urls: dl = android_urls[0]
            elif android_url2: dl = android_url2[0]
            elif redirect: dl = redirect[0]
            else:
                print('无APK链接'); continue

            out_path = f'{APK_DIR}/{domain}.apk'
            subprocess.run(['curl','-sk','-L','--connect-timeout','15','-o',out_path,dl],
                          capture_output=True, timeout=120)
            if not os.path.exists(out_path) or os.path.getsize(out_path) < 1000000:
                if os.path.exists(out_path): os.remove(out_path)
                print('下载失败'); continue
            with open(out_path,'rb') as f:
                if f.read(4) != b'PK\x03\x04':
                    os.remove(out_path); print('非APK'); continue
        except:
            print('下载超时'); continue

        # 2. 检测
        score, pkg, label = detect_apk(out_path)
        size_mb = os.path.getsize(out_path) // 1024 // 1024
        if score < 80:
            os.remove(out_path); print(f'非恶意(score={score})'); continue
        if pkg in existing_pkgs:
            os.remove(out_path); print(f'包名冲突({pkg[:20]}...)'); continue

        print(f'({label},{size_mb}MB)', end=' ')

        # 3. 安装
        if get_storage_gb() < STORAGE_THRESHOLD_GB:
            print('存储不足，清理...')
            cmd_cleanup(state)
            r = subprocess.run(f'{ADB} shell pm list packages -3'.split(), capture_output=True, text=True, timeout=10)
            installed_pkgs.clear()
            for line in r.stdout.split('\n'):
                if line.startswith('package:'):
                    installed_pkgs.add(line.replace('package:','').strip())

        if pkg in installed_pkgs:
            subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)

        r = subprocess.run(f'{ADB} install -r {out_path}'.split(),
                          capture_output=True, text=True, timeout=120)
        if 'Success' not in r.stdout:
            print('安装失败'); continue
        installed_pkgs.add(pkg)
        print('✅安装', end=' ')

        # 4. 启动+弹窗+获取节点
        subprocess.run(f'{ADB} shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1'.split(),
                      capture_output=True, timeout=10)
        time.sleep(3)
        click_popup()
        nodes = get_proxy_nodes(pkg)
        hw_ips = [ip for ip in nodes if get_cloud(ip) == "华为云"]
        subprocess.run(f'{ADB} shell am force-stop {pkg}'.split(),
                      capture_output=True, timeout=5)

        # 5. 记录
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        entry = {'apk_id': domain, 'package': pkg, 'label': label,
                 'score': str(score), 'size_mb': str(size_mb),
                 'first_installed': now, 'last_monitored': now,
                 'proxy_count': str(len(nodes)), 'huawei_count': str(len(hw_ips)),
                 'installed_on_device': 'true', 'apk_path': out_path,
                 'domain': domain, 'download_url': url,
                 'status': 'ok' if nodes else 'no_nodes'}
        state.append(entry)
        existing_ids.add(domain)
        existing_pkgs.add(pkg)

        # 更新数据库
        db = load_db()
        all_proxy = set(db.get('all_proxy_nodes', []))
        db['apks'].append({'id': domain, 'package': pkg, 'label': label,
                          'app_name': '', 'app_domain_port': '',
                          'proxy_nodes': nodes, 'proxy_count': len(nodes),
                          'first_seen': now, 'last_collected': now})
        for ip in nodes:
            all_proxy.add(ip)
        db['all_proxy_nodes'] = sorted(all_proxy)
        save_db(db)
        save_state(state)

        print(f'节点={len(nodes)} 华为={len(hw_ips)}')
        processed += 1

        # 每10个生成一次HTML
        if processed % 10 == 0:
            subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py'], timeout=60)

    # 最后生成HTML
    subprocess.run(['python3', f'{BASE_DIR}/scripts/monitor/regen_html.py'], timeout=60)
    print(f"\n=== 流水线完成 ===")
    print(f"处理: {processed} 个新 APK")

def cmd_download(state):
    with open(DOMAIN_CSV, encoding='utf-8-sig') as f:
        domains = list(csv.DictReader(f))
    print(f"共 {len(domains)} 个域名")
    existing_ids = {e['apk_id'] for e in state}
    existing_pkgs = {e['package'] for e in state if e.get('package')}
    new_count = 0; skip = 0; fail = 0
    for i, d in enumerate(domains):
        domain = d.get('pre_host', '')
        url = d.get('max(prev)', f'https://{domain}/')
        if domain in existing_ids:
            skip += 1; continue
        if (i+1) % 50 == 0:
            print(f"  [{i+1}/{len(domains)}] 新={new_count} 跳过={skip} 失败={fail}")
        try:
            r = subprocess.run(['curl','-sk','-L','--connect-timeout','8',url],
                             capture_output=True, text=True, timeout=12)
            html = r.stdout
            if not html or len(html) < 50:
                fail += 1; continue
            android_urls = re.findall(r'android["\s]*:["\s]*"([^"]+)"', html)
            android_url2 = re.findall(r'androidUrl["\s]*:["\s]*"([^"]+)"', html)
            redirect = re.findall(r'window\.location\s*=\s*"([^"]+)"', html)
            dl = None
            if android_urls: dl = android_urls[0]
            elif android_url2: dl = android_url2[0]
            elif redirect: dl = redirect[0]
            else: fail += 1; continue
            out_path = f'{APK_DIR}/{domain}.apk'
            subprocess.run(['curl','-sk','-L','--connect-timeout','15','-o',out_path,dl],
                          capture_output=True, timeout=120)
            if not os.path.exists(out_path) or os.path.getsize(out_path) < 1000000:
                if os.path.exists(out_path): os.remove(out_path)
                fail += 1; continue
            with open(out_path,'rb') as f:
                if f.read(4) != b'PK\x03\x04':
                    os.remove(out_path); fail += 1; continue
            score, pkg, label = detect_apk(out_path)
            size_mb = os.path.getsize(out_path) // 1024 // 1024
            if score < 80:
                os.remove(out_path); fail += 1; continue
            if pkg in existing_pkgs:
                os.remove(out_path); skip += 1; continue
            entry = {'apk_id': domain, 'package': pkg, 'label': label,
                     'score': str(score), 'size_mb': str(size_mb),
                     'first_installed': '', 'last_monitored': '',
                     'proxy_count': '0', 'huawei_count': '0',
                     'installed_on_device': 'false', 'apk_path': out_path,
                     'domain': domain, 'download_url': url, 'status': 'downloaded'}
            state.append(entry)
            existing_ids.add(domain); existing_pkgs.add(pkg)
            new_count += 1
            print(f"  ✅ {domain} ({label}, {size_mb}MB)")
        except:
            fail += 1
        if (i+1) % 10 == 0:
            save_state(state)
    save_state(state)
    print(f"下载完成: 新={new_count} 跳过={skip} 失败={fail}")

def cmd_install(state):
    storage = get_storage_gb()
    print(f"手机存储: {storage}GB")
    installed_pkgs = set()
    result = subprocess.run(f'{ADB} shell pm list packages -3'.split(),
                           capture_output=True, text=True, timeout=10)
    for line in result.stdout.split('\n'):
        if line.startswith('package:'):
            installed_pkgs.add(line.replace('package:','').strip())
    new_count = 0
    for entry in state:
        if entry.get('status') != 'downloaded': continue
        if entry.get('installed_on_device') == 'true': continue
        pkg = entry['package']
        if get_storage_gb() < STORAGE_THRESHOLD_GB:
            print("存储不足，先清理...")
            cmd_cleanup(state)
        if pkg in installed_pkgs:
            subprocess.run(f'{ADB} uninstall {pkg}'.split(), capture_output=True, timeout=30)
        print(f"  安装 {entry['apk_id']}...", end=' ')
        r = subprocess.run(f'{ADB} install -r {entry["apk_path"]}'.split(),
                          capture_output=True, text=True, timeout=120)
        if 'Success' in r.stdout:
            entry['installed_on_device'] = 'true'
            entry['status'] = 'installed'
            entry['first_installed'] = datetime.now().strftime('%Y-%m-%d %H:%M')
            installed_pkgs.add(pkg)
            new_count += 1
            print("✅")
        else:
            entry['status'] = 'install_failed'
            print("❌")
    save_state(state)
    print(f"安装完成: {new_count} 个")

def cmd_cleanup(state):
    storage = get_storage_gb()
    if storage >= STORAGE_THRESHOLD_GB:
        print(f"存储充足: {storage}GB")
        return 0
    installed = [e for e in state if e.get('installed_on_device') == 'true']
    installed.sort(key=lambda x: x.get('last_monitored', ''))
    removed = 0
    for entry in installed:
        if get_storage_gb() >= STORAGE_THRESHOLD_GB + 5: break
        subprocess.run(f'{ADB} uninstall {entry["package"]}'.split(), capture_output=True, timeout=30)
        entry['installed_on_device'] = 'false'
        entry['status'] = 'uninstalled_lru'
        removed += 1
    save_state(state)
    print(f"清理: 卸载 {removed} 个, 当前 {get_storage_gb()}GB")
    return removed

def cmd_status(state):
    installed = [e for e in state if e.get('installed_on_device') == 'true']
    downloaded = [e for e in state if e.get('status') == 'downloaded']
    ok = [e for e in state if e.get('status') == 'ok']
    cursor = load_cursor()
    total_installed = len(installed)
    print(f"=== APK 监控状态 ===")
    print(f"总计: {len(state)} 个 APK")
    print(f"已安装: {total_installed}")
    print(f"已下载未安装: {len(downloaded)}")
    print(f"监控正常: {len(ok)}")
    print(f"手机存储: {get_storage_gb()}GB")
    print(f"轮询游标: {cursor}/{total_installed} (下次从第 {cursor+1} 个开始)")
    print(f"每批: {BATCH_SIZE} 个, 全覆盖需 {((total_installed + BATCH_SIZE - 1) // BATCH_SIZE)} 轮")
    if installed:
        print(f"\n已安装 APK 列表:")
        for i, e in enumerate(installed):
            mark = "→" if i == cursor else " "
            print(f"  {mark} [{i+1}] {e['apk_id']} ({e.get('label','')}) 节点={e.get('proxy_count','0')} 上次={e.get('last_monitored','')}")

if __name__ == '__main__':
    import sys
    state = load_state()
    cmd = sys.argv[1] if len(sys.argv) > 1 else '--status'
    if cmd == '--monitor':
        monitor_all = '--all' in sys.argv
        cmd_monitor(state, monitor_all)
    elif cmd == '--pipeline':
        max_count = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        cmd_pipeline(state, max_count)
    elif cmd == '--download': cmd_download(state)
    elif cmd == '--install': cmd_install(state)
    elif cmd == '--cleanup': cmd_cleanup(state)
    elif cmd == '--full':
        cmd_download(state); cmd_install(state); cmd_monitor(state); cmd_cleanup(state)
    elif cmd == '--status': cmd_status(state)
    else:
        print(f"用法: python3 apk_manager.py [--pipeline [N]|--monitor [--all]|--download|--install|--cleanup|--full|--status]")
