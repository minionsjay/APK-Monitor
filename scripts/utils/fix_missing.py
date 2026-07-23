#!/usr/bin/env python3
"""Re-process the two APKs that didn't get full config: 720ww55 and 720bh282."""
import subprocess
import json
import os
import re
import time
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
SAMPLES_DIR = "/home/ninini/Agents/APK-Research/new_samples"
ADB_DEVICE = "192.168.1.16:43351"

APKS_TO_FIX = [
    {'file': '720ww55_j8rh8w_top.apk', 'md5': 'bde7594267037e774a4b4a1da8c88597',
     'domains': ['720ww55.j8rh8w.top'],
     'download_url': 'https://0bdnuong9lih.1n1xdd.cc/Dqmy4H7u0w1frd07mwm622ghd/6n9e5u',
     'app_name': 'dh145', 'aes_key': 'gpTtoF31cUxTjrTo1m6iyDfFI28TK2Hh',
     'app_domain': '*.sdkvghty145.qianchixt.com', 'port': 30145,
     'sni': 'bilibili.com', 'sdk_version': '4.0.1',
     'dat_url': 'https://04ecc9508b9e674f.gz.bcebos.com/faddbf0d6fffc983.dat'},
    {'file': '720bh282_livs6_com.apk', 'md5': '79f5d5f0e0c4e9899efadb622c58ecbf',
     'domains': ['720bh282.livs6.com'],
     'download_url': 'https://1peg6he7uu0t.8nnxao.cc/176al/5t40lu'},
    # 721cpc06 has same config as 720pt1 (both dh176) - let's verify
    {'file': '721cpc06_i1bmh_com.apk', 'md5': '7339c33a7bcdc438ee854c305e4130a3',
     'domains': ['721cpc06.i1bmh.com'],
     'download_url': 'https://mbm9jtvk6owk.8nnxao.cc/jd/awp0so'},
]


def adb_shell(cmd, timeout=15):
    full = ['adb', '-s', ADB_DEVICE, 'shell', cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except:
        return ""


def install_and_extract(apk_path):
    """Install, launch, wait longer, extract."""
    r = subprocess.run(
        ['adb', '-s', ADB_DEVICE, 'install', '-r', '-t', apk_path],
        capture_output=True, text=True, timeout=120
    )
    if 'Success' not in r.stdout:
        print(f"  Install failed: {r.stdout[:100]}")
        return None
    
    # Get new package
    known_system = {
        'com.topjohnwu.magisk', 'ru.maximoff.apktool', 'com.netease.uuremote',
        'bin.mt.plus', 'com.github.metacubex.clash.meta', 'com.android.adbkeyboard',
        'io.github.muntashirakon.AppManager', 'com.emanuelef.remote_capture',
        'com.github.android', 'youqu.android.todesk', 'android.v2board.app',
        'com.wn.app.np', 'com.google.android.safetycore',
        'com.google.android.contactkeys',
    }
    with open(DB_PATH) as f:
        db = json.load(f)
    for a in db.get('apks', []):
        if a.get('package'):
            known_system.add(a['package'])
    
    result = adb_shell('pm list packages -3', timeout=10)
    new_pkg = None
    for line in result.split('\n'):
        line = line.strip()
        if line.startswith('package:'):
            pkg = line[8:]
            if pkg not in known_system:
                new_pkg = pkg
                break
    
    if not new_pkg:
        print(f"  No new package found")
        return None
    
    print(f"  Package: {new_pkg}")
    
    # Launch
    adb_shell(f'monkey -p {new_pkg} -c android.intent.category.LAUNCHER 1', timeout=10)
    print(f"  Launched, waiting 60s...")
    time.sleep(60)
    
    # Extract forwarder cache
    result = {'package': new_pkg, 'proxy_nodes': [], 'control_nodes': []}
    path = f'/sdcard/Android/data/{new_pkg}/files/sdk_forwarder_fixed.json'
    r = adb_shell(f'cat {path}', timeout=10)
    if r and '{' in r:
        try:
            data = json.loads(r)
            result['proxy_nodes'] = data.get('app_line_ips', [])
            result['port'] = data.get('app_line_port')
            result['config'] = data
            print(f"  Forwarder: {len(result['proxy_nodes'])} proxy nodes, port={result['port']}")
        except:
            pass
    
    # Read SDK cache
    path2 = f'/sdcard/Android/data/{new_pkg}/files/sdk_cache.json'
    r2 = adb_shell(f'cat {path2}', timeout=10)
    if r2 and '{' in r2:
        try:
            cache = json.loads(r2)
            entries = cache.get('entries', {})
            for url, info in entries.items():
                result['dat_url'] = url
                result['dat_payload_b64'] = info.get('payload_b64')
                break
            if result.get('dat_url'):
                print(f"  SDK cache: dat_url={result['dat_url'][:60]}...")
        except:
            pass
    
    # Read Go heap
    pid = adb_shell(f'pidof {new_pkg}', timeout=5)
    if pid:
        pid = pid.split()[0]
        print(f"  Go heap: PID={pid}")
        try:
            proc = subprocess.run(
                ['adb', '-s', ADB_DEVICE, 'shell',
                 f'timeout 10 su -c "dd if=/proc/{pid}/mem bs=4096 skip=67108864 count=2048 2>/dev/null"'],
                capture_output=True, timeout=20
            )
            heap = proc.stdout.decode('utf-8', errors='replace')
        except:
            heap = ''
        
        for pattern, key in [
            (r'"app_name"\s*:\s*"([^"]*)"', 'app_name'),
            (r'"AES-key"\s*:\s*"([^"]*)"', 'aes_key'),
            (r'"app_domain"\s*:\s*"([^"]*)"', 'app_domain'),
            (r'"app_domain_port"\s*:\s*(\d+)', 'port'),
            (r'"tls_sni_for_current_host"\s*:\s*"([^"]*)"', 'sni'),
            (r'"sdk_version"\s*:\s*"([^"]*)"', 'sdk_version'),
        ]:
            m = re.search(pattern, heap)
            if m:
                result[key] = m.group(1)
                print(f"  Heap: {key}={m.group(1)}")
    
    return result


def decrypt_dat(dat_url, aes_key):
    if not dat_url or not aes_key:
        return None
    try:
        import urllib.request
        if not dat_url.startswith('http'):
            dat_url = 'https://' + dat_url
        print(f"  Downloading .dat: {dat_url[:80]}...")
        req = urllib.request.Request(dat_url, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urllib.request.urlopen(req, timeout=20).read()
        print(f"  .dat size: {len(raw)} bytes")
        key = aes_key.encode()
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(raw)
        pt = unpad(pt, 16)
        return json.loads(pt.decode())
    except Exception as e:
        print(f"  .dat error: {e}")
        return None


def main():
    with open(DB_PATH) as f:
        db = json.load(f)
    
    for apk_info in APKS_TO_FIX:
        print(f"\n{'='*60}")
        print(f"Fixing: {apk_info['file']}")
        
        apk_path = os.path.join(SAMPLES_DIR, apk_info['file'])
        
        # Uninstall any previous
        for a in db.get('apks', []):
            if a.get('id') == apk_info['domains'][0].split('.')[0]:
                if a.get('package'):
                    adb_shell(f'pm uninstall {a["package"]}', timeout=10)
        
        # Install and extract
        result = install_and_extract(apk_path)
        
        if not result:
            # Use offline config if available
            if apk_info.get('aes_key'):
                result = {
                    'package': None,
                    'proxy_nodes': [],
                    'control_nodes': [],
                    'app_name': apk_info.get('app_name'),
                    'aes_key': apk_info.get('aes_key'),
                    'app_domain': apk_info.get('app_domain'),
                    'port': apk_info.get('port'),
                    'sni': apk_info.get('sni'),
                    'sdk_version': apk_info.get('sdk_version'),
                    'dat_url': apk_info.get('dat_url'),
                }
            else:
                continue
        
        # Decrypt .dat
        dat_url = result.get('dat_url') or apk_info.get('dat_url')
        aes_key = result.get('aes_key') or apk_info.get('aes_key')
        if dat_url and aes_key:
            nodes = decrypt_dat(dat_url, aes_key)
            if nodes:
                result['dat_decrypted'] = nodes
                for k in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                    result['control_nodes'].extend(nodes.get(k, []))
        
        # Update DB entry
        entry_id = apk_info['domains'][0].split('.')[0]
        db['apks'] = [a for a in db.get('apks', []) if a.get('id') != entry_id]
        
        entry = {
            'id': entry_id,
            'source': f"域名下载: {' + '.join(apk_info['domains'])}",
            'download_url': apk_info['download_url'],
            'apk_path': apk_path,
            'md5': apk_info['md5'],
            'package': result.get('package'),
            'app_name': result.get('app_name') or apk_info.get('app_name'),
            'app_domain': result.get('app_domain') or apk_info.get('app_domain'),
            'app_domain_port': result.get('port') or apk_info.get('port'),
            'aes_key': result.get('aes_key') or apk_info.get('aes_key'),
            'sni': result.get('sni') or apk_info.get('sni'),
            'sdk_version': result.get('sdk_version') or apk_info.get('sdk_version'),
            'dat_url': dat_url,
            'dat_decrypted': result.get('dat_decrypted'),
            'control_nodes': result.get('control_nodes', []),
            'proxy_nodes': result.get('proxy_nodes', []),
            'proxy_count': len(result.get('proxy_nodes', [])),
            'score': 160,
            'first_seen': datetime.now().strftime('%Y-%m-%d'),
            'last_collected': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'related_domains': apk_info['domains'],
        }
        
        db['apks'].append(entry)
        
        # Update global nodes
        for ip in result.get('proxy_nodes', []):
            if ip not in db.get('all_proxy_nodes', []):
                db.setdefault('all_proxy_nodes', []).append(ip)
        for node in result.get('control_nodes', []):
            ip = node.split(':')[0] if ':' in node else node
            if ip not in db.get('all_control_nodes', []):
                db.setdefault('all_control_nodes', []).append(ip)
        
        # Uninstall
        if result.get('package'):
            print(f"  Uninstalling {result['package']}...")
            adb_shell(f'pm uninstall {result["package"]}', timeout=15)
        
        # Save after each
        with open(DB_PATH, 'w') as f:
            json.dump(db, f, indent=2, ensure_ascii=False)
        
        print(f"  RESULT: app={entry['app_name']}, proxy={entry['proxy_count']}, ctrl={len(entry['control_nodes'])}")
    
    db['last_updated'] = datetime.now().strftime('%Y-%m-%d')
    with open(DB_PATH, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    
    print(f"\n=== DONE ===")
    print(f"Total APKs: {len(db['apks'])}")
    print(f"Total proxy nodes: {len(db.get('all_proxy_nodes', []))}")
    print(f"Total control nodes: {len(db.get('all_control_nodes', []))}")


if __name__ == '__main__':
    main()
