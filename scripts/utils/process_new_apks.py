#!/usr/bin/env python3
"""Process newly downloaded APKs: install, extract nodes, update DB."""
import subprocess
import json
import os
import re
import time
import base64
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
SAMPLES_DIR = "/home/ninini/Agents/APK-Research/new_samples"
ADB_DEVICE = "192.168.1.16:43351"

# Known packages already in DB
KNOWN_PKGS = {
    'bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns', 'ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc',
    'gjithpd.enjfpfakiubo.amkrrlirim', 'com.topjohnwu.magisk', 'ru.maximoff.apktool',
    'com.netease.uuremote', 'bin.mt.plus', 'com.github.metacubex.clash.meta',
    'com.android.adbkeyboard', 'io.github.muntashirakon.AppManager',
    'com.emanuelef.remote_capture', 'com.github.android', 'youqu.android.todesk',
    'android.v2board.app', 'com.wn.app.np', 'com.google.android.safetycore',
    'com.google.android.contactkeys', 'net.f7df3up4.cxo1cw', 'jnNPfy.SNrsaS.eOtCtk',
    'cii.gjjvikjqhhupaab.aaoknxedxpgnwa', 'com.qdvvgnzdnhiqqbf.ooyblxyrjmluulgbgdek',
    'ldp.swtacwpthqoe.cyfueitnswummxsjngda',
    'ybp.kdxrbdjkfyfa.khdcpdgopxndqpbuyj', 'sgv.wdbijuhlemtbj.unvvkhfxfameqhldorq',
    'oow.fufsegdrnlxs.obarucmklnbikqfiqyxr', 'cngjlbmff.evjkbhwcetabwgyw.chqnfkne',
    'jlu.clisymxohrsrbcw.otmxtcihooocbacdecuc', 'ait.bwucaomsepjdbgy.dbpndjdbpunguop',
    # System/utility packages
    'l7v_1rpq9kz9tkz9ozf8_.ph727_ykyxyb0rmisr6_w9c.cy_n8gm6afl6shjsvxmfkc5esfbse',
}

# New unique APKs to process (one per unique MD5)
NEW_APKS = [
    {
        'file': '721sf5_9ursg_top.apk',
        'md5': 'b801e4b9183144a9b2a8f7c30aebad32',
        'domains': ['721sf5.9ursg.top', '720a275.w8zc3.com'],
        'download_url': 'http://s2uwgne8dmgq.s3-website.us-west-1.amazonaws.com/jsyd/zaeuas.hbbu',
    },
    {
        'file': '720ww55_j8rh8w_top.apk',
        'md5': 'bde7594267037e774a4b4a1da8c88597',
        'domains': ['720ww55.j8rh8w.top'],
        'download_url': 'https://0bdnuong9lih.1n1xdd.cc/Dqmy4H7u0w1frd07mwm622ghd/6n9e5u',
    },
    {
        'file': '721yh118_6p3n0_com.apk',
        'md5': '459b65abd14cb264e82bebf3348fa5e4',
        'domains': ['721yh118.6p3n0.com', '721yh366.0x8ls.com', '721yh485.z3x4k.com'],
        'download_url': 'https://he2h91t5aho5.784w47.cc/YH/e7kdnb',
    },
    {
        'file': '721cpa5_vbbon_com.apk',
        'md5': '100da829bad40f49a40db80b249171c9',
        'domains': ['721cpa5.vbbon.com'],
        'download_url': 'https://65m2v74ujvmw.7bq47o.cc/arjs/zkh9c1',
    },
    {
        'file': '720pt1_eeaq5_com.apk',
        'md5': '48f4d5819e99db6f4bd586dcf79446d1',
        'domains': ['720pt1.eeaq5.com', '720pt2.dpuhv.top', '721pt1.k2ebr.top'],
        'download_url': 'https://6abyzqv1hpy7.8cgxy2.cc/ysci9dz4k52tuij/1hst5q',
    },
    {
        'file': '720bh282_livs6_com.apk',
        'md5': '79f5d5f0e0c4e9899efadb622c58ecbf',
        'domains': ['720bh282.livs6.com'],
        'download_url': 'https://1peg6he7uu0t.8nnxao.cc/176al/5t40lu',
    },
    {
        'file': '721cpc06_i1bmh_com.apk',
        'md5': '7339c33a7bcdc438ee854c305e4130a3',
        'domains': ['721cpc06.i1bmh.com'],
        'download_url': 'https://mbm9jtvk6owk.8nnxao.cc/jd/awp0so',
    },
]


def load_db():
    with open(DB_PATH) as f:
        return json.load(f)


def save_db(db):
    with open(DB_PATH, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def adb_shell(cmd, timeout=15):
    """Run adb shell command."""
    full = ['adb', '-s', ADB_DEVICE, 'shell', cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"


def install_apk(apk_path):
    """Install APK and return the new package name."""
    # Uninstall any previous version of the same APK first (to detect new package)
    print(f"  Installing {apk_path}...")
    r = subprocess.run(
        ['adb', '-s', ADB_DEVICE, 'install', '-r', '-t', apk_path],
        capture_output=True, text=True, timeout=120
    )
    if 'Success' in r.stdout:
        print(f"  Install success")
    else:
        print(f"  Install output: {r.stdout[:200]} {r.stderr[:200]}")
    
    # List third-party packages and find new ones
    result = adb_shell('pm list packages -3', timeout=10)
    new_pkgs = []
    for line in result.split('\n'):
        line = line.strip()
        if line.startswith('package:'):
            pkg = line[8:]
            if pkg not in KNOWN_PKGS:
                new_pkgs.append(pkg)
    
    return new_pkgs


def launch_app(package):
    """Launch the app and wait for Go SDK initialization."""
    adb_shell(f'monkey -p {package} -c android.intent.category.LAUNCHER 1', timeout=10)
    print(f"  Launched {package}, waiting 45s for SDK init...")
    time.sleep(45)


def read_forwarder_cache(package):
    """Read sdk_forwarder_fixed.json from device."""
    result = {
        'proxy_nodes': [],
        'port': None,
        'config': {},
    }
    
    # Try direct cat (not su)
    path = f'/sdcard/Android/data/{package}/files/sdk_forwarder_fixed.json'
    r = adb_shell(f'cat {path}', timeout=10)
    if r and not r.startswith('cat:'):
        try:
            data = json.loads(r)
            result['proxy_nodes'] = data.get('app_line_ips', [])
            result['port'] = data.get('app_line_port')
            result['config'] = data
            print(f"  Forwarder cache: {len(result['proxy_nodes'])} proxy nodes, port={result['port']}")
            return result
        except:
            pass
    
    # Try su
    r2 = adb_shell(f'su -c "cat {path}"', timeout=10)
    if r2 and not r2.startswith('cat:') and 'No such file' not in r2:
        try:
            data = json.loads(r2)
            result['proxy_nodes'] = data.get('app_line_ips', [])
            result['port'] = data.get('app_line_port')
            result['config'] = data
            print(f"  Forwarder cache (su): {len(result['proxy_nodes'])} proxy nodes, port={result['port']}")
            return result
        except:
            pass
    
    print(f"  Forwarder cache: not found")
    return result


def read_sdk_cache(package):
    """Read sdk_cache.json for dat URL and payload."""
    result = {'dat_url': None, 'dat_payload_b64': None}
    
    path = f'/sdcard/Android/data/{package}/files/sdk_cache.json'
    r = adb_shell(f'cat {path}', timeout=10)
    if r and 'No such file' not in r and not r.startswith('cat:'):
        try:
            cache = json.loads(r)
            entries = cache.get('entries', {})
            for url, info in entries.items():
                result['dat_url'] = url
                result['dat_payload_b64'] = info.get('payload_b64')
                break
            if result['dat_url']:
                print(f"  SDK cache: dat_url={result['dat_url'][:60]}...")
        except:
            pass
    
    if not result['dat_url']:
        # Try su
        r2 = adb_shell(f'su -c "cat {path}"', timeout=10)
        if r2 and 'No such file' not in r2 and not r2.startswith('cat:'):
            try:
                cache = json.loads(r2)
                entries = cache.get('entries', {})
                for url, info in entries.items():
                    result['dat_url'] = url
                    result['dat_payload_b64'] = info.get('payload_b64')
                    break
                if result['dat_url']:
                    print(f"  SDK cache (su): dat_url={result['dat_url'][:60]}...")
            except:
                    pass
    
    if not result['dat_url']:
        print(f"  SDK cache: not found")
    return result


def read_go_heap(package):
    """Read Go heap memory for config extraction."""
    result = {'app_name': None, 'aes_key': None, 'app_domain': None, 'port': None, 'sni': None}
    
    pid = adb_shell(f'pidof {package}', timeout=5)
    if not pid or 'ERROR' in pid:
        print(f"  Go heap: no PID for {package}")
        return result
    
    pid = pid.split()[0]  # In case multiple PIDs
    print(f"  Go heap: PID={pid}, reading memory...")
    
    # Read heap without su first (will likely fail), then try su
    # Use direct dd with timeout to avoid hang
    r = adb_shell(f'dd if=/proc/{pid}/mem bs=4096 skip=67108864 count=2048 2>/dev/null', timeout=15)
    
    if not r or len(r) < 100:
        # Try su with explicit timeout
        try:
            proc = subprocess.run(
                ['adb', '-s', ADB_DEVICE, 'shell',
                 f'timeout 10 su -c "dd if=/proc/{pid}/mem bs=4096 skip=67108864 count=2048 2>/dev/null"'],
                capture_output=True, timeout=20
            )
            r = proc.stdout.decode('utf-8', errors='replace')
        except:
            r = ''
    
    if not r:
        # Try a different memory region
        r = adb_shell(f'su -c "dd if=/proc/{pid}/mem bs=4096 skip=33554432 count=4096 2>/dev/null"', timeout=15)
    
    # Search for config patterns
    patterns = [
        (r'"app_name"\s*:\s*"([^"]*)"', 'app_name'),
        (r'"AES-key"\s*:\s*"([^"]*)"', 'aes_key'),
        (r'"app_domain"\s*:\s*"([^"]*)"', 'app_domain'),
        (r'"app_domain_port"\s*:\s*(\d+)', 'port'),
        (r'"tls_sni_for_current_host"\s*:\s*"([^"]*)"', 'sni'),
        (r'"sdk_version"\s*:\s*"([^"]*)"', 'sdk_version'),
    ]
    
    for pattern, key in patterns:
        m = re.search(pattern, r)
        if m:
            result[key] = m.group(1)
            print(f"  Go heap: {key}={m.group(1)}")
    
    # Also search for complete SDK state JSON
    m = re.search(r'\{"prepared".*?"payload":\{[^}]+\}.*?"state"', r)
    if m:
        try:
            sdk = json.loads(m.group(0))
            payload = sdk.get('payload', {})
            if payload.get('app_name'):
                result['app_name'] = payload['app_name']
            if payload.get('AES-key'):
                result['aes_key'] = payload['AES-key']
            if payload.get('app_domain'):
                result['app_domain'] = payload['app_domain']
            if payload.get('app_domain_port'):
                result['port'] = int(payload['app_domain_port'])
            result['sni'] = sdk.get('tls_sni_for_current_host', result.get('sni'))
        except:
            pass
    
    # Search for AES key pattern (32-char alphanumeric)
    if not result.get('aes_key'):
        # Look in strings for known AES key patterns
        m = re.search(r'([A-Za-z0-9]{32})', r)
        if m:
            candidate = m.group(1)
            # Check if it looks like an AES key (has mixed case and digits)
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            if has_upper and has_lower and has_digit:
                result['aes_key'] = candidate
                print(f"  Go heap: aes_key candidate={candidate}")
    
    if not result.get('app_name'):
        print(f"  Go heap: no config found (read {len(r)} bytes)")
    
    return result


def decrypt_dat(dat_url, aes_key, payload_b64=None):
    """Download and decrypt .dat control plane nodes."""
    if not aes_key:
        return None, None
    
    try:
        import urllib.request
        if not dat_url:
            return None, None
        
        # Ensure URL has scheme
        if not dat_url.startswith('http'):
            dat_url = 'https://' + dat_url
        
        print(f"  Downloading .dat from {dat_url[:80]}...")
        req = urllib.request.Request(dat_url, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urllib.request.urlopen(req, timeout=20).read()
        print(f"  .dat size: {len(raw)} bytes")
        
        # Decrypt with AES-CBC
        key = aes_key.encode() if isinstance(aes_key, str) else aes_key
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(raw)
        try:
            pt = unpad(pt, 16)
        except:
            # Try without unpad
            pass
        
        try:
            nodes = json.loads(pt.decode())
            return nodes, raw.hex()[:100]
        except:
            # Maybe the payload is base64 encoded
            if payload_b64:
                data = base64.b64decode(payload_b64)
                cipher2 = AES.new(key, AES.MODE_CBC, iv=key[:16])
                pt2 = cipher2.decrypt(data)
                pt2 = unpad(pt2, 16)
                nodes = json.loads(pt2.decode())
                return nodes, None
            return None, None
    except Exception as e:
        print(f"  .dat decrypt error: {e}")
        return None, None


def extract_app_name_from_dat_url(app_name, sdk_version, aes_key):
    """Try to compute and download .dat from offline method."""
    if not app_name or not sdk_version or not aes_key:
        return None
    
    try:
        import urllib.request
        date = datetime.now().strftime('%Y%m%d')
        md5 = hashlib.md5(f'{date}{app_name}oss{sdk_version}'.encode()).hexdigest()
        url = f'https://{md5[:16]}.oss-accelerate.aliyuncs.com/{md5[16:32]}.dat'
        print(f"  Trying offline .dat: {url}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urllib.request.urlopen(req, timeout=15).read()
        print(f"  .dat size: {len(raw)} bytes")
        
        key = aes_key.encode()
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(raw)
        pt = unpad(pt, 16)
        nodes = json.loads(pt.decode())
        return nodes
    except Exception as e:
        print(f"  Offline .dat failed: {e}")
        return None


def process_one_apk(apk_info):
    """Process a single new APK."""
    apk_path = os.path.join(SAMPLES_DIR, apk_info['file'])
    print(f"\n{'='*60}")
    print(f"Processing: {apk_info['file']}")
    print(f"  MD5: {apk_info['md5']}")
    print(f"  Domains: {', '.join(apk_info['domains'])}")
    print(f"  Download URL: {apk_info['download_url']}")
    
    # 1. Install
    new_pkgs = install_apk(apk_path)
    if not new_pkgs:
        print("  No new package found after install - trying to find by matching APK")
        # The APK might replace an existing package
        # Let's check all packages and try to find which one has this APK
        # Try launching known packages from same domains
        print("  Checking if APK replaced an existing package...")
        result = None
    else:
        package = new_pkgs[0]
        print(f"  New package: {package}")
        
        # 2. Launch and wait
        launch_app(package)
        
        # 3. Read forwarder cache
        fwd = read_forwarder_cache(package)
        
        # 4. Read SDK cache for dat URL
        cache = read_sdk_cache(package)
        
        # 5. Read Go heap
        heap = read_go_heap(package)
        
        # 6. Try to decrypt .dat
        control_nodes = []
        dat_decrypted = None
        dat_url = cache.get('dat_url')
        aes_key = heap.get('aes_key')
        
        if dat_url and aes_key:
            nodes, _ = decrypt_dat(dat_url, aes_key, cache.get('dat_payload_b64'))
            if nodes:
                dat_decrypted = nodes
                for key in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                    if key in nodes:
                        control_nodes.extend(nodes[key])
                print(f"  Control nodes from .dat: {len(control_nodes)}")
        
        # 7. Try offline .dat
        if not control_nodes and heap.get('app_name') and heap.get('sdk_version') and aes_key:
            nodes = extract_app_name_from_dat_url(
                heap.get('app_name'), heap.get('sdk_version'), aes_key
            )
            if nodes:
                dat_decrypted = nodes
                for key in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                    if key in nodes:
                        control_nodes.extend(nodes[key])
                print(f"  Control nodes from offline .dat: {len(control_nodes)}")
        
        # 8. Compile result
        result = {
            'package': package,
            'proxy_nodes': fwd.get('proxy_nodes', []),
            'control_nodes': control_nodes,
            'config': fwd.get('config', {}),
            'dat_url': dat_url,
            'dat_decrypted': dat_decrypted,
            'aes_key': aes_key,
            'app_name': heap.get('app_name'),
            'app_domain': heap.get('app_domain'),
            'app_domain_port': heap.get('port'),
            'sni': heap.get('sni'),
            'sdk_version': heap.get('sdk_version'),
        }
        
        print(f"\n  Summary:")
        print(f"    Package: {package}")
        print(f"    App name: {result['app_name']}")
        print(f"    AES key: {result['aes_key']}")
        print(f"    App domain: {result['app_domain']}")
        print(f"    Port: {result['app_domain_port']}")
        print(f"    SNI: {result['sni']}")
        print(f"    Proxy nodes: {len(result['proxy_nodes'])}")
        print(f"    Control nodes: {len(result['control_nodes'])}")
    
    return result


def update_db(db, apk_info, result):
    """Update the database with new APK info."""
    if not result:
        return
    
    # Create entry
    entry_id = apk_info['domains'][0].split('.')[0]  # e.g. "721sf5"
    apk_entry = {
        'id': entry_id,
        'source': f"域名下载: {' + '.join(apk_info['domains'])}",
        'download_url': apk_info['download_url'],
        'apk_path': os.path.join(SAMPLES_DIR, apk_info['file']),
        'md5': apk_info['md5'],
        'package': result.get('package'),
        'app_name': result.get('app_name'),
        'app_domain': result.get('app_domain'),
        'app_domain_port': result.get('app_domain_port'),
        'aes_key': result.get('aes_key'),
        'sni': result.get('sni'),
        'sdk_version': result.get('sdk_version'),
        'dat_url': result.get('dat_url'),
        'dat_decrypted': result.get('dat_decrypted'),
        'control_nodes': result.get('control_nodes', []),
        'proxy_nodes': result.get('proxy_nodes', []),
        'proxy_count': len(result.get('proxy_nodes', [])),
        'score': 160,
        'first_seen': datetime.now().strftime('%Y-%m-%d'),
        'last_collected': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'related_domains': apk_info['domains'],
    }
    
    db['apks'].append(apk_entry)
    
    # Update global node lists
    for ip in result.get('proxy_nodes', []):
        if ip not in db.get('all_proxy_nodes', []):
            db.setdefault('all_proxy_nodes', []).append(ip)
    for node in result.get('control_nodes', []):
        ip = node.split(':')[0] if ':' in node else node
        if ip not in db.get('all_control_nodes', []):
            db.setdefault('all_control_nodes', []).append(ip)
    
    # Update known domains
    for domain in apk_info['domains']:
        if not any(d.get('domain') == domain for d in db.get('known_domains', [])):
            db.setdefault('known_domains', []).append({
                'domain': domain,
                'download_method': 'static_html',
                'download_url': apk_info['download_url'],
                'first_seen': datetime.now().strftime('%Y-%m-%d'),
            })


def main():
    print(f"=== New APK Processing Pipeline ===")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"New unique APKs to process: {len(NEW_APKS)}")
    
    db = load_db()
    
    for apk_info in NEW_APKS:
        result = process_one_apk(apk_info)
        if result:
            update_db(db, apk_info, result)
            save_db(db)  # Save after each APK
    
    # Update last_updated
    db['last_updated'] = datetime.now().strftime('%Y-%m-%d')
    save_db(db)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"=== COMPLETE ===")
    print(f"Total APKs in DB: {len(db.get('apks', []))}")
    print(f"Total proxy nodes: {len(db.get('all_proxy_nodes', []))}")
    print(f"Total control nodes: {len(db.get('all_control_nodes', []))}")


if __name__ == '__main__':
    main()
