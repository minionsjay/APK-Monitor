#!/usr/bin/env python3
"""Process new APKs with uninstall between each, plus offline RSA config extraction."""
import subprocess
import json
import os
import re
import time
import base64
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import unpad

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
SAMPLES_DIR = "/home/ninini/Agents/APK-Research/new_samples"
ADB_DEVICE = "192.168.1.16:43351"
TMP_DIR = "/tmp/apk_extract"

NEW_APKS = [
    {'file': '721sf5_9ursg_top.apk', 'md5': 'b801e4b9183144a9b2a8f7c30aebad32',
     'domains': ['721sf5.9ursg.top', '720a275.w8zc3.com'],
     'download_url': 'http://s2uwgne8dmgq.s3-website.us-west-1.amazonaws.com/jsyd/zaeuas.hbbu'},
    {'file': '720ww55_j8rh8w_top.apk', 'md5': 'bde7594267037e774a4b4a1da8c88597',
     'domains': ['720ww55.j8rh8w.top'],
     'download_url': 'https://0bdnuong9lih.1n1xdd.cc/Dqmy4H7u0w1frd07mwm622ghd/6n9e5u'},
    {'file': '721yh118_6p3n0_com.apk', 'md5': '459b65abd14cb264e82bebf3348fa5e4',
     'domains': ['721yh118.6p3n0.com', '721yh366.0x8ls.com', '721yh485.z3x4k.com'],
     'download_url': 'https://he2h91t5aho5.784w47.cc/YH/e7kdnb'},
    {'file': '721cpa5_vbbon_com.apk', 'md5': '100da829bad40f49a40db80b249171c9',
     'domains': ['721cpa5.vbbon.com'],
     'download_url': 'https://65m2v74ujvmw.7bq47o.cc/arjs/zkh9c1'},
    {'file': '720pt1_eeaq5_com.apk', 'md5': '48f4d5819e99db6f4bd586dcf79446d1',
     'domains': ['720pt1.eeaq5.com', '720pt2.dpuhv.top', '721pt1.k2ebr.top'],
     'download_url': 'https://6abyzqv1hpy7.8cgxy2.cc/ysci9dz4k52tuij/1hst5q'},
    {'file': '720bh282_livs6_com.apk', 'md5': '79f5d5f0e0c4e9899efadb622c58ecbf',
     'domains': ['720bh282.livs6.com'],
     'download_url': 'https://1peg6he7uu0t.8nnxao.cc/176al/5t40lu'},
    {'file': '721cpc06_i1bmh_com.apk', 'md5': '7339c33a7bcdc438ee854c305e4130a3',
     'domains': ['721cpc06.i1bmh.com'],
     'download_url': 'https://mbm9jtvk6owk.8nnxao.cc/jd/awp0so'},
]


def load_db():
    with open(DB_PATH) as f:
        return json.load(f)


def save_db(db):
    with open(DB_PATH, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def adb_shell(cmd, timeout=15):
    full = ['adb', '-s', ADB_DEVICE, 'shell', cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except:
        return ""


def extract_libgojni(apk_path):
    """Extract libgojni.so from APK and extract RSA private key."""
    import zipfile
    z = zipfile.ZipFile(apk_path)
    
    # Find libgojni.so
    libgojni = None
    for name in z.namelist():
        if 'libgojni.so' in name:
            libgojni = name
            break
    
    if not libgojni:
        return None, None
    
    os.makedirs(TMP_DIR, exist_ok=True)
    so_path = os.path.join(TMP_DIR, 'libgojni.so')
    with open(so_path, 'wb') as f:
        f.write(z.read(libgojni))
    
    # Extract RSA private key
    try:
        result = subprocess.run(['strings', '-n', '100', so_path],
                              capture_output=True, text=True, timeout=30)
        rsa_key = None
        for line in result.stdout.split('\n'):
            if 'EmbeddedPrivateKeyB64=' in line:
                b64 = line.split('EmbeddedPrivateKeyB64=')[1].strip().rstrip('"').strip("'")
                key_data = base64.b64decode(b64)
                rsa_key = RSA.import_key(key_data)
                print(f"  RSA key extracted from libgojni.so")
                break
        return so_path, rsa_key
    except Exception as e:
        print(f"  RSA extraction error: {e}")
        return so_path, None


def extract_network_constant(apk_path, rsa_key):
    """Extract NetworkConstant.k from DEX and RSA-decrypt to get config JSON."""
    if not rsa_key:
        return None
    
    import zipfile
    z = zipfile.ZipFile(apk_path)
    
    # Find all DEX files
    dex_files = [n for n in z.namelist() if n.endswith('.dex')]
    
    for dex_file in dex_files:
        dex_data = z.read(dex_file)
        # Search for 344-char base64 strings (RSA-2048 encrypted)
        # Base64 of 256 bytes = 344 chars (with padding)
        import re
        matches = re.findall(rb'[A-Za-z0-9+/]{340,344}={0,2}', dex_data)
        
        for match in matches:
            try:
                b64_str = match.decode()
                # Pad if needed
                while len(b64_str) % 4:
                    b64_str += '='
                ciphertext = base64.b64decode(b64_str)
                
                if len(ciphertext) == 256:  # RSA-2048
                    cipher = PKCS1_v1_5.new(rsa_key)
                    try:
                        plaintext = cipher.decrypt(ciphertext, None)
                        if plaintext:
                            text = plaintext.decode('utf-8', errors='replace')
                            if 'app_name' in text or 'app_domain' in text:
                                config = json.loads(text)
                                print(f"  Config decrypted from {dex_file}: {config.get('app_name')}")
                                return config
                    except:
                        continue
            except:
                continue
    
    # Also try searching in the DEX for strings that look like the constant
    # Sometimes it's stored as a Java string literal
    for dex_file in dex_files:
        dex_data = z.read(dex_file)
        # Look for strings that might be the network constant
        # Pattern: 344-char base64 in string constant
        matches = re.findall(rb'[\x00-\x7f]{340,400}', dex_data)
        for match in matches:
            text = match.decode('ascii', errors='replace')
            b64_match = re.search(r'[A-Za-z0-9+/]{340,344}={0,2}', text)
            if b64_match:
                try:
                    b64_str = b64_match.group()
                    while len(b64_str) % 4:
                        b64_str += '='
                    ciphertext = base64.b64decode(b64_str)
                    if len(ciphertext) == 256:
                        cipher = PKCS1_v1_5.new(rsa_key)
                        plaintext = cipher.decrypt(ciphertext, None)
                        if plaintext:
                            decoded = plaintext.decode('utf-8', errors='replace')
                            if 'app_name' in decoded:
                                config = json.loads(decoded)
                                print(f"  Config found in {dex_file}: {config.get('app_name')}")
                                return config
                except:
                    continue
    
    print(f"  No NetworkConstant.k found in DEX")
    return None


def extract_config_from_strings(apk_path):
    """Try to find config strings directly in the APK's native libs."""
    import zipfile
    z = zipfile.ZipFile(apk_path)
    
    # Search all .so files for config JSON patterns
    for name in z.namelist():
        if name.endswith('.so'):
            data = z.read(name)
            # Search for app_name pattern
            matches = re.findall(rb'"app_name"\s*:\s*"([^"]+)"', data)
            if matches:
                app_name = matches[0].decode()
                # Get more config
                aes_matches = re.findall(rb'"AES-key"\s*:\s*"([^"]+)"', data)
                domain_matches = re.findall(rb'"app_domain"\s*:\s*"([^"]+)"', data)
                port_matches = re.findall(rb'"app_domain_port"\s*:\s*(\d+)', data)
                sni_matches = re.findall(rb'"tls_sni_for_current_host"\s*:\s*"([^"]+)"', data)
                sdk_matches = re.findall(rb'"sdk_version"\s*:\s*"([^"]+)"', data)
                
                config = {
                    'app_name': app_name,
                    'AES-key': aes_matches[0].decode() if aes_matches else None,
                    'app_domain': domain_matches[0].decode() if domain_matches else None,
                    'app_domain_port': int(port_matches[0]) if port_matches else None,
                    'sni': sni_matches[0].decode() if sni_matches else None,
                    'sdk_version': sdk_matches[0].decode() if sdk_matches else None,
                }
                print(f"  Config from .so strings: {config}")
                return config
    
    return None


def install_and_extract(apk_path, package_hint=None):
    """Install APK, launch, extract nodes from device."""
    # Uninstall any previous version of the same package
    if package_hint:
        adb_shell(f'pm uninstall {package_hint}', timeout=10)
    
    # Install
    r = subprocess.run(
        ['adb', '-s', ADB_DEVICE, 'install', '-r', '-t', apk_path],
        capture_output=True, text=True, timeout=120
    )
    if 'Success' not in r.stdout:
        print(f"  Install failed: {r.stdout[:100]} {r.stderr[:100]}")
        return None
    
    # Get package name
    result = adb_shell('pm list packages -3', timeout=10)
    # Known non-malware packages
    known_system = {
        'com.topjohnwu.magisk', 'ru.maximoff.apktool', 'com.netease.uuremote',
        'bin.mt.plus', 'com.github.metacubex.clash.meta', 'com.android.adbkeyboard',
        'io.github.muntashirakon.AppManager', 'com.emanuelef.remote_capture',
        'com.github.android', 'youqu.android.todesk', 'android.v2board.app',
        'com.wn.app.np', 'com.google.android.safetycore',
        'com.google.android.contactkeys',
    }
    # Also exclude all packages already in DB
    db = load_db()
    for a in db.get('apks', []):
        if a.get('package'):
            known_system.add(a['package'])
    
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
    print(f"  Launched, waiting 45s...")
    time.sleep(45)
    
    # Extract
    result = {'package': new_pkg, 'proxy_nodes': [], 'control_nodes': []}
    
    # Read forwarder cache
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
        # Try su with timeout
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


def decrypt_dat_offline(dat_url, aes_key, payload_b64=None):
    """Download and decrypt .dat file."""
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
        
        key = aes_key.encode() if isinstance(aes_key, str) else aes_key
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(raw)
        try:
            pt = unpad(pt, 16)
        except:
            pass
        
        nodes = json.loads(pt.decode())
        return nodes
    except Exception as e:
        print(f"  .dat error: {e}")
        return None


def decrypt_dat_from_payload(payload_b64, aes_key):
    """Decrypt .dat from cached base64 payload."""
    if not payload_b64 or not aes_key:
        return None
    
    try:
        data = base64.b64decode(payload_b64)
        key = aes_key.encode() if isinstance(aes_key, str) else aes_key
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(data)
        pt = unpad(pt, 16)
        return json.loads(pt.decode())
    except Exception as e:
        print(f"  Payload .dat error: {e}")
        return None


def process_apk(apk_info):
    """Full processing of one APK."""
    apk_path = os.path.join(SAMPLES_DIR, apk_info['file'])
    print(f"\n{'='*60}")
    print(f"APK: {apk_info['file']}")
    print(f"  MD5: {apk_info['md5']}")
    print(f"  Domains: {', '.join(apk_info['domains'])}")
    
    # Step 1: Extract RSA key from libgojni.so
    print("  [1] Extracting RSA key from libgojni.so...")
    so_path, rsa_key = extract_libgojni(apk_path)
    
    # Step 2: Try to extract config via RSA decryption of NetworkConstant.k
    config = None
    if rsa_key:
        print("  [2] Decrypting NetworkConstant.k...")
        config = extract_network_constant(apk_path, rsa_key)
    
    # Step 3: Try extracting config from .so strings
    if not config:
        print("  [2b] Searching .so strings for config...")
        config = extract_config_from_strings(apk_path)
    
    # Step 4: Install on device and extract nodes
    print("  [3] Installing on device...")
    # Get the expected package from DB if known
    db = load_db()
    prev_pkg = None
    for a in db.get('apks', []):
        if a.get('package') == 'dcm.oyilqypbfykjic.yjsnwjgyarvmculrhseb':
            prev_pkg = 'dcm.oyilqypbfykjic.yjsnwjgyarvmculrhseb'
            break
    
    device_result = install_and_extract(apk_path, prev_pkg)
    
    if not device_result:
        device_result = {'package': None, 'proxy_nodes': [], 'control_nodes': []}
    
    # Merge config from offline + device
    final = {
        'package': device_result.get('package'),
        'app_name': device_result.get('app_name') or (config or {}).get('app_name'),
        'aes_key': device_result.get('aes_key') or (config or {}).get('AES-key'),
        'app_domain': device_result.get('app_domain') or (config or {}).get('app_domain'),
        'app_domain_port': device_result.get('port') or (config or {}).get('app_domain_port'),
        'sni': device_result.get('sni') or (config or {}).get('sni'),
        'sdk_version': device_result.get('sdk_version') or (config or {}).get('sdk_version'),
        'proxy_nodes': device_result.get('proxy_nodes', []),
        'control_nodes': [],
        'dat_url': device_result.get('dat_url'),
        'dat_decrypted': None,
    }
    
    # Step 5: Decrypt .dat
    if final['dat_url'] and final['aes_key']:
        print("  [4] Decrypting .dat...")
        nodes = decrypt_dat_offline(final['dat_url'], final['aes_key'],
                                    device_result.get('dat_payload_b64'))
        if nodes:
            final['dat_decrypted'] = nodes
            for k in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                final['control_nodes'].extend(nodes.get(k, []))
    
    if not final['control_nodes'] and device_result.get('dat_payload_b64') and final['aes_key']:
        print("  [4b] Decrypting .dat from cached payload...")
        nodes = decrypt_dat_from_payload(device_result['dat_payload_b64'], final['aes_key'])
        if nodes:
            final['dat_decrypted'] = nodes
            for k in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                final['control_nodes'].extend(nodes.get(k, []))
    
    print(f"\n  RESULT:")
    for k, v in final.items():
        if k in ('proxy_nodes', 'control_nodes'):
            print(f"    {k}: {len(v)} items")
        elif k == 'dat_decrypted' and v:
            print(f"    {k}: [decrypted]")
        else:
            print(f"    {k}: {v}")
    
    return final


def update_db_entry(db, apk_info, result):
    """Update or create DB entry for this APK."""
    entry_id = apk_info['domains'][0].split('.')[0]
    
    # Remove any existing entry with same id (from the buggy first run)
    db['apks'] = [a for a in db.get('apks', []) if a.get('id') != entry_id]
    
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
    print(f"=== APK Processing Pipeline (v2 - with uninstall) ===")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    db = load_db()
    
    for apk_info in NEW_APKS:
        result = process_apk(apk_info)
        update_db_entry(db, apk_info, result)
        save_db(db)
        
        # Uninstall between APKs
        if result.get('package'):
            print(f"  Uninstalling {result['package']}...")
            adb_shell(f'pm uninstall {result["package"]}', timeout=15)
    
    db['last_updated'] = datetime.now().strftime('%Y-%m-%d')
    save_db(db)
    
    print(f"\n{'='*60}")
    print(f"=== COMPLETE ===")
    print(f"Total APKs: {len(db.get('apks', []))}")
    print(f"Total proxy nodes: {len(db.get('all_proxy_nodes', []))}")
    print(f"Total control nodes: {len(db.get('all_control_nodes', []))}")


if __name__ == '__main__':
    main()
