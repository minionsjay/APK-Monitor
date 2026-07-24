#!/usr/bin/env python3
"""
代理恶意 APK 自动监控工具
功能: 域名→下载→检测→安装→提取节点→保存

用法:
  python3 auto_monitor.py [--check-domains] [--install-new] [--extract-nodes] [--full]
"""

import subprocess
import json
import os
import re
import time
import base64
import socket
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
SAMPLES_DIR = "/home/ninini/Agents/APK-Research/new_samples"
DETECT_SCRIPT = "/home/ninini/Agents/APK-Research/detect_proxy_apk.py"
ADB_DEVICE = "192.168.1.16:38399"

# 已知域名
DOMAINS = [
    "718c257.z4ee1.com",
    "718xssp20.v9ux9d.top",
    "718dla78.fll33.wlsmlt.com",
    "714cpk28.ldp244.com",
    "718fl314.vhw49.dntwag.cn",
    "721sf5.9ursg.top",
    "720cpb01.vwlyh.com",
    "7200.8dgoi.com",
    "720ww55.j8rh8w.top",
    "721fc031.fihs6.top",
    "720a275.w8zc3.com",
    "721yh118.6p3n0.com",
    "721fc032.v83sp.top",
    "721cpa5.vbbon.com",
    "720cpb01.snw70.com",
    "720bg054.vlwed.top",
    "721yh366.0x8ls.com",
    "721ls153.ufeesi.cn",
    "720fc046.758wl.top",
    "720fc045.8ne02.top",
    "720yhp43.ffe45u.com",
    "720pt1.eeaq5.com",
    "721dx124.elpqqz.cn",
    "720bh282.livs6.com",
    "720pt2.dpuhv.top",
    "721cpa3.1662t.com",
    "720qt123.swffg.top",
    "721yh485.z3x4k.com",
    "721cpc06.i1bmh.com",
    "721pt1.k2ebr.top",
    "721zok05.imv55.top",
]

def load_db():
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            return json.load(f)
    return {"apks": [], "all_proxy_nodes": [], "all_control_nodes": []}

def save_db(db):
    with open(DB_PATH, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def get_download_url(domain, method, **kwargs):
    """从域名获取 APK 下载链接"""
    import urllib.request
    
    if method == "static_html":
        # 静态 HTML 页面，搜索 downloadLinks.android
        url = f"https://{domain}/"
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=10, context=__import__('ssl').create_default_context()) as resp:
                html = resp.read().decode('utf-8', errors='replace')
            # 搜索 downloadLinks
            match = re.search(r'android:\s*"([^"]+)"', html)
            if match:
                return match.group(1)
        except:
            pass
        return None
    
    elif method == "dynamic_api":
        api_url = kwargs.get('api_url')
        api_params = kwargs.get('api_params')
        try:
            data = api_params.encode()
            req = urllib.request.Request(api_url, data=data, headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Linux; Android 13)'
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
            if result.get('success') and result.get('result', {}).get('androidUrl'):
                return result['result']['androidUrl']
        except:
            pass
        return None
    
    return None

def download_apk(url, domain):
    """下载 APK"""
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    filename = f"{domain.replace('.', '_')}.apk"
    filepath = os.path.join(SAMPLES_DIR, filename)
    
    import urllib.request
    try:
        urllib.request.urlretrieve(url, filepath)
        return filepath
    except:
        return None

def detect_apk(apk_path):
    """检测 APK 是否为恶意代理"""
    try:
        result = subprocess.run(['python3', DETECT_SCRIPT, apk_path],
                              capture_output=True, text=True, timeout=30)
        if 'score=160' in result.stdout or '确认恶意' in result.stdout:
            return True, 160
        # 搜索 score
        match = re.search(r'score=(\d+)', result.stdout)
        if match:
            return int(match.group(1)) >= 70, int(match.group(1))
        return False, 0
    except:
        return False, 0

def install_and_start(apk_path):
    """安装 APK 到真机并启动"""
    # 安装
    result = subprocess.run(['adb', '-s', ADB_DEVICE, 'install', '-r', apk_path],
                          capture_output=True, text=True, timeout=120)
    if 'Success' not in result.stdout:
        return None, None
    
    # 获取包名
    result = subprocess.run(['adb', '-s', ADB_DEVICE, 'shell', 'pm', 'list', 'packages', '-3'],
                          capture_output=True, text=True, timeout=10)
    # 找新安装的包
    known = {'bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns', 'ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc',
             'gjithpd.enjfpfakiubo.amkrrlirim', 'com.topjohnwu.magisk', 'ru.maximoff.apktool',
             'com.netease.uuremote', 'bin.mt.plus', 'com.github.metacubex.clash.meta',
             'com.android.adbkeyboard', 'io.github.muntashirakon.AppManager',
             'com.emanuelef.remote_capture', 'com.github.android', 'youqu.android.todesk',
             'android.v2board.app', 'com.wn.app.np', 'com.google.android.safetycore',
             'com.google.android.contactkeys', 'net.f7df3up4.cxo1cw', 'jnNPfy.SNrsaS.eOtCtk',
             'cii.gjjvikjqhhupaab.aaoknxedxpgnwa', 'com.qdvvgnzdnhiqqbf.ooyblxyrjmluulgbgdek',
             'ldp.swtacwpthqoe.cyfueitnswummxsjngda'}
    
    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('package:'):
            pkg = line[8:]
            if pkg not in known:
                # 启动
                subprocess.run(['adb', '-s', ADB_DEVICE, 'shell',
                              f'monkey -p {pkg} -c android.intent.category.LAUNCHER 1'],
                             capture_output=True, timeout=10)
                # 等待 Go SDK 初始化
                time.sleep(60)
                return pkg, None
    return None, None

def extract_nodes(package):
    """从真机提取代理节点和配置"""
    result = {
        'package': package,
        'proxy_nodes': [],
        'control_nodes': [],
        'config': {},
        'dat_url': None,
        'dat_decrypted': None,
        'aes_key': None,
        'app_name': None,
        'port': None,
    }
    
    # 读取 sdk_forwarder_fixed.json
    cmd = ['adb', '-s', ADB_DEVICE, 'shell',
           f'cat /sdcard/Android/data/{package}/files/sdk_forwarder_fixed.json']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if r.stdout.strip():
        try:
            data = json.loads(r.stdout)
            result['proxy_nodes'] = data.get('app_line_ips', [])
            result['port'] = data.get('app_line_port')
        except:
            pass
    
    # 读取 sdk_cache.json
    cmd = ['adb', '-s', ADB_DEVICE, 'shell',
           f'cat /sdcard/Android/data/{package}/files/sdk_cache.json']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if r.stdout.strip():
        try:
            cache = json.loads(r.stdout)
            entries = cache.get('entries', {})
            for url, info in entries.items():
                result['dat_url'] = url
                result['dat_payload_b64'] = info.get('payload_b64')
                break
        except:
            pass
    
    # 从 Go 堆提取配置
    pid_r = subprocess.run(['adb', '-s', ADB_DEVICE, 'shell', f'pidof {package}'],
                          capture_output=True, text=True, timeout=5)
    pid = pid_r.stdout.strip()
    if pid:
        # 读取 Go 堆
        heap_r = subprocess.run(['adb', '-s', ADB_DEVICE, 'shell',
                                f'su -c "dd if=/proc/{pid}/mem bs=4096 skip=67108864 count=2048 2>/dev/null"'],
                               capture_output=True, timeout=30)
        text = heap_r.stdout.decode('utf-8', errors='replace')
        
        # 搜索配置
        for pattern, key in [
            (r'"app_name"\s*:\s*"([^"]*)"', 'app_name'),
            (r'"AES-key"\s*:\s*"([^"]*)"', 'aes_key'),
            (r'"app_domain"\s*:\s*"([^"]*)"', 'app_domain'),
            (r'"app_domain_port"\s*:\s*(\d+)', 'port'),
            (r'"tls_sni_for_current_host"\s*:\s*"([^"]*)"', 'sni'),
        ]:
            m = re.search(pattern, text)
            if m:
                result[key] = m.group(1)
        
        # 也搜索完整 SDK 状态
        m = re.search(r'\{"prepared".*?"payload":\{[^}]+\}.*?"state"', text)
        if m:
            try:
                sdk = json.loads(m.group(0))
                payload = sdk.get('payload', {})
                result['app_name'] = payload.get('app_name', result.get('app_name'))
                result['aes_key'] = payload.get('AES-key', result.get('aes_key'))
                result['app_domain'] = payload.get('app_domain', result.get('app_domain'))
                result['port'] = int(payload.get('app_domain_port', 0)) or result.get('port')
                result['sni'] = sdk.get('tls_sni_for_current_host', result.get('sni'))
                result['local_port'] = sdk.get('local_port')
            except:
                pass
        
        # 也搜索 AES key (cKxT pattern)
        if not result.get('aes_key'):
            m = re.search(r'([A-Za-z0-9]{32})', text)
            if m and 'cKxT' in m.group(1) and 'HfEI' in m.group(1):
                result['aes_key'] = m.group(1)
    
    # 解密 .dat 文件
    if result.get('dat_payload_b64') and result.get('aes_key'):
        try:
            data = base64.b64decode(result['dat_payload_b64'])
            key = result['aes_key'].encode()
            cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
            pt = cipher.decrypt(data)
            pt = unpad(pt, 16)
            result['dat_decrypted'] = json.loads(pt.decode())
            result['control_nodes'] = result['dat_decrypted'].get('nodesA', [])
        except:
            pass
    
    return result

def check_domains():
    """检查所有域名是否有新 APK"""
    print("=== 检查域名 ===\n")
    new_apks = []
    
    for d in DOMAINS:
        if isinstance(d, dict):
            domain = d['domain']
            method = d['method']
            api_url = d.get('api_url')
            api_params = d.get('api_params')
        else:
            domain = d
            method = 'static_html'
            api_url = None
            api_params = None
        print(f"  {domain} ({method})")

        url = get_download_url(domain, method,
                              api_url=api_url,
                              api_params=api_params)
        
        if url:
            print(f"    下载链接: {url}")
            # 检查是否已下载
            db = load_db()
            existing_urls = [a.get('download_url') for a in db.get('apks', [])]
            if url not in existing_urls:
                print(f"    新 APK！下载中...")
                path = download_apk(url, domain)
                if path and os.path.getsize(path) > 1000000:
                    is_malware, score = detect_apk(path)
                    print(f"    检测: score={score} {'恶意' if is_malware else '正常'}")
                    if is_malware:
                        new_apks.append({'domain': domain, 'url': url, 'path': path, 'score': score})
                else:
                    print(f"    下载失败或文件太小")
            else:
                print(f"    已知 URL，跳过")
        else:
            print(f"    无法获取下载链接")
        print()
    
    return new_apks

def full_monitor():
    """完整监控流程"""
    print("=== 代理恶意 APK 自动监控 ===")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 1. 检查域名
    new_apks = check_domains()
    
    if new_apks:
        print(f"\n=== 发现 {len(new_apks)} 个新恶意 APK ===\n")
        
        for apk_info in new_apks:
            print(f"\n处理: {apk_info['domain']}")
            
            # 2. 安装到真机
            if check_adb():
                pkg, _ = install_and_start(apk_info['path'])
                if pkg:
                    print(f"  安装成功: {pkg}")
                    
                    # 3. 提取节点
                    result = extract_nodes(pkg)
                    print(f"  app_name: {result.get('app_name')}")
                    print(f"  port: {result.get('port')}")
                    print(f"  AES-key: {result.get('aes_key')}")
                    print(f"  SNI: {result.get('sni')}")
                    print(f"  代理节点: {len(result.get('proxy_nodes', []))} 个")
                    print(f"  控制面节点: {len(result.get('control_nodes', []))} 个")
                    print(f"  .dat URL: {result.get('dat_url')}")
                    
                    # 4. 保存到数据库
                    db = load_db()
                    apk_entry = {
                        'id': apk_info['domain'],
                        'source': f"域名下载: {apk_info['domain']}",
                        'download_url': apk_info['url'],
                        'apk_path': apk_info['path'],
                        'package': pkg,
                        'app_name': result.get('app_name'),
                        'app_domain': result.get('app_domain'),
                        'app_domain_port': result.get('port'),
                        'aes_key': result.get('aes_key'),
                        'sni': result.get('sni'),
                        'dat_url': result.get('dat_url'),
                        'dat_decrypted': result.get('dat_decrypted'),
                        'control_nodes': result.get('control_nodes'),
                        'proxy_nodes': result.get('proxy_nodes'),
                        'proxy_count': len(result.get('proxy_nodes', [])),
                        'score': apk_info['score'],
                        'first_seen': datetime.now().strftime('%Y-%m-%d'),
                    }
                    db['apks'].append(apk_entry)
                    
                    # 更新全局节点列表
                    for ip in result.get('proxy_nodes', []):
                        if ip not in db.get('all_proxy_nodes', []):
                            db.setdefault('all_proxy_nodes', []).append(ip)
                    for node in result.get('control_nodes', []):
                        ip = node.split(':')[0]
                        if ip not in db.get('all_control_nodes', []):
                            db.setdefault('all_control_nodes', []).append(ip)
                    
                    save_db(db)
                    print(f"  已保存到数据库")
            else:
                print(f"  真机不在线，跳过安装")
    else:
        print("没有新 APK")
    
    # 5. 更新已有 APK 的节点
    print(f"\n=== 更新已有 APK 节点 ===\n")
    db = load_db()
    if check_adb():
        for apk in db.get('apks', []):
            pkg = apk.get('package')
            if not pkg:
                continue
            result = extract_nodes(pkg)
            if result.get('proxy_nodes'):
                old_count = len(apk.get('proxy_nodes', []))
                new_count = len(result['proxy_nodes'])
                if old_count != new_count or set(result['proxy_nodes']) != set(apk.get('proxy_nodes', [])):
                    print(f"  {apk['id']}: 节点变化 {old_count}→{new_count}")
                    apk['proxy_nodes'] = result['proxy_nodes']
                    apk['control_nodes'] = result.get('control_nodes', apk.get('control_nodes', []))
                    save_db(db)
                else:
                    print(f"  {apk['id']}: 无变化 ({new_count} 个节点)")
    
    # 6. 保存 IP 列表
    save_ip_lists(db)
    
    print(f"\n=== 监控完成 ===")
    print(f"总 APK: {len(db.get('apks', []))}")
    print(f"总代理节点: {len(db.get('all_proxy_nodes', []))}")
    print(f"总控制面节点: {len(db.get('all_control_nodes', []))}")

def check_adb():
    """检查 ADB 设备是否在线"""
    try:
        r = subprocess.run(['adb', '-s', ADB_DEVICE, 'shell', 'echo', 'ok'],
                          capture_output=True, text=True, timeout=5)
        return 'ok' in r.stdout
    except:
        return False

def save_ip_lists(db):
    """保存 IP 列表到文件"""
    report_dir = "/home/ninini/Agents/APK-Research/forensics"
    os.makedirs(report_dir, exist_ok=True)
    
    with open(f"{report_dir}/all_proxy_nodes.txt", 'w') as f:
        for ip in sorted(db.get('all_proxy_nodes', [])):
            f.write(ip + "\n")
    
    with open(f"{report_dir}/all_control_nodes.txt", 'w') as f:
        for ip in sorted(db.get('all_control_nodes', [])):
            f.write(ip + "\n")
    
    print(f"IP 列表已更新到 {report_dir}/")

if __name__ == '__main__':
    import sys
    if '--full' in sys.argv or len(sys.argv) == 1:
        full_monitor()
    elif '--check-domains' in sys.argv:
        check_domains()
