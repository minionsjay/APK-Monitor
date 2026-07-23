#!/usr/bin/env python3
"""Clean up DB: remove duplicate/bad entries, fix 720ww55 and 720bh282 with offline .dat decrypt."""
import json
import os
import base64
import hashlib
import urllib.request
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
SAMPLES_DIR = "/home/ninini/Agents/APK-Research/new_samples"

# Known correct config for each APK (from successful extractions)
CORRECT_CONFIGS = {
    '721sf5': {
        'md5': 'b801e4b9183144a9b2a8f7c30aebad32',
        'package': 'bbbyyeefh.wexxetfaliyvaqbs.hfgjolxw',
        'app_name': 'dh138', 'aes_key': 'yjHtoU18cKxTjwVh4m2iyHfEI91RG5Uq',
        'app_domain': '*.sdkchcga138.cwenku.com', 'port': 30138,
        'sni': 'www.zhihu.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://cbfc78521fdee22c.gz.bcebos.com/6c263e39f41ea417.dat',
        'domains': ['721sf5.9ursg.top', '720a275.w8zc3.com'],
        'download_url': 'http://s2uwgne8dmgq.s3-website.us-west-1.amazonaws.com/jsyd/zaeuas.hbbu',
        'proxy_nodes': [],  # Will be filled from forwarder cache
    },
    '720ww55': {
        'md5': 'bde7594267037e774a4b4a1da8c88597',
        'package': 'bva.vmalbuihxsxr.asqcwavqwftumojjmmef',
        'app_name': 'dh145', 'aes_key': 'gpTtoF31cUxTjrTo1m6iyDfFI28TK2Hh',
        'app_domain': '*.sdkvghty145.qianchixt.com', 'port': 30145,
        'sni': 'bilibili.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://04ecc9508b9e674f.gz.bcebos.com/faddbf0d6fffc983.dat',
        'domains': ['720ww55.j8rh8w.top'],
        'download_url': 'https://0bdnuong9lih.1n1xdd.cc/Dqmy4H7u0w1frd07mwm622ghd/6n9e5u',
    },
    '721yh118': {
        'md5': '459b65abd14cb264e82bebf3348fa5e4',
        'package': 'ema.wdbruunskrevoxu.ypdcekkbglyheay',
        'app_name': 'dh160', 'aes_key': 'guTtoF18cKxTjrTo3m7iyHfEI17RK5Cu',
        'app_domain': '*.sdkppph160.qianchixt.com', 'port': 30160,
        'sni': 'share.note.youdao.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://fdae6d82ab921d65.gz.bcebos.com/f0519b47d5faa95e.dat',
        'domains': ['721yh118.6p3n0.com', '721yh366.0x8ls.com', '721yh485.z3x4k.com'],
        'download_url': 'https://he2h91t5aho5.784w47.cc/YH/e7kdnb',
    },
    '721cpa5': {
        'md5': '100da829bad40f49a40db80b249171c9',
        'package': 'oow.fufsegdrnlxs.obarucmklnbikqfiqyxr',
        'app_name': 'dh122', 'aes_key': 'puTtoP12cKxTjrEo8m1iyHfEI92RK5Sb',
        'app_domain': '*.sdkdshau122.cwenku.com', 'port': 30122,
        'sni': 'www.zhihu.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://18b48918a2679508.gz.bcebos.com/6a5b82cf694a143f.dat',
        'domains': ['721cpa5.vbbon.com'],
        'download_url': 'https://65m2v74ujvmw.7bq47o.cc/arjs/zkh9c1',
    },
    '720pt1': {
        'md5': '48f4d5819e99db6f4bd586dcf79446d1',
        'package': 'aah.cjtuiwgxkdgym.xdueaqgrdhyuyodoakv',
        'app_name': 'dh176', 'aes_key': 'adGtoF52cBxTjrDo3m2iyDfFI17TK3Kq',
        'app_domain': '*.sdkvutg176.xverse66.com', 'port': 30176,
        'sni': 'www.bootcdn.cn', 'sdk_version': '4.0.1',
        'dat_url': 'https://c9e4d72785555940.gz.bcebos.com/9ebbe71b3dd60ae0.dat',
        'domains': ['720pt1.eeaq5.com', '720pt2.dpuhv.top', '721pt1.k2ebr.top'],
        'download_url': 'https://6abyzqv1hpy7.8cgxy2.cc/ysci9dz4k52tuij/1hst5q',
    },
    '720bh282': {
        'md5': '79f5d5f0e0c4e9899efadb622c58ecbf',
        'package': 'jnNPfy.SNrsaS.eOtCtk',  # This was the old package - may be wrong
        'app_name': 'dh176', 'aes_key': 'adGtoF52cBxTjrDo3m2iyDfFI17TK3Kq',
        'app_domain': '*.sdkvutg176.xverse66.com', 'port': 30176,
        'sni': 'www.zhihu.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://c9e4d72785555940.gz.bcebos.com/9ebbe71b3dd60ae0.dat',
        'domains': ['720bh282.livs6.com'],
        'download_url': 'https://1peg6he7uu0t.8nnxao.cc/176al/5t40lu',
    },
    '721cpc06': {
        'md5': '7339c33a7bcdc438ee854c305e4130a3',
        'package': 'tke.vjvpcxwbgcxn.clblevnhryjlvqdjhsns',
        'app_name': 'dh176', 'aes_key': 'adGtoF52cBxTjrDo3m2iyDfFI17TK3Kq',
        'app_domain': '*.sdkvutg176.xverse66.com', 'port': 30176,
        'sni': 'www.zhihu.com', 'sdk_version': '4.0.1',
        'dat_url': 'https://c9e4d72785555940.gz.bcebos.com/9ebbe71b3dd60ae0.dat',
        'domains': ['721cpc06.i1bmh.com'],
        'download_url': 'https://mbm9jtvk6owk.8nnxao.cc/jd/awp0so',
    },
}


def decrypt_dat(dat_url, aes_key):
    """Download and decrypt .dat file."""
    try:
        if not dat_url.startswith('http'):
            dat_url = 'https://' + dat_url
        print(f"  Downloading .dat: {dat_url[:80]}...")
        req = urllib.request.Request(dat_url, headers={'User-Agent': 'Mozilla/5.0'})
        raw = urllib.request.urlopen(req, timeout=20).read()
        print(f"  .dat size: {len(raw)} bytes")
        key = aes_key.encode()
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        pt = cipher.decrypt(raw)
        try:
            pt = unpad(pt, 16)
        except:
            # Try without unpad - maybe last block has different padding
            print(f"  Unpad failed, trying raw decrypt...")
            pt = pt.rstrip(b'\x00')
        nodes = json.loads(pt.decode())
        return nodes
    except Exception as e:
        print(f"  .dat error: {e}")
        return None


def main():
    with open(DB_PATH) as f:
        db = json.load(f)
    
    # Remove bad duplicate entries from first run
    bad_ids = {'721cpa5_vbbon', '720pt1_eeaq5', '721yh366', '721cpc06_i1bmh'}
    db['apks'] = [a for a in db['apks'] if a.get('id') not in bad_ids]
    print(f"Removed {len(bad_ids)} bad duplicate entries")
    
    # Rebuild all_proxy_nodes and all_control_nodes from scratch
    all_proxy = set()
    all_ctrl = set()
    
    # Fix/update each new APK entry
    for entry_id, config in CORRECT_CONFIGS.items():
        # Find existing entry
        existing = None
        for a in db['apks']:
            if a.get('id') == entry_id:
                existing = a
                break
        
        if not existing:
            print(f"\nCreating entry: {entry_id}")
            existing = {
                'id': entry_id,
                'first_seen': datetime.now().strftime('%Y-%m-%d'),
            }
            db['apks'].append(existing)
        else:
            print(f"\nUpdating entry: {entry_id}")
        
        # Update fields
        existing['source'] = f"域名下载: {' + '.join(config['domains'])}"
        existing['download_url'] = config['download_url']
        existing['apk_path'] = os.path.join(SAMPLES_DIR, config['md5'] + '.apk')
        # Use actual file name
        for f in os.listdir(SAMPLES_DIR):
            if f.endswith('.apk'):
                import hashlib as h
                with open(os.path.join(SAMPLES_DIR, f), 'rb') as fh:
                    md5 = h.md5(fh.read()).hexdigest()
                if md5 == config['md5']:
                    existing['apk_path'] = os.path.join(SAMPLES_DIR, f)
                    break
        
        existing['md5'] = config['md5']
        existing['package'] = config['package']
        existing['app_name'] = config['app_name']
        existing['app_domain'] = config['app_domain']
        existing['app_domain_port'] = config['port']
        existing['aes_key'] = config['aes_key']
        existing['sni'] = config['sni']
        existing['sdk_version'] = config['sdk_version']
        existing['dat_url'] = config['dat_url']
        existing['score'] = 160
        existing['last_collected'] = datetime.now().strftime('%Y-%m-%d %H:%M')
        existing['related_domains'] = config['domains']
        
        # Keep existing proxy_nodes if we have them
        if not existing.get('proxy_nodes'):
            existing['proxy_nodes'] = []
        
        # Download and decrypt .dat
        nodes = decrypt_dat(config['dat_url'], config['aes_key'])
        if nodes:
            existing['dat_decrypted'] = nodes
            control_nodes = []
            for k in ['nodesA', 'nodesB', 'nodesC', 'nodesD']:
                control_nodes.extend(nodes.get(k, []))
            existing['control_nodes'] = control_nodes
            print(f"  Control nodes: {len(control_nodes)}")
        else:
            existing['control_nodes'] = existing.get('control_nodes', [])
        
        existing['proxy_count'] = len(existing['proxy_nodes'])
        
        # Collect all nodes
        for ip in existing['proxy_nodes']:
            all_proxy.add(ip)
        for node in existing.get('control_nodes', []):
            ip = node.split(':')[0] if ':' in node else node
            all_ctrl.add(ip)
    
    # Also collect from pre-existing entries
    for a in db['apks']:
        if a.get('id') not in CORRECT_CONFIGS:
            for ip in a.get('proxy_nodes', []):
                all_proxy.add(ip)
            for node in a.get('control_nodes', []):
                ip = node.split(':')[0] if ':' in node else node
                all_ctrl.add(ip)
    
    db['all_proxy_nodes'] = sorted(all_proxy)
    db['all_control_nodes'] = sorted(all_ctrl)
    db['last_updated'] = datetime.now().strftime('%Y-%m-%d')
    
    with open(DB_PATH, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    
    print(f"\n=== DONE ===")
    print(f"Total APKs: {len(db['apks'])}")
    print(f"Total proxy nodes: {len(all_proxy)}")
    print(f"Total control nodes: {len(all_ctrl)}")


if __name__ == '__main__':
    main()
