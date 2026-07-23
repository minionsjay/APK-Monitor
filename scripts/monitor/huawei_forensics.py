#!/usr/bin/env python3
"""
华为云 IP 抓包取证脚本
对代理网络中的华为云节点进行网络取证

用法:
  python3 huawei_forensics.py [--capture] [--port-scan] [--tls-fingerprint] [--report]
"""

import subprocess
import json
import time
import os
import socket
import ssl
import struct
from datetime import datetime

DB_PATH = "/home/ninini/Agents/APK-Research/proxy_monitor_db.json"
REPORT_DIR = "/home/ninini/Agents/APK-Research/forensics"
PCAP_DIR = "/home/ninini/Agents/APK-Research/forensics/pcaps"

HUAWEI_IP_RANGES = [
    (0x6E2900, 0x6E29FF),  # 110.41.0-255
    (0x712D00, 0x712DFF),  # 113.45.0-255
    (0x728400, 0x7284FF),  # 114.132.0-255
    (0x74CD00, 0x74CDFF),  # 116.205.0-255
    (0x792500, 0x7925FF),  # 121.37.0-255
    (0x7C4700, 0x7C47FF),  # 124.71.0-255
]

def is_huawei(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    ip_int = (int(parts[0]) << 16) | (int(parts[1]) << 8) | int(parts[2])
    for start, end in HUAWEI_IP_RANGES:
        if start <= ip_int <= end:
            return True
    return False

def load_db():
    with open(DB_PATH) as f:
        return json.load(f)

def get_huawei_ips():
    db = load_db()
    ips = []
    for entry in db.get('huawei_ips', []):
        ips.append(entry)
    # 也从代理节点中筛选
    for ip in db.get('all_proxy_nodes', []):
        if is_huawei(ip) and ip not in [e['ip'] for e in ips]:
            ips.append({'ip': ip, 'port': None, 'apk': 'unknown', 'type': 'proxy'})
    # 控制面节点
    for node in db.get('all_control_nodes', []):
        if is_huawei(node) and node not in [e['ip'] for e in ips]:
            ips.append({'ip': node, 'port': None, 'apk': 'unknown', 'type': 'control'})
    return ips

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

def port_scan(ip, ports=None):
    if ports is None:
        ports = [80, 443, 30052, 30122, 30139, 30146, 30151, 22, 8080, 8443]
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                # 尝试获取 banner
                banner = ""
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='replace')[:100]
                except:
                    pass
                results.append({'port': port, 'state': 'open', 'banner': banner})
            else:
                results.append({'port': port, 'state': 'closed', 'banner': ''})
        except socket.timeout:
            results.append({'port': port, 'state': 'timeout', 'banner': ''})
        except:
            results.append({'port': port, 'state': 'error', 'banner': ''})
        finally:
            sock.close()
    return results

def tls_fingerprint(ip, port, sni_list=None):
    if sni_list is None:
        sni_list = ['bilibili.com', 'music.163.com', 'www.bootcdn.cn', '']
    results = []
    for sni in sni_list:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    results.append({
                        'sni': sni,
                        'tls_version': version,
                        'cipher': cipher[0] if cipher else 'N/A',
                        'cert_size': len(cert) if cert else 0,
                        'status': 'connected'
                    })
        except ssl.SSLError as e:
            results.append({'sni': sni, 'status': 'ssl_error', 'error': str(e)[:100]})
        except ConnectionRefusedError:
            results.append({'sni': sni, 'status': 'refused'})
        except socket.timeout:
            results.append({'sni': sni, 'status': 'timeout'})
        except Exception as e:
            results.append({'sni': sni, 'status': 'error', 'error': str(e)[:100]})
    return results

def capture_pcap(ip, port, duration=30):
    """用 tcpdump 抓包（需要 root）"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = f"{PCAP_DIR}/{ip}_{port}_{ts}.pcap"
    
    # 在真机上执行 tcpdump
    cmd = f"adb -s 192.168.1.16:43351 shell \"su 0 -c 'timeout {duration} tcpdump -i any host {ip} -c 200 -w /sdcard/forensics.pcap'\""
    try:
        subprocess.run(cmd, shell=True, timeout=duration+10, capture_output=True)
        # 拉取 pcap
        subprocess.run(f"adb -s 192.168.1.16:43351 pull /sdcard/forensics.pcap {pcap_file}",
                      shell=True, timeout=10, capture_output=True)
        if os.path.exists(pcap_file):
            return {'pcap_file': pcap_file, 'size': os.path.getsize(pcap_file)}
    except:
        pass
    return None

def http_probe(ip, port):
    """HTTP 探测"""
    results = []
    for protocol in ['http', 'https']:
        url = f"{protocol}://{ip}:{port}/"
        try:
            cmd = ['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}:%{redirect_url}',
                   '--connect-timeout', '5', '--max-time', '10', url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout.strip()
            results.append({'protocol': protocol, 'response': output})
        except:
            results.append({'protocol': protocol, 'response': 'timeout'})
    return results

def generate_report():
    os.makedirs(REPORT_DIR, exist_ok=True)
    db = load_db()
    hw_ips = get_huawei_ips()
    
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f"{REPORT_DIR}/huawei_forensics_{ts}.md"
    
    with open(report_file, 'w') as f:
        f.write(f"# 华为云 IP 取证报告\n\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## 华为云节点概览\n\n")
        f.write(f"共 {len(hw_ips)} 个华为云 IP\n\n")
        f.write(f"| IP | 端口 | APK | 类型 | 反向DNS |\n")
        f.write(f"|----|------|-----|------|--------|\n")
        for entry in hw_ips:
            ip = entry['ip']
            port = entry.get('port', 'N/A')
            apk = entry.get('apk', 'N/A')
            ptype = entry.get('type', 'N/A')
            rdns = entry.get('reverse_dns', reverse_dns(ip))
            f.write(f"| {ip} | {port} | {apk} | {ptype} | {rdns} |\n")
        
        f.write(f"\n## 详细取证信息\n\n")
        for entry in hw_ips:
            ip = entry['ip']
            port = entry.get('port')
            f.write(f"### {ip}:{port}\n\n")
            f.write(f"- 反向 DNS: {reverse_dns(ip)}\n")
            f.write(f"- APK: {entry.get('apk', 'N/A')}\n")
            f.write(f"- 类型: {entry.get('type', 'N/A')}\n")
            
            # 端口扫描
            f.write(f"\n#### 端口扫描\n\n")
            if port:
                scan = port_scan(ip, [port, 80, 443, 22])
            else:
                scan = port_scan(ip)
            f.write(f"| 端口 | 状态 | Banner |\n")
            f.write(f"|------|------|--------|\n")
            for s in scan:
                f.write(f"| {s['port']} | {s['state']} | {s['banner'][:50]} |\n")
            
            # TLS 指纹（如果有端口）
            if port:
                f.write(f"\n#### TLS 指纹\n\n")
                tls = tls_fingerprint(ip, port)
                for t in tls:
                    f.write(f"- SNI={t.get('sni','')}: {t.get('status','')} {t.get('tls_version','')} {t.get('cipher','')}\n")
            
            # HTTP 探测
            if port:
                f.write(f"\n#### HTTP 探测\n\n")
                http = http_probe(ip, port)
                for h in http:
                    f.write(f"- {h['protocol']}: {h['response']}\n")
            
            f.write("\n---\n\n")
    
    print(f"报告已保存: {report_file}")
    return report_file

def save_all_ips():
    """保存所有节点 IP 到文件"""
    db = load_db()
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    # 全部代理节点
    with open(f"{REPORT_DIR}/all_proxy_nodes.txt", 'w') as f:
        for ip in sorted(db.get('all_proxy_nodes', [])):
            f.write(ip + "\n")
    
    # 全部控制面节点
    with open(f"{REPORT_DIR}/all_control_nodes.txt", 'w') as f:
        for ip in sorted(db.get('all_control_nodes', [])):
            f.write(ip + "\n")
    
    # 华为 IP
    hw = get_huawei_ips()
    with open(f"{REPORT_DIR}/huawei_ips.txt", 'w') as f:
        for entry in sorted(hw, key=lambda x: x['ip']):
            f.write(f"{entry['ip']}\t{entry.get('port','')}\t{entry.get('apk','')}\t{entry.get('type','')}\n")
    
    # 阿里云 IP
    with open(f"{REPORT_DIR}/aliyun_ips.txt", 'w') as f:
        for ip in sorted(db.get('all_proxy_nodes', [])):
            if ip.startswith('8.13') or ip.startswith('8.138') or ip.startswith('8.148') or ip.startswith('8.163'):
                f.write(ip + "\n")
    
    # 腾讯云 IP
    tencent_prefixes = ('1.1', '42.', '43.', '106.', '111.', '119.', '123.', '129.', '134.', '139.', '159.', '175.', '193.')
    with open(f"{REPORT_DIR}/tencent_ips.txt", 'w') as f:
        for ip in sorted(db.get('all_proxy_nodes', [])):
            if ip.startswith(tencent_prefixes):
                f.write(ip + "\n")
    
    print(f"IP 列表已保存到 {REPORT_DIR}/")
    print(f"  all_proxy_nodes.txt ({len(db.get('all_proxy_nodes',[]))} 个)")
    print(f"  all_control_nodes.txt ({len(db.get('all_control_nodes',[]))} 个)")
    print(f"  huawei_ips.txt ({len(hw)} 个)")
    print(f"  aliyun_ips.txt")
    print(f"  tencent_ips.txt")

if __name__ == '__main__':
    import sys
    print("=== 华为云 IP 取证工具 ===")
    print()
    
    if '--report' in sys.argv or len(sys.argv) == 1:
        print("生成取证报告...")
        generate_report()
    
    if '--save-ips' in sys.argv or len(sys.argv) == 1:
        print()
        save_all_ips()
    
    if '--port-scan' in sys.argv:
        print("\n端口扫描...")
        hw = get_huawei_ips()
        for entry in hw:
            ip = entry['ip']
            port = entry.get('port')
            if port:
                print(f"\n{ip}:{port}")
                results = port_scan(ip, [port, 80, 443, 22])
                for r in results:
                    print(f"  {r['port']}: {r['state']} {r['banner'][:30]}")
    
    if '--tls-fingerprint' in sys.argv:
        print("\nTLS 指纹...")
        hw = get_huawei_ips()
        for entry in hw:
            ip = entry['ip']
            port = entry.get('port')
            if port:
                print(f"\n{ip}:{port}")
                results = tls_fingerprint(ip, port)
                for r in results:
                    print(f"  SNI={r.get('sni','')}: {r.get('status','')}")
    
    print("\n完成!")
