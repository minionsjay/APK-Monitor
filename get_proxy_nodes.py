#!/usr/bin/env python3
"""
exdyfb 代理节点获取器（综合版）

支持多种方式获取代理节点：
1. 从设备缓存读取（最简单）
2. 从 Go 堆内存读取（需要 root + APP 运行中）
3. 从 .dat 解密控制面节点（不需要设备）
4. 从 DNS TXT 获取节点（不需要设备）

用法:
  python3 get_proxy_nodes.py --device 192.168.1.16:38493  # 从设备获取
  python3 get_proxy_nodes.py --offline                      # 离线获取控制面节点
  python3 get_proxy_nodes.py --memory                        # 从内存读取代理节点
"""

import argparse, base64, hashlib, json, os, re, socket, struct, subprocess, sys, time

# 已知常量
AES_KEY = b"qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb"
IV = AES_KEY[:16]
APP_DOMAIN = "sdkcgyuf151.qianchixt.com"
APP_NAME = "dh151"
SDK_VERSION = "4.0.1"
PKG = "bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns"
DEVICE_SERIAL = "192.168.1.16:38493"

CLOUDS = {
    "oss": "oss-accelerate.aliyuncs.com",
    "bos": "gz.bcebos.com",
    "zos": "jiangsu-10.zos.ctyun.cn",
}

def aes_cbc_decrypt(ct, key=AES_KEY):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except:
        pass
    return pt

def derive_dat_urls(date_str):
    urls = {}
    for tag, host in CLOUDS.items():
        h = hashlib.md5(f"{date_str}{APP_NAME}{tag}{SDK_VERSION}".encode()).hexdigest()
        urls[tag] = f"https://{h[:16]}.{host}/{h[16:32]}.dat"
    return urls

def get_control_nodes_offline(date_str=None):
    """离线获取控制面节点（从 .dat 解密）"""
    from datetime import datetime, timezone, timedelta
    if not date_str:
        bj = datetime.now(timezone(timedelta(hours=8)))
        date_str = bj.strftime("%Y%m%d")
    
    urls = derive_dat_urls(date_str)
    print(f"日期: {date_str}")
    
    for tag, url in urls.items():
        print(f"  [{tag}] {url}")
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
            data = json.loads(aes_cbc_decrypt(raw).decode())
            nodes = []
            for grp in ("nodesA", "nodesB", "nodesC", "nodesD", "nodesE"):
                nodes += data.get(grp, [])
            if nodes:
                print(f"  控制面节点 ({tag}命中): {nodes}")
                return nodes
        except Exception as e:
            print(f"  {tag} 失败: {e}")
    return []

def get_txt_nodes():
    """从 DNS TXT 获取节点"""
    try:
        out = subprocess.check_output(
            ["dig", "+short", "TXT", APP_DOMAIN, "@8.8.8.8"],
            stderr=subprocess.DEVNULL, timeout=15).decode()
        records = [l.strip().strip('"') for l in out.splitlines() if l.strip()]
        nodes = []
        for rec in records:
            try:
                ip = aes_cbc_decrypt(base64.b64decode(rec)).decode().strip()
                if ip and ip[0].isdigit():
                    nodes.append(ip)
            except:
                pass
        return nodes
    except:
        return []

def get_proxy_nodes_from_cache(device=DEVICE_SERIAL):
    """从设备缓存读取代理节点"""
    path = f"/sdcard/Android/data/{PKG}/files/sdk_forwarder_fixed.json"
    result = subprocess.run(
        ["adb", "-s", device, "shell", "cat", path],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            return data.get("app_line_ips", [])
        except:
            pass
    return []

def get_proxy_nodes_from_memory(device=DEVICE_SERIAL):
    """从 Go 堆内存读取代理节点（需要 root + APP 运行中）"""
    # 获取 PID
    result = subprocess.run(
        ["adb", "-s", device, "shell", "pidof", PKG],
        capture_output=True, text=True, timeout=5
    )
    pid = result.stdout.strip()
    if not pid:
        print("APP 未运行")
        return []
    
    print(f"PID={pid}")
    
    # 找 Go 堆段
    result = subprocess.run(
        ["adb", "-s", device, "shell", f"su -c 'cat /proc/{pid}/maps'"],
        capture_output=True, timeout=10
    )
    maps_text = result.stdout.decode("latin-1", errors="replace")
    
    go_heap_ranges = []
    for line in maps_text.split("\n"):
        if line.startswith("4000") and "rw" in line:
            parts = line.split()
            go_heap_ranges.append(parts[0])
    
    if not go_heap_ranges:
        print("未找到 Go 堆段")
        return []
    
    print(f"Go 堆段: {go_heap_ranges}")
    
    # 搜索每个 Go 堆段
    for heap_range in go_heap_ranges:
        start = int(heap_range.split("-")[0], 16)
        end = int(heap_range.split("-")[1], 16)
        skip = start // 4096
        count = (end - start) // 4096
        count = min(count, 1024)
        
        result = subprocess.run(
            ["adb", "-s", device, "shell", f"su -c 'dd if=/proc/{pid}/mem bs=4096 skip={skip} count={count} 2>/dev/null'"],
            capture_output=True, timeout=30
        )
        
        # 搜索 app_line_ips JSON
        text = result.stdout.decode("latin-1", errors="replace")
        
        # 搜索 IP:30151 模式（更可靠）
        ips_set = set()
        for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+):30151', text):
            ip = m.group(1)
            # 过滤掉明显错误的 IP（如以 2 开头的 2193.x）
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts) and not ip.startswith(("0.", "2193", "28.")):
                ips_set.add(ip)
        
        if len(ips_set) >= 5:
            return sorted(ips_set)
    
    return []

def main():
    ap = argparse.ArgumentParser(description="exdyfb 代理节点获取器")
    ap.add_argument("--device", default=DEVICE_SERIAL, help="adb 设备地址")
    ap.add_argument("--offline", action="store_true", help="离线获取控制面节点")
    ap.add_argument("--memory", action="store_true", help="从内存读取代理节点")
    ap.add_argument("--all", action="store_true", help="所有方式都试一遍")
    args = ap.parse_args()
    
    if args.offline:
        print("=== 离线获取控制面节点 ===")
        control = get_control_nodes_offline()
        if control:
            print(f"\n控制面节点: {control}")
        
        print("\n=== DNS TXT 节点 ===")
        txt = get_txt_nodes()
        if txt:
            print(f"TXT 节点: {txt}")
        else:
            print("无 TXT 记录")
    
    if args.memory or args.all:
        print("\n=== 从 Go 堆内存读取 ===")
        nodes = get_proxy_nodes_from_memory(args.device)
        if nodes:
            print(f"\n代理节点 ({len(nodes)}个):")
            for ip in nodes:
                print(f"  {ip}:30151")
    
    if args.all or not (args.offline or args.memory):
        print("\n=== 从设备缓存读取 ===")
        nodes = get_proxy_nodes_from_cache(args.device)
        if nodes:
            print(f"\n代理节点 ({len(nodes)}个):")
            for ip in nodes:
                print(f"  {ip}:30151")
        else:
            print("缓存为空")
    
    if args.all:
        print("\n=== 离线控制面节点 ===")
        control = get_control_nodes_offline()
        if control:
            print(f"控制面节点: {control}")

if __name__ == "__main__":
    main()
