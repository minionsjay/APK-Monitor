#!/usr/bin/env python3
"""定时从真机读取代理节点并保存

使用方法：
  python3 fetch_proxy_cron.py

输出：
  /home/ninini/Agents/APK-Research/proxy_nodes_history.json
"""
import json, subprocess, sys, os
from datetime import datetime

def get_proxy_from_device():
    """从真机 Go 堆内存读取代理节点"""
    try:
        # 获取 exdyfb PID
        result = subprocess.run(
            ['adb', 'shell', 'pidof', 'bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns'],
            capture_output=True, text=True, timeout=5
        )
        pid = result.stdout.strip()
        if not pid:
            return None, "APP 不在运行"

        # 读 sdk_forwarder_fixed.json
        result = subprocess.run(
            ['adb', 'shell', 'cat',
             '/sdcard/Android/data/bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns/files/sdk_forwarder_fixed.json'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return data, "from cache"

        # 从 Go 堆读取
        result = subprocess.run(
            ['adb', 'shell', 'su', '-c',
             f'dd if=/proc/{pid}/mem bs=4096 skip=67108864 count=256 2>/dev/null | strings -n 30'],
            capture_output=True, text=True, timeout=15
        )
        import re
        ips = set(re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', result.stdout))
        # 过滤控制面节点
        control_nodes = {'106.53.12.54:30151', '193.112.206.154:30151', '8.138.41.144:30151'}
        proxy_ips = ips - control_nodes
        if proxy_ips:
            return {"app_line_ips": [ip.split(':')[0] for ip in proxy_ips], "app_line_port": 30151}, "from heap"
        
        return None, "没有找到代理节点"
    except Exception as e:
        return None, str(e)

def main():
    history_file = '/home/ninini/Agents/APK-Research/proxy_nodes_history.json'
    
    # 读取历史
    history = []
    if os.path.exists(history_file):
        with open(history_file) as f:
            history = json.load(f)
    
    # 获取当前节点
    nodes, source = get_proxy_from_device()
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "nodes": nodes,
    }
    
    history.append(entry)
    # 只保留最近 100 条
    history = history[-100:]
    
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2, ensure_ascii=False)
    
    if nodes:
        ips = nodes.get('app_line_ips', [])
        print(f"[{entry['timestamp']}] {source}: {len(ips)} 个代理节点")
        for ip in ips:
            print(f"  {ip}:{nodes.get('app_line_port', 30151)}")
    else:
        print(f"[{entry['timestamp']}] {source}")

if __name__ == '__main__':
    main()
