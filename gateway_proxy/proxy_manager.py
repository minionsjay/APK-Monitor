#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理轮换管理器 —— 反诈样本批量分析用
调 58ip.top API 拉一批 → 并发探活+过滤国内 → 维护可用池 → rotate 挂到手机并验证出口。

子命令:
  refill [N]        拉取并探活,把可用国内代理填进池子(默认目标 N=20)
  rotate            从池里挑一个可用代理挂到手机,验证手机出口=该国内IP(池空自动refill)
  up <ip:port>      指定代理挂上
  down              拆除隧道恢复直连
  status            看当前代理+池子大小
  verify            打印手机当前经隧道的出口IP(HTTP --resolve,绕DNS/绕透明劫持)
  check <ip:port>   单测一个代理(宿主机侧)

依赖:adb(在PATH)、手机已root且 /data/local/tmp 下有 tun2socks/curl/proxy_*.sh
"""
import os, sys, subprocess, time, re, json, concurrent.futures as cf

GP = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.environ.get("PROXY_TOKEN", "0effad46fb00c320382e8614553897")
API = "http://58ip.top/api/get?token={t}&number={n}&type=socket5&format=1"
POOL = os.path.join(GP, "pool.txt")
CUR  = os.path.join(GP, "current.json")

# 国内HTTPS回显(代理自己解析域名,返回归属地);测代理出口是否国内用
ECHO = "https://myip.ipip.net"
HOME_HINT = "223.74.115.212"      # 家宽IP,出口若=这个说明没换成功(仅参考)
# 手机侧验证用的HTTP回显(--resolve绕DNS;经隧道时返回代理出口IP)
PH_ECHO_HOST = "ip.3322.net"
PH_ECHO_IP   = "118.184.169.32"

def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"

def adb_dev():
    if os.environ.get("ADB_SERIAL"): return os.environ["ADB_SERIAL"]
    _, out = sh("adb devices")
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 2 and p[1] == "device":
            return p[0]
    sys.exit("!! 没有可用 adb 设备")

def fetch(n):
    rc, out = sh(f'curl -s -m 25 "{API.format(t=TOKEN, n=n)}"', timeout=30)
    ips = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}:\d+", out)
    return ips

def check(proxy, timeout=8):
    """宿主机侧测代理:返回 (ok, exit_ip, is_domestic, loc)"""
    rc, out = sh(f'curl -s -m {timeout} -x "http://{proxy}" "{ECHO}"', timeout=timeout+3)
    m = re.search(r"IP[：:]\s*(\d{1,3}(?:\.\d{1,3}){3})", out)
    if not m:
        return (False, None, False, "")
    exit_ip = m.group(1)
    is_cn = ("中国" in out)
    loc = out.strip().replace("\n", " ")[:60]
    return (True, exit_ip, is_cn, loc)

def refill(target=20, batch=60, max_batches=10):
    pool = read_pool()
    have = set(pool)
    print(f"[*] 现有池 {len(pool)} 个,目标 {target},开始拉取探活...")
    tested = 0
    for b in range(max_batches):
        if len(pool) >= target: break
        cand = [p for p in fetch(batch) if p not in have]
        if not cand:
            print("[*] API无新代理,停止"); break
        with cf.ThreadPoolExecutor(max_workers=25) as ex:
            for proxy, res in zip(cand, ex.map(lambda p: check(p), cand)):
                tested += 1
                ok, ip, cn, loc = res
                if ok and cn:
                    if proxy not in have:
                        pool.append(proxy); have.add(proxy)
                        print(f"  + {proxy:22s} -> {ip:15s} [{loc.split('来自于')[-1].strip()[:20]}]")
                        if len(pool) >= target: break
    write_pool(pool)
    print(f"[*] 池子现有 {len(pool)} 个可用国内代理(本轮测了 {tested} 个)")
    return pool

def read_pool():
    if not os.path.exists(POOL): return []
    return [l.strip() for l in open(POOL) if l.strip()]

def write_pool(pool):
    open(POOL, "w").write("\n".join(pool) + ("\n" if pool else ""))

def phone_exit(dev, timeout=15):
    """手机经隧道的出口IP(HTTP --resolve,绕DNS/绕透明劫持)"""
    cmd = (f'adb -s {dev} shell "su -c \'/data/local/tmp/curl -s -m {timeout} '
           f'--resolve {PH_ECHO_HOST}:80:{PH_ECHO_IP} http://{PH_ECHO_HOST}\'"')
    rc, out = sh(cmd, timeout=timeout+8)
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", out)
    return m.group(0) if m else None

def up(dev, proxy):
    cmd = (f'adb -s {dev} shell "su -c \'PROXY_URL=http://{proxy} '
           f'sh /data/local/tmp/proxy_up.sh >/data/local/tmp/up.log 2>&1; echo ok\'"')
    sh(cmd, timeout=30)

def down(dev):
    sh(f'adb -s {dev} shell "su -c \'sh /data/local/tmp/proxy_down.sh; killall tun2socks 2>/dev/null\'"', timeout=20)
    print("[OK] 已拆除,恢复直连")

def rotate(dev):
    pool = read_pool()
    if len(pool) < 3:
        pool = refill(target=20)
    while pool:
        proxy = pool.pop(0)
        write_pool(pool)
        exit_expect = proxy.split(":")[0]
        print(f"[*] 挂 {proxy} ...")
        up(dev, proxy)
        got = phone_exit(dev)
        if got and got != HOME_HINT:
            json.dump({"proxy": proxy, "exit_ip": got, "ts": time.time()}, open(CUR, "w"))
            print(f"[OK] 已换IP:手机出口 = {got}  (代理 {proxy})")
            return proxy, got
        print(f"  ✗ 验证失败(手机出口={got}),换下一个")
    print("!! 池子耗尽且都失败,重新 refill 再试")
    refill(target=20)
    return None, None

def status(dev):
    pool = read_pool()
    cur = json.load(open(CUR)) if os.path.exists(CUR) else {}
    print(f"池子可用: {len(pool)} 个")
    print(f"当前代理: {cur.get('proxy','(无)')}  出口: {cur.get('exit_ip','?')}")
    print(f"手机实时出口: {phone_exit(dev)}")

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    dev = None
    if cmd in ("rotate","up","down","status","verify"):
        dev = adb_dev()
    if cmd == "refill":
        refill(int(sys.argv[2]) if len(sys.argv) > 2 else 20)
    elif cmd == "rotate":
        rotate(dev)
    elif cmd == "up":
        up(dev, sys.argv[2]); print("出口:", phone_exit(dev))
    elif cmd == "down":
        down(dev)
    elif cmd == "status":
        status(dev)
    elif cmd == "verify":
        print("手机经隧道出口 IP:", phone_exit(dev))
    elif cmd == "check":
        print(check(sys.argv[2]))
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
